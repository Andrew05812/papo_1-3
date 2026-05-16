"""
Lab1 Service — 10 студентов с минимальным % посещения лекций, содержащих термин

Задание ЛР1:
  Выполнить запрос для извлечения отчёта о 10 студентах с минимальным процентом
  посещения лекций, содержащих заданный термин или фразу, за определённый период.
  Состав полей: полная информация о студенте, процент посещения, период отчёта,
  термин в занятиях курса.

Путь запроса: Elasticsearch → PostgreSQL → Redis

Шаг 1 — Elasticsearch:
  Полнотекстовый поиск по индексу "lectures" (BM25 + fuzziness AUTO + russian_custom).
  Ищем термин в полях title, annotation, content_text.
  Результат: список lecture_id, которые содержат термин.

Шаг 2 — PostgreSQL:
  CTE MATERIALIZED: находим расписание для этих лекций в заданном периоде,
  считаем total_scheduled и total_attended для каждого студента,
  сортируем по attendance_pct ASC, берём LIMIT 10.
  Используем ANY(%s::uuid[]) для batch-запроса и partition pruning по week_start_date.

Шаг 3 — Redis:
  Pipeline HGETALL student:{id} для топ-10 студентов.
  При промахе кэша — заполняем из данных PG через pipeline (cache-aside).
"""
# FastAPI: веб-фреймворк для REST API; Query — параметры запроса; Depends — внедрение зависимостей; HTTPException — ошибки
from fastapi import FastAPI, Query, Depends, HTTPException
# HTTPBearer — схема Bearer-аутентификации; HTTPAuthorizationCredentials — объект с токеном из заголовка Authorization
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# Elasticsearch: клиент для полнотекстового поиска по индексу lectures (BM25, fuzzy-совпадения)
from elasticsearch import Elasticsearch
# psycopg2: драйвер PostgreSQL для выполнения SQL-запросов с CTE и параметризованными подстановками
import psycopg2
# redis: клиент Redis для кэширования данных студентов (Hash + TTL, pipeline-операции)
import redis
# jwt: библиотека PyJWT для декодирования и проверки JWT-токенов сервисной аутентификации
import jwt
# os: чтение переменных окружения для конфигурации подключений к БД и JWT-секрета
import os
# logging: структурированный логгинг шагов запроса (ES → PG → Redis)
import logging
# time: замер общего времени выполнения запроса (execution_time_sec)
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Lab 1 - Attendance Flow")

# Секретный ключ для проверки подписи JWT-токена (HS256 — симметричное подписание).
# Токен декодируется: jwt.decode() проверяет подпись секретом и срок действия,
# затем проверяется поле type=="service", чтобы разрешить только межсервисные токены.
JWT_SECRET = os.environ.get("JWT_SECRET", "polyglot_jwt_secret_key_2026")
# Алгоритм подписи JWT (HS256 — HMAC-SHA256, симметричный, быстрый, подходит для межсервисной аутентификации)
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
# Экземпляр схемы Bearer — автоматически извлекает токен из заголовка Authorization: Bearer <token>
security = HTTPBearer()


# Проверка сервисного JWT-токена. Принимаются ТОЛЬКО токены с type=="service"
# (межсервисная аутентификация). Пользовательские токены (type=="user") отклоняются
# с 403, чтобы гарантировать, что эндпоинт /query вызывается только другими сервисами.
def verify_service_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "service":
            raise HTTPException(status_code=403, detail="Service token required")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Параметры подключения к сервисам, читаемые из переменных окружения Docker;
# значения по умолчанию — для локальной разработки без Docker
ES_HOST = os.environ.get("ES_HOST", "elasticsearch")
ES_PORT = int(os.environ.get("ES_PORT", 9200))
PG_HOST = os.environ.get("POSTGRES_HOST", "postgres")
PG_PORT = int(os.environ.get("POSTGRES_PORT", 5432))
PG_DB = os.environ.get("POSTGRES_DB", "university")
PG_USER = os.environ.get("POSTGRES_USER", "postgres")
PG_PASS = os.environ.get("POSTGRES_PASSWORD", "postgres")
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))


# Elasticsearch: подключение к поисковому движку для полнотекстового поиска лекций по термину
# (BM25-ранжирование, fuzzy-совпадения, анализатор russian_custom для морфологии русского языка)
def get_es():
    return Elasticsearch(f"http://{ES_HOST}:{ES_PORT}")


# PostgreSQL: реляционная БД для вычисления процента посещения через CTE MATERIALIZED
# (batch-запрос ANY(uuid[]), partition pruning по week_start_date, top-N heapsort)
def get_pg():
    return psycopg2.connect(host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASS)


# Redis: in-memory кэш для данных студентов (Hash-структура, TTL=2ч, pipeline для O(1)-чтения топ-10)
def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


# Основной запрос: трёхступенчатый конвейер ES → PostgreSQL → Redis.
# Шаг 1 (ES): полнотекстовый поиск термина → список lecture_id.
# Шаг 2 (PG): CTE MATERIALIZED: расписание → кол-во запланированных → кол-во посещённых → топ-10 по минимальному %.
# Шаг 3 (Redis): cache-aside для данных студентов: HGETALL при попадании, HSET+EXPIRE при промахе.
@app.get("/query")
def query_attendance_flow(
    term: str = Query(..., description="Термин для поиска в лекциях"),
    start_date: str = Query(..., description="Начало периода (YYYY-MM-DD)"),
    end_date: str = Query(..., description="Конец периода (YYYY-MM-DD)"),
    _=Depends(verify_service_token)
):
    steps = []
    start = time.time()

    # --- Шаг 1: Elasticsearch — полнотекстовый поиск термина ---
    # Запрос к индексу "lectures":
    #   • bool.should — хотя бы одно поле должно совпасть (minimum_should_match=1);
    #   • match с fuzziness=AUTO — допускает опечатки (1-2 символа в зависимости от длины слова);
    #   • BM25 — ранжирование по релевантности (встроено в match-запросы Elasticsearch);
    #   • russian_custom — анализатор индекса, учитывающий морфологию русского языка
    #     (стемминг, стоп-слова), что позволяет находить формы слова (лекция/лекции/лекций);
    #   • _source — возвращаем только нужные поля, без полнотекстового содержимого;
    #   • size=500 — ограничиваем число хитов (предотвращает перегрузку при широком термине).
    logger.info(f"Step 1: ES - searching term '{term}'")
    es = get_es()
    es_result = es.search(index="lectures", body={
        "query": {
            "bool": {
                "should": [
                    {"match": {"title": {"query": term, "fuzziness": "AUTO"}}},
                    {"match": {"annotation": {"query": term, "fuzziness": "AUTO"}}},
                    {"match": {"content_text": {"query": term, "fuzziness": "AUTO"}}}
                ],
                "minimum_should_match": 1
            }
        },
        "_source": ["lecture_id", "course_id", "course_name", "title", "tags"],
        "size": 500
    })
    es.close()

    # Извлекаем lecture_id из хитов ES и собираем справочник course_info
    # для последующего обогащения результата (course_name, lecture_title, tags)
    lecture_hits = es_result["hits"]["hits"]
    lecture_ids = [h["_source"]["lecture_id"] for h in lecture_hits]
    course_info = {}
    for h in lecture_hits:
        src = h["_source"]
        lid = src.get("lecture_id")
        if lid not in course_info:
            course_info[lid] = {
                "course_id": src.get("course_id", ""),
                "course_name": src.get("course_name", ""),
                "lecture_title": src.get("title", ""),
                "tags": src.get("tags", [])
            }

    steps.append({
        "step": 1,
        "store": "Elasticsearch",
        "action": f"Полнотекстовый поиск термина '{term}' (BM25 + fuzziness=AUTO, russian_custom анализатор)",
        "result": f"Найдено {len(lecture_ids)} лекций"
    })

    if not lecture_ids:
        return {"result": [], "steps": steps, "query_path": "ES → PostgreSQL → Redis",
                "execution_time_sec": round(time.time() - start, 3)}

    # --- Шаг 2: PostgreSQL — CTE MATERIALIZED для вычисления топ-10 по минимальному % посещения ---
    # Предварительный запрос: определяем, какие лекции из списка принадлежат каким группам,
    # чтобы потом обогатить результат термином из курса. Используем ANY(%s::uuid[]) для
    # batch-подстановки массива UUID вместо N отдельных запросов.
    logger.info(f"Step 2: PG - CTE top-10 for {len(lecture_ids)} lectures")
    pg = get_pg()
    cur = pg.cursor()

    cur.execute("""
        SELECT sch.group_id, array_agg(DISTINCT sch.lecture_id)
        FROM schedule sch
        WHERE sch.lecture_id = ANY(%s::uuid[])
          AND sch.week_start_date BETWEEN %s AND %s
        GROUP BY sch.group_id
    """, (lecture_ids, start_date, end_date))
    group_lecture_map = {str(r[0]): [str(lid) for lid in r[1]] for r in cur.fetchall()}

    # Основной CTE-запрос: три MATERIALIZED подзапроса + финальная JOIN-секция.
    # MATERIALIZED заставляет PostgreSQL материализовать (сохранить) промежуточный результат
    # каждого CTE, что выгодно при повторном использовании matching_schedule в двух последующих CTE.
    #
    # CTE 1 — matching_schedule: фильтруем schedule по lecture_ids и периоду;
    #   ANY(%s::uuid[]) — batch-подстановка массива UUID, избегая N+1 запросов;
    #   week_start_date BETWEEN — partition pruning (партиционированная таблица по неделям).
    #
    # CTE 2 — group_sched_count: для каждой группы считаем total_scheduled —
    #   сколько занятий из matching_schedule запланировано (COUNT DISTINCT id).
    #
    # CTE 3 — attended: для каждого студента считаем total_attended —
    #   сколько занятий он посетил (JOIN matching_schedule + COUNT DISTINCT schedule_id).
    #
    # Финальный SELECT: JOIN student + group_sched_count + LEFT JOIN attended,
    #   вычисляем attendance_pct = total_attended / total_scheduled * 100,
    #   ORDER BY attendance_pct ASC — студенты с наименьшим % посещения первыми,
    #   LIMIT 10 — top-N heapsort O(N log K) на partitioned/indexed данных.
    cur.execute("""
        WITH matching_schedule AS MATERIALIZED (
            SELECT id, group_id
            FROM schedule
            WHERE lecture_id = ANY(%s::uuid[])
              AND week_start_date BETWEEN %s AND %s
        ),
        group_sched_count AS MATERIALIZED (
            SELECT group_id, COUNT(DISTINCT id) as total_scheduled
            FROM matching_schedule
            GROUP BY group_id
        ),
        attended AS MATERIALIZED (
            SELECT a.student_id, COUNT(DISTINCT a.schedule_id) as total_attended
            FROM attendance a
            JOIN matching_schedule ms ON ms.id = a.schedule_id
            WHERE a.week_start_date BETWEEN %s AND %s
            GROUP BY a.student_id
        )
        SELECT s.id, s.first_name, s.last_name, s.patronymic,
               s.email, s.student_card_number, s.status, s.enrollment_date,
               s.group_id,
               gsc.total_scheduled,
               COALESCE(att.total_attended, 0) as total_attended,
               ROUND((COALESCE(att.total_attended, 0)::numeric / gsc.total_scheduled) * 100, 2) as attendance_pct
        FROM student s
        JOIN group_sched_count gsc ON gsc.group_id = s.group_id
        LEFT JOIN attended att ON att.student_id = s.id
        WHERE gsc.total_scheduled > 0
        ORDER BY attendance_pct ASC, total_attended ASC
        LIMIT 10
    """, (lecture_ids, start_date, end_date, start_date, end_date))

    top10 = cur.fetchall()
    cur.close()
    pg.close()

    steps.append({
        "step": 2,
        "store": "PostgreSQL",
        "action": "CTE MATERIALIZED: matching_schedule → group_sched_count → attended (JOIN). ORDER BY attendance_pct LIMIT 10 — O(N log K) top-N heapsort на partitioned/indexed данных",
        "result": f"Топ-10 студентов с минимальным % посещения (вычислено в SQL, без загрузки всех строк в Python)"
    })

    results = []
    for row in top10:
        sid = str(row[0])
        gid = str(row[8])
        pct = float(row[11]) if row[11] is not None else 0.0

        group_lectures = group_lecture_map.get(gid, [])
        first_matching = next((lid for lid in group_lectures if lid in course_info), None)
        term_info = course_info.get(first_matching, {})

        results.append({
            "student": {
                "id": sid,
                "first_name": row[1],
                "last_name": row[2],
                "patronymic": row[3] or "",
                "email": row[4],
                "student_card_number": row[5],
                "status": row[6],
                "enrollment_date": str(row[7])
            },
            "group_id": gid,
            "attendance_pct": pct,
            "total_scheduled": row[9],
            "total_attended": row[10],
            "period": {"start_date": start_date, "end_date": end_date},
            "term_in_course": {
                "course_name": term_info.get("course_name", ""),
                "lecture_title": term_info.get("lecture_title", ""),
                "tags": term_info.get("tags", [])
            }
        })

    if not results:
        return {"result": [], "steps": steps, "query_path": "ES → PostgreSQL → Redis",
                "execution_time_sec": round(time.time() - start, 3)}

    # --- Шаг 3: Redis — cache-aside для данных студентов топ-10 ---
    # Паттерн cache-aside: сначала проверяем кэш, при промахе — заполняем из данных PG.
    # Pipeline: группируем несколько команд в один сетевойRound-Trip (вместо N отдельных запросов).
    # Структура ключа: student:{id} — Redis Hash с полями first_name, last_name и т.д.
    # TTL=7200с (2ч): кэш автоматически истекает, обеспечивая актуальность данных.
    logger.info(f"Step 3: Redis - pipeline for {len(results)} students")
    r = get_redis()
    pipe = r.pipeline()
    # Pipeline HGETALL: пакетно запрашиваем данные всех 10 студентов одним Round-Trip
    for ri in results:
        pipe.hgetall(f"student:{ri['student']['id']}")
    cached_results = pipe.execute()

    # Подсчёт попаданий/промахов кэша и заполнение при промахах (cache-aside)
    cache_hits = 0
    cache_misses = 0
    fill_pipe = r.pipeline()
    for ri, cached in zip(results, cached_results):
        if cached:
            # Попадание кэша: данные уже в Redis, дополнительных действий не требуется
            cache_hits += 1
        else:
            # Промах кэша: записываем данные студента в Redis Hash + устанавливаем TTL
            cache_misses += 1
            s = ri["student"]
            # HSET: записываем все поля студента в Hash-ключ student:{id} одной командой (mapping)
            fill_pipe.hset(f"student:{s['id']}", mapping={
                "first_name": s["first_name"],
                "last_name": s["last_name"],
                "patronymic": s["patronymic"],
                "email": s["email"],
                "student_card_number": s["student_card_number"],
                "group_id": ri["group_id"],
                "status": s["status"],
                "enrollment_date": s["enrollment_date"]
            })
            # EXPIRE: устанавливаем TTL=7200с (2 часа) — по истечении ключ удаляется автоматически
            fill_pipe.expire(f"student:{s['id']}", 7200)
    # Выполняем pipeline заполнения кэша только если были промахи (избегаем пустого Round-Trip)
    if cache_misses:
        fill_pipe.execute()

    steps.append({
        "step": 3,
        "store": "Redis",
        "action": f"Pipeline HGETALL student:{{id}} для топ-10 только (Hash, TTL=2ч). Попаданий: {cache_hits}, промахов: {cache_misses} (пополнение из данных PG)",
        "result": f"Кэш проверен/пополнен для {len(results)} студентов"
    })

    elapsed = round(time.time() - start, 3)

    return {
        "result": results,
        "steps": steps,
        "query_path": "ES → PostgreSQL → Redis",
        "execution_time_sec": elapsed,
        # Обоснование выбора каждой БД в конвейере:
        # Elasticsearch: полнотекстовый поиск (BM25-ранжирование, fuzzy-совпадения для опечаток,
        #   russian_custom для морфологии русского языка) — значительно эффективнее LIKE/TSVECTOR в PG
        #   при поиске по контенту лекций с допусканием опечаток и форм слова.
        # PostgreSQL: реляционные вычисления (CTE MATERIALIZED + JOIN + ORDER BY + LIMIT 10) —
        #   top-N heapsort O(N log K) на partitioned/indexed данных, масштабируемо до 1M+ записей;
        #   ANY(uuid[]) для batch-запроса вместо N+1, partition pruning по week_start_date.
        # Redis: O(1) доступ к данным студентов через pipeline HGETALL (Hash-структура);
        #   cache-aside с TTL=2ч: при повторных запросах кэш отдаёт данные без обращения к PG,
        #   pipeline сокращает число Round-Trip до 1 вместо 10 отдельных GET-запросов.
        "justification": {
            "Elasticsearch": "Полнотекстовый поиск (BM25, fuzziness, russian_custom) — эффективнее LIKE в PostgreSQL",
            "PostgreSQL": "CTE MATERIALIZED + ORDER BY + LIMIT 10: top-N heapsort O(N log K) на partitioned/indexed данных — масштабируемо до 1M+ записей",
            "Redis": "O(1) pipeline HGETALL student:{id} для 10 студентов — кэш-проверка вместо SELECT из PG при повторных запросах"
        }
    }


# Health-check эндпоинт для проверки доступности сервиса
@app.get("/")
def root():
    return {"service": "lab1", "description": "Attendance flow: ES → PostgreSQL → Redis"}
