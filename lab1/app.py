"""
Lab1 Service — 10 студентов с минимальным % посещения лекций, содержащих термин

Задание ЛР1:
  Выполнить запрос для извлечения отчёта о 10 студентах с минимальным процентом
  посещения лекций, содержащих заданный термин или фразу, за определённый период.
  Состав полей: полная информация о студенте, процент посещения, период отчёта,
  термин в занятиях курса.

Путь запроса: Elasticsearch → Neo4j → PostgreSQL → Redis

Шаг 1 — Elasticsearch:
  Полнотекстовый поиск по индексу "lectures" (BM25 + fuzziness AUTO + russian_custom).
  Ищем термин в полях title, annotation, content_text.
  Результат: список lecture_id, которые содержат термин.

Шаг 2 — Neo4j:
  Обход графа: находим Schedule для лекций из ES в заданном периоде,
  через SHOULD_ATTEND получаем пары (student_id, schedule_id).
  Neo4j не хранит данные о фактическом посещении — только связи.

Шаг 3 — PostgreSQL:
  По парам (student_id, schedule_id) из Neo4j считаем посещаемость:
  total_scheduled = кол-во schedule_id для студента,
  total_attended = кол-во schedule_id WHERE is_present = TRUE,
  attendance_pct = total_attended / total_scheduled * 100.
  Таблица attendance партиционирована по week_start_date — partition pruning.
  ORDER BY attendance_pct ASC LIMIT 10.
  Также получаем полные данные студентов из PG.

Шаг 4 — Redis:
  Pipeline HGETALL student:{id} для топ-10 студентов.
  При промахе кэша — заполняем из данных PG через pipeline (cache-aside).
"""
# FastAPI — веб-фреймворк для REST API; Query — параметры запроса; Depends — внедрение зависимостей; HTTPException — ошибки
from fastapi import FastAPI, Query, Depends, HTTPException
# HTTPBearer — схема Bearer-аутентификации; HTTPAuthorizationCredentials — объект с токеном из заголовка Authorization
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# Elasticsearch: клиент для полнотекстового поиска по индексу lectures (BM25, fuzzy-совпадения)
from elasticsearch import Elasticsearch
# Neo4j: графовая СУБД; GraphDatabase — драйвер для обхода связей Student-[SHOULD_ATTEND]->Schedule-[PART_OF]->Lecture
from neo4j import GraphDatabase
# psycopg2: драйвер PostgreSQL для подсчёта посещаемости по is_present в partitioned таблице attendance
import psycopg2
# redis: клиент Redis для кэширования данных студентов (Hash + TTL, pipeline-операции)
import redis
# jwt: библиотека PyJWT для декодирования и проверки JWT-токенов сервисной аутентификации
import jwt
# os: чтение переменных окружения для конфигурации подключений к БД и JWT-секрета
import os
# logging: структурированный логгинг шагов запроса (ES → Neo4j → PG → Redis)
import logging
# time: замер общего времени выполнения запроса (execution_time_sec)
import time

# Настройка логгирования: INFO-уровень для протоколирования каждого шага запроса
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI-приложение для ЛР1 — 10 студентов с минимальным % посещения
app = FastAPI(title="Lab 1 - Attendance Flow")

# JWT-секрет и алгоритм для проверки сервисных токенов (выдаются api-gateway)
JWT_SECRET = os.environ.get("JWT_SECRET", "polyglot_jwt_secret_key_2026")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
# Схема Bearer для извлечения токена из заголовка Authorization
security = HTTPBearer()


def verify_service_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Проверка JWT-токена: тип=service, подпись HS256, срок действия."""
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "service":
            raise HTTPException(status_code=403, detail="Service token required")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Конфигурация Elasticsearch: полнотекстовый поиск по индексу lectures (BM25, fuzzy, russian_custom)
ES_HOST = os.environ.get("ES_HOST", "elasticsearch")
ES_PORT = int(os.environ.get("ES_PORT", 9200))
# Конфигурация Neo4j: обход графа Student-[SHOULD_ATTEND]->Schedule-[PART_OF]->Lecture
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASSWORD", "password12345")
# Конфигурация PostgreSQL: подсчёт attendance_pct по is_present в partitioned таблице
PG_HOST = os.environ.get("POSTGRES_HOST", "postgres")
PG_PORT = int(os.environ.get("POSTGRES_PORT", 5432))
PG_DB = os.environ.get("POSTGRES_DB", "university")
PG_USER = os.environ.get("POSTGRES_USER", "postgres")
PG_PASS = os.environ.get("POSTGRES_PASSWORD", "postgres")
# Конфигурация Redis: кэш данных студентов (Hash student:{id}, TTL=7200с)
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))


def get_es():
    """Создаёт клиент Elasticsearch для шага 1 (BM25-поиск термина)."""
    return Elasticsearch(f"http://{ES_HOST}:{ES_PORT}")


def get_neo4j():
    """Создаёт драйвер Neo4j для шага 2 (обход SHOULD_ATTEND + PART_OF)."""
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


def get_pg():
    """Создаёт соединение с PostgreSQL для шага 3 (unnest + LEFT JOIN attendance)."""
    return psycopg2.connect(host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASS)


def get_redis():
    """Создаёт клиент Redis для шага 4 (pipeline HGETALL + cache-aside)."""
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


@app.get("/query")
def query_attendance_flow(
    term: str = Query(..., description="Термин для поиска в лекциях"),
    start_date: str = Query(..., description="Начало периода (YYYY-MM-DD)"),
    end_date: str = Query(..., description="Конец периода (YYYY-MM-DD)"),
    _=Depends(verify_service_token)
):
    """
    ЛР1: 10 студентов с минимальным % посещения лекций, содержащих термин.
    Путь: Elasticsearch → Neo4j → PostgreSQL → Redis.
    """
    steps = []
    start = time.time()

    # --- Шаг 1: Elasticsearch — полнотекстовый поиск термина ---
    # BM25 + fuzziness=AUTO для опечаток; russian_custom анализатор для русской морфологии.
    # Ищем термин в полях title, annotation, content_text (minimum_should_match=1).
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
        # Берём только нужные поля: lecture_id (для Neo4j), course_id/name/title/tags (для обогащения)
        "_source": ["lecture_id", "course_id", "course_name", "title", "tags"],
        "size": 500
    })
    es.close()

    lecture_hits = es_result["hits"]["hits"]
    # Извлекаем lecture_id — это ключевой результат шага 1, передаётся в Neo4j
    lecture_ids = [h["_source"]["lecture_id"] for h in lecture_hits]
    # Справочник lecture_id → информация о курсе (для term_in_course в итоговом отчёте)
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
        return {"result": [], "steps": steps, "query_path": "ES → Neo4j → PostgreSQL → Redis",
                "execution_time_sec": round(time.time() - start, 3)}

    # --- Шаг 2: Neo4j — обход графа для получения пар студент↔расписание ---
    # Neo4j хранит связи (SHOULD_ATTEND), но НЕ хранит данные о фактическом посещении.
    # Получаем список (student_id, schedule_id) для передачи в PostgreSQL.
    # Cypher-запрос: Lecture (из ES) → Schedule (PART_OF, фильтр по дате) → Student (SHOULD_ATTEND)
    logger.info(f"Step 2: Neo4j - graph traversal for {len(lecture_ids)} lectures")
    driver = get_neo4j()
    neo_pairs = []

    with driver.session() as session:
        # MATCH: находим лекции из ES → расписания в периоде → студентов через SHOULD_ATTEND
        result = session.run("""
            MATCH (l:Lecture)
            WHERE l.id IN $lecture_ids
            MATCH (sch:Schedule)-[:PART_OF]->(l)
            WHERE sch.week_start_date >= $start_date AND sch.week_start_date <= $end_date
            MATCH (st:Student)-[:SHOULD_ATTEND]->(sch)
            RETURN DISTINCT st.id AS student_id, sch.id AS schedule_id
        """, lecture_ids=lecture_ids, start_date=start_date, end_date=end_date)

        for record in result:
            neo_pairs.append((record["student_id"], record["schedule_id"]))

    driver.close()

    steps.append({
        "step": 2,
        "store": "Neo4j",
        "action": "Обход графа: Schedule-[PART_OF]->Lecture (фильтр по lecture_ids + период), Student-[SHOULD_ATTEND]->Schedule — O(E) по индексу",
        "result": f"Найдено {len(neo_pairs)} пар студент↔расписание (связи, без данных о посещении)"
    })

    if not neo_pairs:
        return {"result": [], "steps": steps, "query_path": "ES → Neo4j → PostgreSQL → Redis",
                "execution_time_sec": round(time.time() - start, 3)}

    # --- Шаг 3: PostgreSQL — подсчёт посещаемости по is_present ---
    # Attendance — партиционированная таблица (PARTITION BY RANGE week_start_date, 4 партиции).
    # Только PostgreSQL хранит фактические данные о посещении (is_present BOOLEAN).
    # Передаём пары из Neo4j через unnest() для batch-обработки — эффективнее N+1 запросов.
    logger.info(f"Step 3: PG - attendance stats for {len(neo_pairs)} pairs")
    pg = get_pg()
    cur = pg.cursor()

    # Разделяем пары на два массива для unnest() в SQL
    student_ids_neo = list(set(p[0] for p in neo_pairs))
    schedule_ids_neo = list(set(p[1] for p in neo_pairs))

    # CTE neo_data: разворачиваем массивы из Neo4j через unnest() в строки
    # LEFT JOIN attendance: если записи нет — студент не пришёл (is_present=NULL/missing)
    # FILTER (WHERE a.is_present = TRUE): считаем только посещённые занятия
    # ORDER BY attendance_pct ASC LIMIT 10: топ-10 с минимальным % посещения
    cur.execute("""
        WITH neo_data AS (
            SELECT unnest(%s::uuid[]) AS student_id,
                   unnest(%s::uuid[]) AS schedule_id
        )
        SELECT nd.student_id,
               COUNT(DISTINCT nd.schedule_id) AS total_scheduled,
               COUNT(DISTINCT a.schedule_id) FILTER (WHERE a.is_present = TRUE) AS total_attended
        FROM neo_data nd
        LEFT JOIN attendance a ON a.schedule_id = nd.schedule_id
            AND a.student_id = nd.student_id
            AND a.week_start_date BETWEEN %s AND %s
        GROUP BY nd.student_id
        ORDER BY (COALESCE(COUNT(DISTINCT a.schedule_id) FILTER (WHERE a.is_present = TRUE), 0)::numeric
                  / NULLIF(COUNT(DISTINCT nd.schedule_id), 0)) ASC
        LIMIT 10
    """, (student_ids_neo, schedule_ids_neo, start_date, end_date))

    top10_pg = cur.fetchall()

    # Получаем полные данные студентов из PG (ФИО, email, phone, номер зачётки и т.д.)
    top10_student_ids = [str(r[0]) for r in top10_pg]
    cur.execute("""
        SELECT id, first_name, last_name, patronymic, email, phone,
               student_card_number, group_id, status, enrollment_date
        FROM student WHERE id = ANY(%s::uuid[])
    """, (top10_student_ids,))
    student_pg_data = {}
    for row in cur.fetchall():
        student_pg_data[str(row[0])] = {
            "first_name": row[1],
            "last_name": row[2],
            "patronymic": row[3] or "",
            "email": row[4],
            "phone": row[5] or "",
            "student_card_number": row[6],
            "group_id": str(row[7]),
            "status": row[8],
            "enrollment_date": str(row[9])
        }

    # Справочник group_id → lecture_ids для обогащения term_in_course
    # (какие лекции с термином привязаны к группе студента)
    cur.execute("""
        SELECT sch.group_id, array_agg(DISTINCT sch.lecture_id)
        FROM schedule sch
        WHERE sch.lecture_id = ANY(%s::uuid[])
          AND sch.week_start_date BETWEEN %s AND %s
        GROUP BY sch.group_id
    """, (lecture_ids, start_date, end_date))
    group_lecture_map = {str(r[0]): [str(lid) for lid in r[1]] for r in cur.fetchall()}

    cur.close()
    pg.close()

    steps.append({
        "step": 3,
        "store": "PostgreSQL",
        "action": "unnest(Neo4j pairs) + LEFT JOIN attendance (is_present=TRUE) → attendance_pct, partition pruning по week_start_date, ORDER BY ASC LIMIT 10",
        "result": f"Топ-10 студентов с минимальным % посещения (is_present из partitioned attendance)"
    })

    results = []
    for row in top10_pg:
        sid = str(row[0])
        total_scheduled = row[1]
        total_attended = row[2]
        pct = round((total_attended / total_scheduled * 100) if total_scheduled > 0 else 0, 2)
        sd = student_pg_data.get(sid, {})
        gid = sd.get("group_id", "")

        group_lectures = group_lecture_map.get(gid, [])
        first_matching = next((lid for lid in group_lectures if lid in course_info), None)
        term_info = course_info.get(first_matching, {})

        results.append({
            "student": {
                "id": sid,
                "first_name": sd.get("first_name", ""),
                "last_name": sd.get("last_name", ""),
                "patronymic": sd.get("patronymic", ""),
                "email": sd.get("email", ""),
                "phone": sd.get("phone", ""),
                "student_card_number": sd.get("student_card_number", ""),
                "status": sd.get("status", ""),
                "enrollment_date": sd.get("enrollment_date", "")
            },
            "group_id": gid,
            "attendance_pct": pct,
            "total_scheduled": total_scheduled,
            "total_attended": total_attended,
            "period": {"start_date": start_date, "end_date": end_date},
            "term_in_course": {
                "course_name": term_info.get("course_name", ""),
                "lecture_title": term_info.get("lecture_title", ""),
                "tags": term_info.get("tags", [])
            }
        })

    if not results:
        return {"result": [], "steps": steps, "query_path": "ES → Neo4j → PostgreSQL → Redis",
                "execution_time_sec": round(time.time() - start, 3)}

    # --- Шаг 4: Redis — cache-aside для данных студентов топ-10 ---
    # Pipeline HGETALL student:{id} — O(1) для каждого ключа, батчевый запрос.
    # При попадании кэша — данные берутся из Redis (без запроса к PG).
    # При промахе — заполняем из данных PG (cache-aside), TTL=7200с (2 часа).
    logger.info(f"Step 4: Redis - pipeline for {len(results)} students")
    r = get_redis()
    # Pipeline: отправляем все HGETALL одним пакетом (уменьшаем round-trip)
    pipe = r.pipeline()
    for ri in results:
        pipe.hgetall(f"student:{ri['student']['id']}")
    cached_results = pipe.execute()

    cache_hits = 0
    cache_misses = 0
    # Pipeline для заполнения кэша при промахах (cache-aside pattern)
    fill_pipe = r.pipeline()
    for ri, cached in zip(results, cached_results):
        if cached:
            cache_hits += 1
        else:
            cache_misses += 1
            # Записываем данные студента в Redis Hash с TTL=7200с
            s = ri["student"]
            fill_pipe.hset(f"student:{s['id']}", mapping={
                "first_name": s["first_name"],
                "last_name": s["last_name"],
                "patronymic": s["patronymic"],
                "email": s["email"],
                "phone": s["phone"],
                "student_card_number": s["student_card_number"],
                "group_id": ri["group_id"],
                "status": s["status"],
                "enrollment_date": s["enrollment_date"]
            })
            fill_pipe.expire(f"student:{s['id']}", 7200)
    if cache_misses:
        fill_pipe.execute()  # Выполняем pipeline только если были промахи

    steps.append({
        "step": 4,
        "store": "Redis",
        "action": f"Pipeline HGETALL student:{{id}} для топ-10 (Hash, TTL=2ч). Попаданий: {cache_hits}, промахов: {cache_misses} (пополнение из данных PG)",
        "result": f"Кэш проверен/пополнен для {len(results)} студентов"
    })

    elapsed = round(time.time() - start, 3)

    # Обоснование выбора хранилищ для каждого шага запроса
    return {
        "result": results,
        "steps": steps,
        "query_path": "ES → Neo4j → PostgreSQL → Redis",
        "execution_time_sec": elapsed,
        "justification": {
            "Elasticsearch": "Полнотекстовый поиск (BM25, fuzziness, russian_custom) — эффективнее LIKE в PostgreSQL",
            "Neo4j": "Обход графа SHOULD_ATTEND: связи студент↔расписание для лекций из ES — O(E), сужает область для PG",
            "PostgreSQL": "Единственный источник данных о фактическом посещении (is_present в partitioned attendance) — unnest + LEFT JOIN + FILTER",
            "Redis": "O(1) pipeline HGETALL student:{id} для 10 студентов — кэш-проверка вместо повторного запроса к PG"
        }
    }


@app.get("/")
def root():
    return {"service": "lab1", "description": "Attendance flow: ES → Neo4j → PostgreSQL → Redis"}
