"""
Lab3 Service — запланированные и посещённые часы по спец. дисциплинам для группы

Задание ЛР3:
  Выполнить запрос для извлечения отчёта по заданной группе учащихся с указанием
  объёма прослушанных часов лекций и необходимого объёма запланированных часов,
  в рамках всех курсов для каждого студента группы.
  Одна лекция = 2 академических часа.
  В отчёт попадают только лекции, содержащие тег специальной дисциплины кафедры.
  Результат: полная информация о группе, студенте, курсе, запланированных и посещённых часах.

Путь запроса: Elasticsearch → Neo4j → PostgreSQL

Шаг 0 — PostgreSQL:
  Lookup group_id по group_name (пользователь вводит название группы).

Шаг 1 — Elasticsearch:
  Фильтрация по тегам спец. дисциплин (terms query: спецдисциплина, кафедральная_дисциплина
  и т.д.) + lecture_type=лекция. Результат: lecture_id спец. дисциплин.

Шаг 2 — Neo4j:
  Обход графа от одной стартовой группы:
  Student-[MEMBER_OF]->Group-[CONTAINS]->Schedule-[PART_OF]->Lecture-[BELONGS_TO]->Course
  WHERE Lecture.id IN lecture_ids (из ES).
  Результат: студент → курсы → расписания.

Шаг 3 — PostgreSQL:
  Batch ANY(%s::uuid[]) для attendance (partitioned), lecture_hours, student details, hierarchy.
  attended_hours = attended_count * 2 (1 лекция = 2 ак.ч.).
"""
from fastapi import FastAPI, Query, Depends, HTTPException          # веб-фреймворк для REST API
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials  # схема Bearer-авторизации для JWT
from elasticsearch import Elasticsearch                              # клиент Elasticsearch для полнотекстового поиска и фильтрации по тегам
from neo4j import GraphDatabase                                     # драйвер Neo4j для обхода графа связей студент→группа→расписание→лекция→курс
import psycopg2                                                     # драйвер PostgreSQL для реляционных запросов (группы, посещаемость, иерархия)
import jwt                                                          # библиотека PyJWT для декодирования и проверки сервисных токенов
import os                                                           # чтение переменных окружения (хосты, пароли, секреты)
import logging                                                      # логирование шагов запроса и ошибок
import time                                                         # замер времени выполнения запроса

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Lab 3 - Hours Report")

# Секрет и алгоритм для верификации JWT-токенов сервисного типа.
# Токен с type="service" выдаётся шлюзом авторизации; он подтверждает,
# что запрос приходит от доверенного микросервиса, а не от конечного пользователя.
JWT_SECRET = os.environ.get("JWT_SECRET", "polyglot_jwt_secret_key_2026")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
security = HTTPBearer()  # автоматически извлекает Bearer-токен из заголовка Authorization


# Принимаются только сервисные токены (type=service), пользовательские токены отклоняются — защита в глубину (defense in depth)
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

# Параметры подключения к трём базам данных (Elasticsearch, PostgreSQL, Neo4j),
# читаемые из переменных окружения Docker-контейнера.
ES_HOST = os.environ.get("ES_HOST", "elasticsearch")
ES_PORT = int(os.environ.get("ES_PORT", 9200))
PG_HOST = os.environ.get("POSTGRES_HOST", "postgres")
PG_PORT = int(os.environ.get("POSTGRES_PORT", 5432))
PG_DB = os.environ.get("POSTGRES_DB", "university")
PG_USER = os.environ.get("POSTGRES_USER", "postgres")
PG_PASS = os.environ.get("POSTGRES_PASSWORD", "postgres")
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASSWORD", "password12345")

# По условию задания: 1 лекция = 2 академических часа.
# Используется для пересчёта количества посещённых лекций в академические часы.
HOURS_PER_LECTURE = 2


# Возвращает клиент Elasticsearch для поиска BM25
def get_es():
    return Elasticsearch(f"http://{ES_HOST}:{ES_PORT}")


# Возвращает драйвер Neo4j для обхода графа
def get_neo4j():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


# Возвращает соединение PostgreSQL для batch-запросов
def get_pg():
    return psycopg2.connect(host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASS)


# =============================================================================
# Основной запрос: отчёт по запланированным и посещённым часам спец. дисциплин
# =============================================================================
# Путь выполнения запроса (4 шага):
#   Шаг 0 (PostgreSQL) — lookup: group_name → group_id (пользователь вводит название, а не UUID)
#   Шаг 1 (Elasticsearch) — фильтрация лекций по тегам спец. дисциплин (terms query по keyword-полю)
#   Шаг 2 (Neo4j) — обход графа от стартовой ноды Group по цепочке связей
#   Шаг 3 (PostgreSQL) — batch-запросы посещаемости, запланированных часов, деталей студентов, иерархии
# =============================================================================
@app.get("/query")
def query_hours_report(
    group_name: str = Query(..., description="Название группы учащихся"),
    _=Depends(verify_service_token)
):
    steps = []
    start = time.time()

    # ── Шаг 0: Lookup group_name → group_id ──
    # Пользователь вводит название группы (например, "ПИ-301"), а не её UUID.
    # Поэтому сначала ищем строку группы в PostgreSQL по имени,
    # чтобы получить group_id, enrollment_year, curator и speciality_id,
    # которые понадобятся на последующих шагах.
    pg = get_pg()
    cur = pg.cursor()
    cur.execute("SELECT id, name, enrollment_year, curator, speciality_id FROM student_group WHERE name = %s", (group_name,))
    group_row = cur.fetchone()
    cur.close()
    pg.close()

    if not group_row:
        raise HTTPException(status_code=404, detail=f"Группа '{group_name}' не найдена")

    group_id = str(group_row[0])
    group_info = {
        "id": group_id,
        "name": group_row[1],
        "enrollment_year": group_row[2],
        "curator": group_row[3],
        "speciality_id": str(group_row[4])
    }

    logger.info("Step 1: ES - lectures with special discipline tags")
    es = get_es()

    # ── Шаг 1: Фильтрация лекций по тегам специальной дисциплины ──
    # В Elasticsearch индекс "lectures" хранит поле tags как keyword-тип.
    # Фильтр terms query по keyword-полю работает значительно быстрее,
    # чем array_contains / ANY() в PostgreSQL на больших массивах.
    # Дополнительно ограничиваем lecture_type="лекция" (исключаем семинары, лабораторные).
    # Результат: список lecture_id лекций спец. дисциплин для передачи в Neo4j.
    special_tags = ["спецдисциплина", "кафедральная_дисциплина", "профильная_дисциплина",
                    "дисциплина_кафедры", "специализация"]

    es_result = es.search(index="lectures", body={
        "query": {
            "bool": {
                "must": [
                    {"term": {"lecture_type": "лекция"}},
                    {"terms": {"tags": special_tags}}
                ]
            }
        },
        "_source": ["lecture_id", "course_id", "course_name", "title", "tags", "semester"],
        "size": 2000
    })
    es.close()

    lecture_hits = es_result["hits"]["hits"]
    lecture_ids = [h["_source"]["lecture_id"] for h in lecture_hits]
    lecture_es_info = {}
    for h in lecture_hits:
        src = h["_source"]
        lid = src["lecture_id"]
        lecture_es_info[lid] = {
            "course_id": src.get("course_id", ""),
            "course_name": src.get("course_name", ""),
            "title": src.get("title", ""),
            "tags": src.get("tags", []),
            "semester": src.get("semester", 0)
        }

    steps.append({
        "step": 1,
        "store": "Elasticsearch",
        "action": "Фильтрация по тегам спец. дисциплин (terms query on keyword field + filter lecture_type=лекция) — быстрее ANY() в PostgreSQL",
        "result": f"Найдено {len(lecture_ids)} лекций со спец. тегами"
    })

    if not lecture_ids:
        return {"students": [], "steps": steps, "query_path": "ES → Neo4j → PostgreSQL",
                "execution_time_sec": round(time.time() - start, 3)}

    logger.info(f"Step 2: Neo4j - graph traversal for group {group_name}")
    driver = get_neo4j()

    # ── Шаг 2: Обход графа Neo4j от одной стартовой ноды Group ──
    # Цепочка связей: Student-[MEMBER_OF]->Group-[CONTAINS]->Schedule-[PART_OF]->Lecture-[BELONGS_TO]->Course
    # Стартуем от единственной ноды StudentGroup с известным group_id (из Шага 0).
    # Фильтруем Lecture по lecture_ids (из Шага 1) — остаются только спец. дисциплины.
    # Обход по индексу — O(E), эффективнее чем 4 JOIN в PostgreSQL.
    # Результат: для каждого студента — набор курсов и расписаний спец. дисциплин.
    student_course_schedules = {}

    with driver.session() as session:
        result = session.run("""
            MATCH (g:StudentGroup {id: $group_id})
            MATCH (st:Student)-[:MEMBER_OF]->(g)
            MATCH (g)-[:CONTAINS]->(sch:Schedule)
            MATCH (sch)-[:PART_OF]->(l:Lecture)
            MATCH (l)-[:BELONGS_TO]->(c:LectureCourse)
            WHERE l.id IN $lecture_ids
            RETURN DISTINCT st.id AS student_id, st.name AS student_name,
                   c.id AS course_id, c.name AS course_name, c.semester AS semester,
                   sch.id AS schedule_id, l.id AS lecture_id, l.title AS lecture_title
        """, group_id=group_id, lecture_ids=lecture_ids)

        student_set = set()
        course_set = set()

        for record in result:
            sid = record["student_id"]
            cid = record["course_id"]
            student_set.add(sid)
            course_set.add(cid)

            if sid not in student_course_schedules:
                student_course_schedules[sid] = {
                    "name": record["student_name"],
                    "courses": {}
                }
            if cid not in student_course_schedules[sid]["courses"]:
                student_course_schedules[sid]["courses"][cid] = {
                    "name": record["course_name"],
                    "semester": record["semester"],
                    "schedule_ids": [],
                    "lecture_ids": set()
                }
            student_course_schedules[sid]["courses"][cid]["schedule_ids"].append(record["schedule_id"])
            student_course_schedules[sid]["courses"][cid]["lecture_ids"].add(record["lecture_id"])

    driver.close()

    steps.append({
        "step": 2,
        "store": "Neo4j",
        "action": "Обход графа: Student-[MEMBER_OF]->Group-[CONTAINS]->Schedule-[PART_OF]->Lecture-[BELONGS_TO]->Course — O(E) по индексу, 1 стартовая нода Group",
        "result": f"Найдено {len(student_set)} студентов, {len(course_set)} курсов спец. дисциплин"
    })

    if not student_course_schedules:
        return {"students": [], "steps": steps, "query_path": "ES → Neo4j → PostgreSQL",
                "execution_time_sec": round(time.time() - start, 3)}

    logger.info("Step 3: PG - batch attendance + hours + student details")
    pg = get_pg()
    cur = pg.cursor()

    # ── Шаг 3: Batch-запросы в PostgreSQL ──
    # Используем ANY(%s::uuid[]) вместо построчных запросов — один запрос покрывает
    # весь набор UUID. На partitioned/indexed таблице attendance это O(K),
    # где K ≈ количество записей расписания группы (~40).
    # Расчёт посещённых часов: attended_hours = attended_count * HOURS_PER_LECTURE (1 лекция = 2 ак.ч.).

    # Получаем запланированные часы (lecture_hours) из таблицы lecture_course
    # для всех курсов спец. дисциплин, найденных на Шаге 2.
    course_ids_list = list(course_set)
    cur.execute("""
        SELECT id, lecture_hours FROM lecture_course WHERE id = ANY(%s::uuid[])
    """, (course_ids_list,))
    course_planned_hours = {str(r[0]): r[1] for r in cur.fetchall()}

    student_ids_list = list(student_set)

    # Batch-запрос посещаемости: DISTINCT пар (student_id, schedule_id)
    # из секционированной таблицы attendance. ANY(%s::uuid[]) позволяет
    # передать весь массив UUID одним параметром вместо N отдельных SELECT.
    all_schedule_ids = []
    for sid, sdata in student_course_schedules.items():
        for cid, cdata in sdata["courses"].items():
            all_schedule_ids.extend(cdata["schedule_ids"])

    cur.execute("""
        SELECT DISTINCT a.student_id, a.schedule_id
        FROM attendance a
        WHERE a.student_id = ANY(%s::uuid[])
          AND a.schedule_id = ANY(%s::uuid[])
    """, (student_ids_list, list(set(all_schedule_ids))))
    attendance_rows = cur.fetchall()

    # Формируем карту посещений: student_id → set(schedule_id),
    # чтобы на этапе агрегации быстро проверить, посещал ли студент данное расписание.
    attended_map = {}
    for row in attendance_rows:
        sid = str(row[0])
        schid = str(row[1])
        attended_map.setdefault(sid, set()).add(schid)

    # Batch-запрос детальной информации о студентах (ФИО, email, номер студенческого билета и т.д.)
    cur.execute("""
        SELECT id, first_name, last_name, patronymic, email, student_card_number,
               group_id, status, enrollment_date
        FROM student WHERE id = ANY(%s::uuid[])
    """, (student_ids_list,))
    student_details = {}
    for row in cur.fetchall():
        sid = str(row[0])
        student_details[sid] = {
            "first_name": row[1],
            "last_name": row[2],
            "patronymic": row[3] or "",
            "email": row[4],
            "student_card_number": row[5],
            "group_id": str(row[6]),
            "status": row[7],
            "enrollment_date": str(row[8])
        }

    # ── Иерархический запрос: институт → кафедра для данной группы ──
    # Цепочка JOIN: student_group → speciality → department_specialities → department → institute
    # Позволяет получить названия института и кафедры, к которым относится группа.
    cur.execute("""
        SELECT sg.id, i.name, d.name
        FROM student_group sg
        JOIN speciality sp ON sg.speciality_id = sp.id
        JOIN department_specialities ds ON ds.speciality_id = sp.id
        JOIN department d ON ds.department_id = d.id
        JOIN institute i ON d.institute_id = i.id
        WHERE sg.name = %s
        LIMIT 1
    """, (group_name,))
    hier_row = cur.fetchone()
    hierarchy = {}
    if hier_row:
        hierarchy = {
            "institute": hier_row[1],
            "department": hier_row[2]
        }

    cur.close()
    pg.close()

    # ── Агрегация результатов: формируем отчёт по каждому студенту ──
    # Пересечение schedule_ids курса с attended_map даёт количество посещённых лекций.
    # attended_hours = attended_count * HOURS_PER_LECTURE (2 ак.ч. за лекцию).
    student_results = []
    for sid, sdata in student_course_schedules.items():
        course_reports = []
        for cid, cdata in sdata["courses"].items():
            attended_count = len(set(cdata["schedule_ids"]) & attended_map.get(sid, set()))
            attended_hours = attended_count * HOURS_PER_LECTURE
            planned_hours = course_planned_hours.get(cid, 0)

            first_lecture_id = next(iter(cdata["lecture_ids"]), None)
            tags = lecture_es_info.get(first_lecture_id, {}).get("tags", [])

            course_reports.append({
                "course_id": cid,
                "course_name": cdata["name"],
                "semester": cdata["semester"],
                "planned_hours": planned_hours,
                "attended_lectures": attended_count,
                "attended_hours": attended_hours,
                "total_scheduled_lectures": len(cdata["schedule_ids"]),
                "special_tags": tags
            })

        sd = student_details.get(sid, {})
        student_results.append({
            "student_id": sid,
            "student_name": sdata["name"],
            "student_details": sd,
            "courses": course_reports,
            "total_planned_hours": sum(c["planned_hours"] for c in course_reports),
            "total_attended_hours": sum(c["attended_hours"] for c in course_reports)
        })

    steps.append({
        "step": 3,
        "store": "PostgreSQL",
        "action": "Batch: attendance DISTINCT + lecture_hours + student details + hierarchy JOINs — ANY(%s::uuid[]) на partitioned/indexed данных, O(K) где K — расписание группы",
        "result": f"Рассчитаны часы для {len(student_results)} студентов ({sum(len(s['courses']) for s in student_results)} записей)"
    })

    elapsed = round(time.time() - start, 3)

    return {
        "group": group_info,
        "hierarchy": hierarchy,
        "students": student_results,
        "hours_per_lecture": HOURS_PER_LECTURE,
        "steps": steps,
        "query_path": "ES → Neo4j → PostgreSQL",
        "execution_time_sec": elapsed,
        "justification": {
            "Elasticsearch": "Фильтрация по тегам спец. дисциплин (terms query on keyword) — быстрее array_contains в PostgreSQL",
            "Neo4j": "Обход графа Student→Group→Schedule→Lecture→Course — O(E), 1 стартовая нода Group, эффективнее 4 JOIN",
            "PostgreSQL": "Batch ANY(%s::uuid[]) на partitioned/indexed таблице attendance — O(K), K = расписание группы (~40)"
        }
    }


# Endpoint проверки работоспособности (health-check)
@app.get("/")
def root():
    return {"service": "lab3", "description": "Hours report: ES → Neo4j → PostgreSQL"}
