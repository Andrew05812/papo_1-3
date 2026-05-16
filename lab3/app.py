"""
Lab3 Service — запланированные и посещённые часы по спец. дисциплинам для группы

Задание ЛР3:
  Выполнить запрос для извлечения отчёта по заданной группе учащихся с указанием
  объёма прослушанных часов лекций и необходимого объёма запланированных часов,
  в рамках всех курсов для каждого студента группы.
  Одна лекция = 2 академических часа.
  В отчёт попадают только лекции, содержащие тег специальной дисциплины кафедры.
  Результат: полная информация о группе, студенте, курсе, запланированных и посещённых часах.

Путь запроса: Neo4j → PostgreSQL

Шаг 1 — Neo4j:
  Обход графа от стартовой ноды Group по имени:
  Student-[MEMBER_OF]->Group-[CONTAINS]->Schedule-[PART_OF]->Lecture-[BELONGS_TO]->Course
  Фильтр: lecture_type='лекция' AND ANY(tag IN l.tags WHERE tag IN special_tags).
  Также получаем: lecture_hours из LectureCourse, student details из Student,
  иерархию через LectureCourse-[FOR_SPECIALITY]->Speciality-[PART_OF]->Department-[PART_OF]->Institute-[PART_OF]->University.
  Результат: студент → курсы → расписания + lecture_hours + student details + иерархия.

Шаг 2 — PostgreSQL:
  Единственный источник данных о фактическом посещении (is_present BOOLEAN).
  Связь ATTENDED в Neo4j не отличает пришёл/не пришёл — создана для всех записей.
  Batch ANY(%s::uuid[]) для attendance (partitioned), FILTER (WHERE is_present = TRUE).
  attended_hours = attended_count * 2 (1 лекция = 2 ак.ч.).
"""
# FastAPI — веб-фреймворк для REST API; Query — параметры запроса; Depends — внедрение зависимостей; HTTPException — ошибки
from fastapi import FastAPI, Query, Depends, HTTPException
# HTTPBearer — схема Bearer-аутентификации; HTTPAuthorizationCredentials — объект с токеном из заголовка Authorization
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# Neo4j: графовая СУБД; GraphDatabase — драйвер для обхода Student-[MEMBER_OF]->Group-[CONTAINS]->Schedule-[PART_OF]->Lecture-[BELONGS_TO]->Course
from neo4j import GraphDatabase
# psycopg2: драйвер PostgreSQL для подсчёта посещаемости по is_present в partitioned таблице attendance
import psycopg2
# jwt: библиотека PyJWT для декодирования и проверки JWT-токенов сервисной аутентификации
import jwt
# os: чтение переменных окружения для конфигурации подключений к Neo4j, PG и JWT-секрета
import os
# logging: структурированный логгинг шагов запроса (Neo4j → PG)
import logging
# time: замер общего времени выполнения запроса (execution_time_sec)
import time

# Настройка логгирования: INFO-уровень для протоколирования каждого шага запроса
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI-приложение для ЛР3 — отчёт по запланированным и посещённым часам
app = FastAPI(title="Lab 3 - Hours Report (Neo4j → PostgreSQL)")

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

# Конфигурация Neo4j: обход графа от стартовой ноды Group + фильтрация по тегам + иерархия
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASSWORD", "password12345")
# Конфигурация PostgreSQL: единственный источник is_present в partitioned таблице attendance
PG_HOST = os.environ.get("POSTGRES_HOST", "postgres")
PG_PORT = int(os.environ.get("POSTGRES_PORT", 5432))
PG_DB = os.environ.get("POSTGRES_DB", "university")
PG_USER = os.environ.get("POSTGRES_USER", "postgres")
PG_PASS = os.environ.get("POSTGRES_PASSWORD", "postgres")

# 1 лекция = 2 академических часа
HOURS_PER_LECTURE = 2


def get_neo4j():
    """Создаёт драйвер Neo4j для шага 1 (обход графа от Group)."""
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


def get_pg():
    """Создаёт соединение с PostgreSQL для шага 2 (is_present в attendance)."""
    return psycopg2.connect(host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASS)


@app.get("/query")
def query_hours_report(
    group_name: str = Query(..., description="Название группы учащихся"),
    _=Depends(verify_service_token)
):
    """
    ЛР3: Отчёт по запланированным и посещённым часам спец. дисциплин для группы.
    Путь: Neo4j → PostgreSQL.
    """
    steps = []
    start = time.time()

    # ── Шаг 1: Neo4j — обход графа от стартовой ноды Group ──
    # Цепочка: Student-[MEMBER_OF]->Group-[CONTAINS]->Schedule-[PART_OF]->Lecture-[BELONGS_TO]->Course
    # Фильтр: lecture_type='лекция' AND теги спец. дисциплин.
    # Также: lecture_hours из Course, student details из Student, иерархия через Course→Speciality→Department→Institute→University.
    # Преимущество Neo4j: обход от 1 стартовой ноды Group за O(E) вместо 4 JOIN в SQL.
    logger.info(f"Step 1: Neo4j - graph traversal for group {group_name}")
    driver = get_neo4j()

    # Теги специальных дисциплин кафедры
    special_tags = ["спецдисциплина", "кафедральная_дисциплина", "профильная_дисциплина",
                    "дисциплина_кафедры", "специализация"]

    # Структура: student_id → {name, details, courses: {course_id → {name, semester, lecture_hours, schedule_ids, lecture_ids, tags}}}
    student_course_schedules = {}
    student_details = {}
    course_planned_hours = {}
    group_info = {}
    hierarchy = {}

    with driver.session() as session:
        # Комплексный Cypher-запрос: от Group по имени → студенты → расписания → лекции (со спец. тегами) → курсы + иерархия
        result = session.run("""
            MATCH (g:StudentGroup {name: $group_name})
            MATCH (st:Student)-[:MEMBER_OF]->(g)
            MATCH (g)-[:CONTAINS]->(sch:Schedule)
            MATCH (sch)-[:PART_OF]->(l:Lecture)
            WHERE l.type = 'лекция' AND ANY(tag IN l.tags WHERE tag IN $special_tags)
            MATCH (l)-[:BELONGS_TO]->(c:LectureCourse)
            // Иерархия: Course→Speciality→Department→Institute→University
            OPTIONAL MATCH (c)-[:FOR_SPECIALITY]->(sp:Speciality)-[:PART_OF]->(d:Department)-[:PART_OF]->(i:Institute)-[:PART_OF]->(u:University)
            RETURN DISTINCT st.id AS student_id, st.name AS student_name,
                   st.first_name AS first_name, st.last_name AS last_name,
                   st.patronymic AS patronymic, st.email AS email,
                   st.card_number AS student_card_number, st.phone AS phone,
                   st.status AS status, st.enrollment_date AS enrollment_date,
                   c.id AS course_id, c.name AS course_name, c.semester AS semester,
                   c.lecture_hours AS lecture_hours,
                   sch.id AS schedule_id, l.id AS lecture_id, l.title AS lecture_title, l.tags AS tags,
                   g.id AS group_id, g.enrollment_year AS enrollment_year, g.curator AS curator,
                   sp.name AS speciality_name, sp.code AS speciality_code,
                   d.name AS department_name, i.name AS institute_name, u.name AS university_name
        """, group_name=group_name, special_tags=special_tags)

        student_set = set()
        course_set = set()

        for record in result:
            sid = record["student_id"]
            cid = record["course_id"]
            student_set.add(sid)
            course_set.add(cid)

            # Student details из Neo4j (ФИО, email, номер зачётки и т.д.)
            if sid not in student_details:
                student_details[sid] = {
                    "first_name": record["first_name"] or "",
                    "last_name": record["last_name"] or "",
                    "patronymic": record["patronymic"] or "",
                    "email": record["email"] or "",
                    "student_card_number": record["student_card_number"] or "",
                    "phone": record["phone"] or "",
                    "status": record["status"] or "",
                    "enrollment_date": record["enrollment_date"] or ""
                }

            # Структура студент → курсы → расписания
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
                    "lecture_ids": set(),
                    "tags": record["tags"] or []
                }
            student_course_schedules[sid]["courses"][cid]["schedule_ids"].append(record["schedule_id"])
            student_course_schedules[sid]["courses"][cid]["lecture_ids"].add(record["lecture_id"])

            # Запланированные часы из LectureCourse (свойство узла в Neo4j)
            if cid not in course_planned_hours:
                course_planned_hours[cid] = record["lecture_hours"] or 0

            # Информация о группе из Neo4j
            if not group_info:
                group_info = {
                    "id": record["group_id"],
                    "name": group_name,
                    "enrollment_year": record["enrollment_year"],
                    "curator": record["curator"] or ""
                }

            # Иерархия из Neo4j: University→Institute→Department→Speciality
            if not hierarchy and record["institute_name"]:
                hierarchy = {
                    "university": record["university_name"] or "",
                    "institute": record["institute_name"] or "",
                    "department": record["department_name"] or ""
                }

    driver.close()

    steps.append({
        "step": 1,
        "store": "Neo4j",
        "action": "Обход графа: Student-[MEMBER_OF]->Group-[CONTAINS]->Schedule-[PART_OF]->Lecture-[BELONGS_TO]->Course + фильтр по спец. тегам + иерархия Course→Speciality→Department→Institute→University + student details + lecture_hours",
        "result": f"Найдено {len(student_set)} студентов, {len(course_set)} курсов спец. дисциплин"
    })

    if not student_course_schedules:
        return {"students": [], "steps": steps, "query_path": "Neo4j → PostgreSQL",
                "execution_time_sec": round(time.time() - start, 3)}

    # ── Шаг 2: PostgreSQL — подсчёт посещаемости по is_present ──
    # Attendance хранится только в PostgreSQL (partitioned по week_start_date).
    # ONLY PostgreSQL знает, был ли студент на занятии (is_present BOOLEAN).
    # Связь ATTENDED в Neo4j не отличает пришёл/не пришёл — создана для всех записей.
    # ANY(%s::uuid[]) для batch-подстановки — partition pruning автоматически отсекает лишние партиции.
    logger.info("Step 2: PG - attendance is_present filter")
    pg = get_pg()
    cur = pg.cursor()

    student_ids_list = list(student_set)

    # Собираем все schedule_ids из Neo4j-результата
    all_schedule_ids = []
    for sid, sdata in student_course_schedules.items():
        for cid, cdata in sdata["courses"].items():
            all_schedule_ids.extend(cdata["schedule_ids"])

    # Batch-запрос: только записи где is_present = TRUE (фактическое посещение)
    cur.execute("""
        SELECT DISTINCT a.student_id, a.schedule_id
        FROM attendance a
        WHERE a.student_id = ANY(%s::uuid[])
          AND a.schedule_id = ANY(%s::uuid[])
          AND a.is_present = TRUE
    """, (student_ids_list, list(set(all_schedule_ids))))
    attendance_rows = cur.fetchall()

    # Формируем справочник: student_id → set(schedule_id) где студент БЫЛ (is_present=TRUE)
    attended_map = {}
    for row in attendance_rows:
        sid = str(row[0])
        schid = str(row[1])
        attended_map.setdefault(sid, set()).add(schid)

    cur.close()
    pg.close()

    steps.append({
        "step": 2,
        "store": "PostgreSQL",
        "action": "Batch: SELECT DISTINCT FROM attendance WHERE is_present = TRUE — единственный источник данных о фактическом посещении (Neo4j связь ATTENDED не отличает пришёл/не пришёл)",
        "result": f"Найдено {sum(len(v) for v in attended_map.values())} фактических посещений для {len(attended_map)} студентов"
    })

    # ── Агрегация результатов ──
    # attended_hours = attended_count * HOURS_PER_LECTURE (2 ак.ч. за лекцию)
    # Пересечение schedule_ids из Neo4j с attended_map из PG даёт фактическое посещение
    student_results = []
    for sid, sdata in student_course_schedules.items():
        course_reports = []
        for cid, cdata in sdata["courses"].items():
            # Пересечение: лекции, где студент присутствовал (Neo4j schedule ∩ PG attendance is_present=TRUE)
            attended_count = len(set(cdata["schedule_ids"]) & attended_map.get(sid, set()))
            attended_hours = attended_count * HOURS_PER_LECTURE
            planned_hours = course_planned_hours.get(cid, 0)

            course_reports.append({
                "course_id": cid,
                "course_name": cdata["name"],
                "semester": cdata["semester"],
                "planned_hours": planned_hours,
                "attended_lectures": attended_count,
                "attended_hours": attended_hours,
                "total_scheduled_lectures": len(cdata["schedule_ids"]),
                "special_tags": cdata["tags"]
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

    elapsed = round(time.time() - start, 3)

    return {
        "group": group_info,
        "hierarchy": hierarchy,
        "students": student_results,
        "hours_per_lecture": HOURS_PER_LECTURE,
        "steps": steps,
        "query_path": "Neo4j → PostgreSQL",
        "execution_time_sec": elapsed,
        "justification": {
            "Neo4j": "Обход графа Student→Group→Schedule→Lecture→Course + фильтрация по спец. тегам + иерархия Course→Speciality→Department→Institute→University + student details + lecture_hours — O(E), 1 стартовая нода Group",
            "PostgreSQL": "Единственный источник данных о фактическом посещении (is_present=TRUE в partitioned attendance) — связь ATTENDED в Neo4j не отличает пришёл/не пришёл"
        }
    }


@app.get("/")
def root():
    return {"service": "lab3", "description": "Hours report: Neo4j → PostgreSQL"}
