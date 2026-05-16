"""
Lab2 Service — необходимый объём аудитории для курса по семестру и году

Задание ЛР2:
  Выполнить запрос для извлечения отчёта о необходимом объёме аудитории для
  проведения занятий по курсу заданного семестра и года обучения с требованиями
  к использованию технических средств.
  Результат: полная информация о курсе, лекции и количестве слушателей.

Путь запроса: Neo4j

Шаг 1 — Neo4j:
  Один комплексный Cypher-запрос:
  - Фильтрация лекций: semester, lecture_type='лекция', computer_type CONTAINS (или точное совпадение в tags)
  - Обход графа: Lecture-[BELONGS_TO]->LectureCourse,
    Lecture<-[PART_OF]-Schedule<-[CONTAINS]-StudentGroup<-[MEMBER_OF]-Student
  - Иерархия: LectureCourse-[FOR_SPECIALITY]->Speciality-[PART_OF]->Department-[PART_OF]->Institute-[PART_OF]->University
  - Агрегация: COUNT студентов в группе, collect() первых 10 студентов
  - Всё в одном запросе вместо 4 JOIN в PostgreSQL + Redis + MongoDB
"""
# FastAPI — веб-фреймворк для REST API; Query — параметры запроса; Depends — внедрение зависимостей; HTTPException — ошибки
from fastapi import FastAPI, Query, Depends, HTTPException
# HTTPBearer — схема Bearer-аутентификации; HTTPAuthorizationCredentials — объект с токеном из заголовка Authorization
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# Neo4j: графовая СУБД; GraphDatabase — драйвер для обхода всех связей в одном Cypher-запросе
from neo4j import GraphDatabase
# jwt: библиотека PyJWT для декодирования и проверки JWT-токенов сервисной аутентификации
import jwt
# os: чтение переменных окружения для конфигурации подключения к Neo4j и JWT-секрета
import os
# logging: структурированный логгинг шага запроса (Neo4j)
import logging
# time: замер общего времени выполнения запроса (execution_time_sec)
import time

# Настройка логгирования: INFO-уровень для протоколирования запроса
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI-приложение для ЛР2 — определение необходимого объёма аудитории (только Neo4j)
app = FastAPI(title="Lab 2 - Schedule Capacity (Neo4j)")

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

# Конфигурация Neo4j: единственное хранилище для ЛР2 — обход графа + агрегация + иерархия
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASSWORD", "password12345")


def get_neo4j():
    """Создаёт драйвер Neo4j для единственного шага запроса."""
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


@app.get("/query")
def query_schedule_capacity(
    semester: int = Query(..., description="Номер семестра (1-8)"),
    year: int = Query(..., description="Год обучения"),
    equipment: str = Query("", description="Требования к компьютерному обеспечению"),
    _=Depends(verify_service_token)
):
    """
    ЛР2: Определение необходимого объёма аудитории для курса по семестру и году.
    Путь: Neo4j (один комплексный Cypher-запрос).
    """
    steps = []
    start = time.time()

    # ===== ЕДИНСТВЕННЫЙ ШАГ: Neo4j =====
    # Один Cypher-запрос заменяет 4 операции:
    #   1) Фильтрация лекций по semester + computer_type + lecture_type
    #   2) Обход графа: Lecture→Course, Schedule←Group←Student
    #   3) COUNT студентов + collect() первых 10 (вместо Redis)
    #   4) Иерархия: Course→Speciality→Department→Institute→University (вместо MongoDB)
    logger.info(f"Step 1: Neo4j - semester={semester}, year={year}, equipment='{equipment}'")
    driver = get_neo4j()

    year_start = f"{year}-01-01"
    year_end = f"{year}-12-31"

    # Структуры для сбора данных из Cypher-результата
    course_info = {}
    lecture_info = {}
    schedule_by_lecture = {}
    group_data = {}
    hierarchy_info = {}

    with driver.session() as session:
        # Основной запрос: фильтрация + обход + агрегация + иерархия
        # toLower для регистронезависимого CONTAINS (аналог ILIKE в PostgreSQL)
        result = session.run("""
            MATCH (l:Lecture)
            WHERE l.type = 'лекция'
              AND ($equipment = '' OR toLower(l.computer_type) CONTAINS toLower($equipment) OR $equipment IN l.tags)
            MATCH (l)-[:BELONGS_TO]->(c:LectureCourse)
            WHERE c.semester = $semester
            MATCH (l)<-[:PART_OF]-(sch:Schedule)
            WHERE sch.date >= $year_start AND sch.date <= $year_end
            MATCH (sch)<-[:CONTAINS]-(g:StudentGroup)
            OPTIONAL MATCH (c)-[:FOR_SPECIALITY]->(sp:Speciality)-[:PART_OF]->(d:Department)-[:PART_OF]->(i:Institute)-[:PART_OF]->(u:University)
            OPTIONAL MATCH (st:Student)-[:MEMBER_OF]->(g)
            WITH l, c, sch, g, sp, d, i, u,
                 collect(st) AS all_students
            RETURN l.id AS lecture_id, l.title AS lecture_title, l.type AS lecture_type,
                   l.computer_type, l.tags,
                   c.id AS course_id, c.name AS course_name, c.semester AS course_semester,
                   c.total_hours AS course_total_hours,
                   c.lecture_hours AS course_lecture_hours, c.practice_hours AS course_practice_hours,
                   c.lab_hours AS course_lab_hours, c.description AS course_description,
                   sch.id AS schedule_id, sch.date AS scheduled_date,
                   sch.start_time, sch.end_time, sch.classroom, sch.teacher_name,
                   g.id AS group_id, g.name AS group_name,
                   size(all_students) AS student_count,
                   [s IN all_students[0..10] | {id: s.id, first_name: s.first_name, last_name: s.last_name, patronymic: s.patronymic, student_card_number: s.card_number}] AS students_sample,
                   sp.id AS speciality_id, sp.name AS speciality_name, sp.code AS speciality_code,
                   d.name AS department_name, d.short_name AS department_short,
                   i.name AS institute_name, i.short_name AS institute_short,
                   u.name AS university_name
        """, semester=semester, year_start=year_start, year_end=year_end, equipment=equipment)

        for record in result:
            # Собираем course_info
            cid = record.get("course_id")
            if cid and cid not in course_info:
                course_info[cid] = {
                    "name": record.get("course_name") or "",
                    "semester": record.get("course_semester") or 0,
                    "total_hours": record.get("course_total_hours") or 0,
                    "lecture_hours": record.get("course_lecture_hours") or 0,
                    "practice_hours": record.get("course_practice_hours") or 0,
                    "lab_hours": record.get("course_lab_hours") or 0,
                    "description": record.get("course_description") or ""
                }

            # Собираем lecture_info
            lid = record.get("lecture_id")
            if lid and lid not in lecture_info:
                lecture_info[lid] = {
                    "title": record.get("lecture_title") or "",
                    "type": record.get("lecture_type") or "",
                    "computer_type": record.get("computer_type") or "",
                    "tags": record.get("tags") or [],
                    "course_id": cid
                }

            # Собираем schedule_by_lecture
            if lid:
                if lid not in schedule_by_lecture:
                    schedule_by_lecture[lid] = []
                schedule_by_lecture[lid].append({
                    "schedule_id": record.get("schedule_id") or "",
                    "group_id": record.get("group_id") or "",
                    "classroom": record.get("classroom") or "",
                    "date": record.get("scheduled_date") or "",
                    "start_time": record.get("start_time") or "",
                    "end_time": record.get("end_time") or "",
                    "teacher": record.get("teacher_name") or ""
                })

            # Собираем group_data (уникальные группы с кол-вом студентов)
            gid = record.get("group_id")
            if gid and gid not in group_data:
                group_data[gid] = {
                    "name": record.get("group_name") or "",
                    "student_count": record.get("student_count") or 0,
                    "students_sample": record.get("students_sample") or []
                }

            # Собираем hierarchy_info (по speciality_id)
            spid = record.get("speciality_id")
            if spid and spid not in hierarchy_info:
                hierarchy_info[spid] = {
                    "university": record.get("university_name") or "",
                    "institute": record.get("institute_name") or "",
                    "department": record.get("department_name") or "",
                    "speciality": record.get("speciality_name") or "",
                    "speciality_code": record.get("speciality_code") or ""
                }

    driver.close()

    # Подсчитываем listeners для каждой лекции (сумма student_count по группам)
    lecture_group_ids = {}
    for lid, scheds in schedule_by_lecture.items():
        gids = set(sch["group_id"] for sch in scheds)
        lecture_group_ids[lid] = gids

    total_lectures = len(lecture_info)
    total_schedules = sum(len(v) for v in schedule_by_lecture.values())

    steps.append({
        "step": 1,
        "store": "Neo4j",
        "action": f"Комплексный Cypher-запрос: фильтр (semester={semester}, computer_type CONTAINS '{equipment}', lecture_type='лекция') + обход графа Lecture→Course→Schedule→Group→Student + иерархия Course→Speciality→Department→Institute→University + collect()/size() для COUNT студентов",
        "result": f"Найдено {total_lectures} лекций, {total_schedules} расписаний за {year} год, {len(group_data)} групп"
    })

    if not lecture_info:
        return {"result": [], "steps": steps, "query_path": "Neo4j",
                "execution_time_sec": round(time.time() - start, 3)}

    # ===== ФИНАЛЬНАЯ СБОРКА =====
    # Группируем лекции по курсам (как в оригинальной Lab2)
    course_lectures = {}
    for lid, li in lecture_info.items():
        cid = li["course_id"]
        course_lectures.setdefault(cid, set()).add(lid)

    # Собираем группы, привязанные к курсу через расписание
    course_groups = {}
    for lid, gids in lecture_group_ids.items():
        cid = lecture_info[lid]["course_id"]
        course_groups.setdefault(cid, set()).update(gids)

    final_results = []
    for cid, lec_ids in course_lectures.items():
        ci = course_info.get(cid, {})

        # Определяем speciality_id через lecture_info → course → speciality
        # Берём первую иерархию, которую нашли для этого курса
        hi = {}
        for spid, h in hierarchy_info.items():
            hi = h
            break

        # Детализация лекций: classroom, date, teacher, listeners
        lecture_details = []
        for lid in lec_ids:
            li = lecture_info.get(lid, {})
            scheds = schedule_by_lecture.get(lid, [])
            gids_for_lecture = lecture_group_ids.get(lid, set())
            listeners = sum(
                group_data.get(gid, {}).get("student_count", 0)
                for gid in gids_for_lecture
            )
            for sch in scheds:
                lecture_details.append({
                    "lecture_id": lid,
                    "title": li.get("title", ""),
                    "type": li.get("type", ""),
                    "computer_type": li.get("computer_type", ""),
                    "tags": li.get("tags", []),
                    "classroom": sch["classroom"],
                    "date": sch["date"],
                    "time": f"{sch['start_time']}-{sch['end_time']}",
                    "teacher": sch["teacher"],
                    "listeners": listeners
                })

        # max_listeners — максимальное кол-во слушателей (определяет объём аудитории)
        max_listeners = max((l["listeners"] for l in lecture_details), default=0)

        # Информация о группах: студенты из Neo4j (первые 10)
        groups_info = []
        for gid in course_groups.get(cid, set()):
            gd = group_data.get(gid, {})
            groups_info.append({
                "id": gid,
                "name": gd.get("name", ""),
                "student_count": gd.get("student_count", 0),
                "students": gd.get("students_sample", [])
            })

        # Иерархия из Neo4j: University→Institute→Department→Speciality
        spec_id = ""
        for lid in lec_ids:
            for spid, h in hierarchy_info.items():
                hi = h
                spec_id = spid
                break
            if spec_id:
                break

        final_results.append({
            "course": {
                "id": cid,
                "name": ci.get("name", ""),
                "semester": ci.get("semester", 0),
                "total_hours": ci.get("total_hours", 0),
                "lecture_hours": ci.get("lecture_hours", 0),
                "practice_hours": ci.get("practice_hours", 0),
                "lab_hours": ci.get("lab_hours", 0),
                "description": ci.get("description", "")
            },
            "groups": groups_info,
            "lectures": lecture_details,
            "total_listeners": sum(
                group_data.get(gid, {}).get("student_count", 0)
                for gid in course_groups.get(cid, set())
            ),
            "max_listeners_per_lecture": max_listeners,
            "required_classroom_capacity": max_listeners,
            "hierarchy": hi
        })

    elapsed = round(time.time() - start, 3)

    return {
        "result": final_results,
        "steps": steps,
        "query_path": "Neo4j",
        "execution_time_sec": elapsed,
        "justification": {
            "Neo4j": "Один Cypher-запрос: фильтрация + обход графа (Lecture→Course→Schedule→Group→Student) + иерархия (Course→Speciality→Department→Institute→University) + collect()/size() вместо 4 JOIN в PG + Redis pipeline + MongoDB findOne"
        }
    }


@app.get("/")
def root():
    return {"service": "lab2", "description": "Schedule capacity: Neo4j"}
