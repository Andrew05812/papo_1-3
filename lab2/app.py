"""
Lab2 Service — необходимый объём аудитории для курса по семестру и году

Задание ЛР2:
  Выполнить запрос для извлечения отчёта о необходимом объёме аудитории для
  проведения занятий по курсу заданного семестра и года обучения с требованиями
  к использованию технических средств.
  Результат: полная информация о курсе, лекции и количестве слушателей.

Путь запроса: PostgreSQL → Neo4j → Redis → MongoDB

Шаг 1 — PostgreSQL:
  Фильтрация лекций по семестру и требованиям к оборудованию.
  Batch-запрос расписания по году, COUNT студентов в группах.

Шаг 2 — Neo4j:
  Обход графа: Lecture-[BELONGS_TO]->Course, Lecture<-[PART_OF]-Schedule<-[CONTAINS]-Group.
  Сужаем множество групп для Redis (не все группы, а только из расписания).

Шаг 3 — Redis:
  Pipeline HGETALL student:{id} — только для студентов из Neo4j-групп.
  При промахе — fallback к PostgreSQL, заполнение кэша.

Шаг 4 — MongoDB:
  findOne: University→Institutes→Departments→Specialities — один запрос вместо 4 JOIN.
"""
from fastapi import FastAPI, Query, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from neo4j import GraphDatabase
import psycopg2
import redis
from pymongo import MongoClient
import jwt
import os
import logging
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Lab 2 - Schedule Capacity")

JWT_SECRET = os.environ.get("JWT_SECRET", "polyglot_jwt_secret_key_2026")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
security = HTTPBearer()


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

PG_HOST = os.environ.get("POSTGRES_HOST", "postgres")
PG_PORT = int(os.environ.get("POSTGRES_PORT", 5432))
PG_DB = os.environ.get("POSTGRES_DB", "university")
PG_USER = os.environ.get("POSTGRES_USER", "postgres")
PG_PASS = os.environ.get("POSTGRES_PASSWORD", "postgres")
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASSWORD", "password12345")
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
MONGO_HOST = os.environ.get("MONGO_HOST", "mongodb")
MONGO_PORT = int(os.environ.get("MONGO_PORT", 27017))
MONGO_USER = os.environ.get("MONGO_USER", "mongo")
MONGO_PASS = os.environ.get("MONGO_PASSWORD", "password12345")
MONGO_DB = os.environ.get("MONGO_DB", "university")


def get_pg():
    return psycopg2.connect(host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASS)


def get_neo4j():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


def get_mongo():
    return MongoClient(host=MONGO_HOST, port=MONGO_PORT, username=MONGO_USER, password=MONGO_PASS)


@app.get("/query")
def query_schedule_capacity(
    semester: int = Query(..., description="Номер семестра (1-8)"),
    year: int = Query(..., description="Год обучения"),
    equipment: str = Query("", description="Требования к оборудованию"),
    _=Depends(verify_service_token)
):
    steps = []
    start = time.time()

    # ===== ШАГ 1: PostgreSQL =====
    # 1a) Фильтрация лекций: только типа «лекция» для заданного семестра;
    #     если указано оборудование — фильтр по equipment_req ILIKE или tags.
    #     JOIN lecture_course даёт информацию о курсе и speciality_id для MongoDB.
    logger.info(f"Step 1: PG - semester={semester}, year={year}, equipment='{equipment}'")
    pg = get_pg()
    cur = pg.cursor()

    query = """
        SELECT l.id, l.title, l.lecture_type, l.equipment_req, l.tags,
               lc.id as course_id, lc.name as course_name, lc.semester,
               lc.total_hours, lc.lecture_hours, lc.practice_hours, lc.lab_hours,
               lc.description, lc.speciality_id
        FROM lecture l
        JOIN lecture_course lc ON l.course_id = lc.id
        WHERE lc.semester = %s
          AND l.lecture_type = 'лекция'
    """
    params = [semester]

    if equipment:
        query += " AND (l.equipment_req ILIKE %s OR %s = ANY(l.tags))"
        params.extend([f"%{equipment}%", equipment])

    cur.execute(query, params)
    lecture_rows = cur.fetchall()

    lecture_ids = [str(r[0]) for r in lecture_rows]
    lecture_info = {}
    course_info = {}
    for r in lecture_rows:
        lid = str(r[0])
        cid = str(r[5])
        lecture_info[lid] = {
            "title": r[1],
            "type": r[2],
            "equipment_req": r[3] or "",
            "tags": r[4] or [],
            "course_id": cid
        }
        if cid not in course_info:
            course_info[cid] = {
                "name": r[6],
                "semester": r[7],
                "total_hours": r[8],
                "lecture_hours": r[9],
                "practice_hours": r[10],
                "lab_hours": r[11],
                "description": r[12] or "",
                "speciality_id": str(r[13])
            }

    # 1b) Batch-запрос расписания: записи за указанный год для лекций из шага 1a
    year_start = f"{year}-01-01"
    year_end = f"{year}-12-31"
    cur.execute("""
        SELECT id, lecture_id, group_id, classroom, scheduled_date, start_time, end_time, teacher_name
        FROM schedule
        WHERE lecture_id = ANY(%s::uuid[])
          AND scheduled_date BETWEEN %s AND %s
        ORDER BY scheduled_date
    """, (lecture_ids, year_start, year_end))
    schedule_rows = cur.fetchall()

    schedule_by_lecture = {}
    all_group_ids = set()
    for sr in schedule_rows:
        lid = str(sr[1])
        gid = str(sr[2])
        all_group_ids.add(gid)
        schedule_by_lecture.setdefault(lid, []).append({
            "schedule_id": str(sr[0]),
            "group_id": gid,
            "classroom": sr[3],
            "date": str(sr[4]),
            "time": f"{sr[5]}-{sr[6]}",
            "teacher": sr[7]
        })

    # 1c) COUNT студентов в каждой группе
    group_ids_list = list(all_group_ids)
    cur.execute("""
        SELECT sg.id, sg.name, COUNT(s.id) as student_count
        FROM student_group sg
        JOIN student s ON s.group_id = sg.id
        WHERE sg.id = ANY(%s::uuid[])
        GROUP BY sg.id, sg.name
    """, (group_ids_list,))
    group_student_counts = {str(r[0]): {"name": r[1], "count": r[2]} for r in cur.fetchall()}

    cur.close()
    pg.close()

    steps.append({
        "step": 1,
        "store": "PostgreSQL",
        "action": f"Batch: lecture filter (semester={semester}, equipment='{equipment}'), schedule by year={year}, GROUP BY student count",
        "result": f"Найдено {len(lecture_ids)} лекций, {len(schedule_rows)} расписаний за {year} год"
    })

    if not lecture_ids:
        return {"result": [], "steps": steps, "query_path": "PostgreSQL → Neo4j → Redis → MongoDB",
                "execution_time_sec": round(time.time() - start, 3)}

    # ===== ШАГ 2: Neo4j =====
    # Обход графа: Lecture-[BELONGS_TO]->Course, Lecture<-[PART_OF]-Schedule<-[CONTAINS]-Group.
    # Сужаем множество групп (не все из PG, а только привязанные через расписание).
    logger.info(f"Step 2: Neo4j - graph traversal for {len(lecture_ids)} lectures")
    driver = get_neo4j()
    course_lecture_map = {}
    neo_group_ids = set()

    with driver.session() as session:
        result = session.run("""
            MATCH (l:Lecture)
            WHERE l.id IN $lecture_ids
            MATCH (l)-[:BELONGS_TO]->(c:LectureCourse)
            MATCH (l)<-[:PART_OF]-(sch:Schedule)
            MATCH (sch)<-[:CONTAINS]-(g:StudentGroup)
            RETURN DISTINCT l.id AS lecture_id, c.id AS course_id, c.name AS course_name,
                   g.id AS group_id, g.name AS group_name, sch.id AS schedule_id
        """, lecture_ids=lecture_ids)

        for record in result:
            lid = record["lecture_id"]
            gid = record["group_id"]
            cid = record["course_id"]
            neo_group_ids.add(gid)

            if cid not in course_lecture_map:
                course_lecture_map[cid] = {
                    "name": record["course_name"],
                    "lecture_ids": set(),
                    "group_ids": set(),
                    "schedule_ids": set()
                }
            course_lecture_map[cid]["lecture_ids"].add(lid)
            course_lecture_map[cid]["group_ids"].add(gid)
            course_lecture_map[cid]["schedule_ids"].add(record["schedule_id"])

    driver.close()

    steps.append({
        "step": 2,
        "store": "Neo4j",
        "action": "Обход графа: Lecture-[BELONGS_TO]->Course, Lecture<-[PART_OF]-Schedule<-[CONTAINS]-Group — O(E) по индексу",
        "result": f"Найдено {len(neo_group_ids)} групп, {len(course_lecture_map)} курсов (сужение области для Redis)"
    })

    if not course_lecture_map:
        return {"result": [], "steps": steps, "query_path": "PostgreSQL → Neo4j → Redis → MongoDB",
                "execution_time_sec": round(time.time() - start, 3)}

    # ===== ШАГ 3: Redis =====
    # Запрашиваем данные студентов ТОЛЬКО для групп из Neo4j (не всех!).
    # Cache-aside: pipeline HGETALL, при промахе — fallback к PG.
    neo_group_ids_list = list(neo_group_ids)

    logger.info(f"Step 3: Redis - pipeline for {len(neo_group_ids_list)} groups only")
    r = get_redis()

    pg = get_pg()
    cur = pg.cursor()
    cur.execute("SELECT id FROM student WHERE group_id = ANY(%s::uuid[])", (neo_group_ids_list,))
    relevant_student_ids = [str(r[0]) for r in cur.fetchall()]
    cur.close()
    pg.close()

    student_details = {}
    cache_hits = 0
    cache_misses = []

    BATCH_SIZE = 2000
    for i in range(0, len(relevant_student_ids), BATCH_SIZE):
        batch = relevant_student_ids[i:i + BATCH_SIZE]
        pipe = r.pipeline()
        for sid in batch:
            pipe.hgetall(f"student:{sid}")
        cached_batch = pipe.execute()

        for idx, sid in enumerate(batch):
            data = cached_batch[idx]
            if data:
                student_details[sid] = data
                cache_hits += 1
            else:
                cache_misses.append(sid)

    # Fallback к PostgreSQL при промахах кэша
    if cache_misses:
        pg = get_pg()
        cur = pg.cursor()
        for j in range(0, len(cache_misses), 5000):
            chunk = cache_misses[j:j + 5000]
            cur.execute("""
                SELECT id, first_name, last_name, patronymic, email, student_card_number,
                       group_id, status, enrollment_date
                FROM student WHERE id = ANY(%s::uuid[])
            """, (chunk,))
            pipe = r.pipeline()
            for row in cur.fetchall():
                sid = str(row[0])
                details = {
                    "first_name": row[1],
                    "last_name": row[2],
                    "patronymic": row[3] or "",
                    "email": row[4],
                    "student_card_number": row[5],
                    "group_id": str(row[6]),
                    "status": row[7],
                    "enrollment_date": str(row[8])
                }
                student_details[sid] = details
                pipe.hset(f"student:{sid}", mapping=details)
                pipe.expire(f"student:{sid}", 7200)
            pipe.execute()
        cur.close()
        pg.close()

    students_by_group = {}
    for sid, sd in student_details.items():
        gid = sd.get("group_id", "")
        students_by_group.setdefault(gid, []).append({
            "id": sid,
            "first_name": sd.get("first_name", ""),
            "last_name": sd.get("last_name", ""),
            "patronymic": sd.get("patronymic", ""),
            "student_card_number": sd.get("student_card_number", "")
        })

    steps.append({
        "step": 3,
        "store": "Redis",
        "action": f"Pipeline HGETALL student:{{id}} (Hash, TTL=2ч) для {len(relevant_student_ids)} студентов из {len(neo_group_ids_list)} групп Neo4j. Попаданий: {cache_hits}, промахов: {len(cache_misses)} (fallback → PG)",
        "result": f"Получены данные {len(student_details)} студентов (сужено Neo4j)"
    })

    # ===== ШАГ 4: MongoDB =====
    # Чтение вложенного документа иерархии: University→Institutes→Departments→Specialities.
    # findOne — O(1) вместо 4 JOIN в PostgreSQL.
    logger.info("Step 4: MongoDB - university hierarchy")
    client = get_mongo()
    db = client[MONGO_DB]
    hierarchy_doc = db["hierarchy"].find_one()
    client.close()

    hierarchy_info = {}
    if hierarchy_doc:
        for inst in hierarchy_doc.get("institutes", []):
            for dept in inst.get("departments", []):
                for spec in dept.get("specialities", []):
                    hierarchy_info[spec["id"]] = {
                        "university": hierarchy_doc.get("name", ""),
                        "institute": inst.get("name", ""),
                        "department": dept.get("name", ""),
                        "speciality": spec.get("name", ""),
                        "speciality_code": spec.get("code", "")
                    }

    steps.append({
        "step": 4,
        "store": "MongoDB",
        "action": "Чтение вложенного документа University→Institutes→Departments→Specialities — O(1) findOne вместо 4 JOIN",
        "result": f"Загружена иерархия ({len(hierarchy_info)} специальностей)"
    })

    # ===== ФИНАЛЬНАЯ СБОРКА =====
    final_results = []
    for cid, cdata in course_lecture_map.items():
        ci = course_info.get(cid, {})
        spec_id = ci.get("speciality_id", "")
        hi = hierarchy_info.get(spec_id, {})

        lecture_details = []
        for lid in cdata["lecture_ids"]:
            li = lecture_info.get(lid, {})
            scheds = schedule_by_lecture.get(lid, [])
            lecture_group_ids = set(sch["group_id"] for sch in scheds)
            listeners = sum(
                group_student_counts.get(str(gid), {}).get("count", 0)
                for gid in lecture_group_ids
            )
            for sch in scheds:
                lecture_details.append({
                    "lecture_id": lid,
                    "title": li.get("title", ""),
                    "type": li.get("type", ""),
                    "equipment_req": li.get("equipment_req", ""),
                    "tags": li.get("tags", []),
                    "classroom": sch["classroom"],
                    "date": sch["date"],
                    "time": sch["time"],
                    "teacher": sch["teacher"],
                    "listeners": listeners
                })

        max_listeners = max((l["listeners"] for l in lecture_details), default=0)

        groups_info = []
        for gid in cdata["group_ids"]:
            gname = group_student_counts.get(str(gid), {}).get("name", "")
            gstudents = students_by_group.get(str(gid), [])
            groups_info.append({
                "id": gid,
                "name": gname,
                "student_count": len(gstudents),
                "students": gstudents[:10]
            })

        final_results.append({
            "course": {
                "id": cid,
                "name": ci.get("name", cdata.get("name", "")),
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
                group_student_counts.get(str(gid), {}).get("count", 0)
                for gid in cdata["group_ids"]
            ),
            "max_listeners_per_lecture": max_listeners,
            "required_classroom_capacity": max_listeners,
            "hierarchy": hi
        })

    elapsed = round(time.time() - start, 3)

    return {
        "result": final_results,
        "steps": steps,
        "query_path": "PostgreSQL → Neo4j → Redis → MongoDB",
        "execution_time_sec": elapsed,
        "justification": {
            "PostgreSQL": "Batch-агрегация: schedule по году + COUNT студентов + фильтр оборудования — composite index (lecture_id, week_start_date)",
            "Neo4j": "Обход графа Lecture→Course и Lecture←Schedule←Group — O(E) по индексу + сужение групп для Redis",
            "Redis": "Pipeline O(1) HGETALL student:{id} — только для групп из Neo4j (не всех!), batch 2000 + fallback PG",
            "MongoDB": "Вложенный документ иерархии университета — O(1) findOne вместо 4 JOIN"
        }
    }


@app.get("/")
def root():
    return {"service": "lab2", "description": "Schedule capacity: PostgreSQL → Neo4j → Redis → MongoDB"}
