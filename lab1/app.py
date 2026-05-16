"""
Lab1 Service — 10 студентов с минимальным % посещения лекций, содержащих термин

Задание ЛР1:
  Выполнить запрос для извлечения отчёта о 10 студентах с минимальным процентом
  посещения лекций, содержащих заданный термин или фразу, за определённый период.
  Состав полей: полная информация о студенте, процент посещения, период отчёта,
  термин в занятиях курса.

Путь запроса: Elasticsearch → Neo4j → Redis

Шаг 1 — Elasticsearch:
  Полнотекстовый поиск по индексу "lectures" (BM25 + fuzziness AUTO + russian_custom).
  Ищем термин в полях title, annotation, content_text.
  Результат: список lecture_id, которые содержат термин.

Шаг 2 — Neo4j:
  Обход графа: находим Schedule для лекций из ES в заданном периоде,
  затем для каждого студента считаем:
  - total_scheduled = кол-во SHOULD_ATTEND связей к matching schedules
  - total_attended  = кол-во ATTENDED связей к matching schedules
  - attendance_pct  = total_attended / total_scheduled * 100
  Сортировка по attendance_pct ASC, LIMIT 10.
  Все свойства студента берём из узла Neo4j (не из PostgreSQL).

Шаг 3 — Redis:
  Pipeline HGETALL student:{id} для топ-10 студентов.
  При промахе кэша — заполняем из данных Neo4j через pipeline (cache-aside).
"""
from fastapi import FastAPI, Query, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from elasticsearch import Elasticsearch
from neo4j import GraphDatabase
import redis
import jwt
import os
import logging
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Lab 1 - Attendance Flow")

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

ES_HOST = os.environ.get("ES_HOST", "elasticsearch")
ES_PORT = int(os.environ.get("ES_PORT", 9200))
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASSWORD", "password12345")
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))


def get_es():
    return Elasticsearch(f"http://{ES_HOST}:{ES_PORT}")


def get_neo4j():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


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
    # BM25-ранжирование + fuzziness=AUTO + анализатор russian_custom
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
        return {"result": [], "steps": steps, "query_path": "ES → Neo4j → Redis",
                "execution_time_sec": round(time.time() - start, 3)}

    # --- Шаг 2: Neo4j — обход графа для вычисления топ-10 по минимальному % посещения ---
    # Цепочка: Student-[SHOULD_ATTEND]->Schedule-[PART_OF]->Lecture
    # Дополнительно: Student-[ATTENDED]->Schedule для фактических посещений
    # Фильтр по lecture_ids (из ES) и week_start_date (период)
    logger.info(f"Step 2: Neo4j - attendance graph for {len(lecture_ids)} lectures")
    driver = get_neo4j()

    with driver.session() as session:
        result = session.run("""
            MATCH (l:Lecture)
            WHERE l.id IN $lecture_ids
            MATCH (sch:Schedule)-[:PART_OF]->(l)
            WHERE sch.week_start_date >= $start_date AND sch.week_start_date <= $end_date
            WITH collect(DISTINCT sch) AS matching_schedules

            UNWIND matching_schedules AS msch
            MATCH (st:Student)-[:SHOULD_ATTEND]->(msch)
            WITH st, count(DISTINCT msch) AS total_scheduled, matching_schedules

            OPTIONAL MATCH (st)-[:ATTENDED]->(asch)
            WHERE asch IN matching_schedules
            WITH st, total_scheduled, count(DISTINCT asch) AS total_attended
            WHERE total_scheduled > 0

            RETURN st.id AS student_id, st.first_name AS first_name, st.last_name AS last_name,
                   st.patronymic AS patronymic, st.email AS email,
                   st.student_card_number AS student_card_number, st.status AS status,
                   st.enrollment_date AS enrollment_date, st.group_id AS group_id,
                   total_scheduled, total_attended,
                   toFloat(total_attended) / total_scheduled * 100 AS attendance_pct
            ORDER BY attendance_pct ASC, total_attended ASC
            LIMIT 10
        """, lecture_ids=lecture_ids, start_date=start_date, end_date=end_date)

        top10 = [dict(record) for record in result]

    driver.close()

    steps.append({
        "step": 2,
        "store": "Neo4j",
        "action": "Обход графа: Schedule-[PART_OF]->Lecture (фильтр по lecture_ids + период), SHOULD_ATTEND (total_scheduled), ATTENDED (total_attended) — ORDER BY attendance_pct ASC LIMIT 10",
        "result": f"Топ-10 студентов с минимальным % посещения (вычислено в графе, без SQL CTE)"
    })

    results = []
    for row in top10:
        sid = str(row["student_id"])
        gid = str(row["group_id"])
        pct = round(float(row["attendance_pct"]), 2)

        results.append({
            "student": {
                "id": sid,
                "first_name": row["first_name"],
                "last_name": row["last_name"],
                "patronymic": row["patronymic"] or "",
                "email": row["email"],
                "student_card_number": row["student_card_number"],
                "status": row["status"],
                "enrollment_date": row["enrollment_date"]
            },
            "group_id": gid,
            "attendance_pct": pct,
            "total_scheduled": row["total_scheduled"],
            "total_attended": row["total_attended"],
            "period": {"start_date": start_date, "end_date": end_date},
            "term_in_course": {
                "course_name": "",
                "lecture_title": "",
                "tags": []
            }
        })

    if not results:
        return {"result": [], "steps": steps, "query_path": "ES → Neo4j → Redis",
                "execution_time_sec": round(time.time() - start, 3)}

    # --- Шаг 3: Redis — cache-aside для данных студентов топ-10 ---
    # Паттерн cache-aside: сначала проверяем кэш, при промахе — заполняем из данных Neo4j.
    # Pipeline: группируем несколько команд в один Round-Trip.
    logger.info(f"Step 3: Redis - pipeline for {len(results)} students")
    r = get_redis()
    pipe = r.pipeline()
    for ri in results:
        pipe.hgetall(f"student:{ri['student']['id']}")
    cached_results = pipe.execute()

    cache_hits = 0
    cache_misses = 0
    fill_pipe = r.pipeline()
    for ri, cached in zip(results, cached_results):
        if cached:
            cache_hits += 1
        else:
            cache_misses += 1
            s = ri["student"]
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
            fill_pipe.expire(f"student:{s['id']}", 7200)
    if cache_misses:
        fill_pipe.execute()

    steps.append({
        "step": 3,
        "store": "Redis",
        "action": f"Pipeline HGETALL student:{{id}} для топ-10 (Hash, TTL=2ч). Попаданий: {cache_hits}, промахов: {cache_misses} (пополнение из данных Neo4j)",
        "result": f"Кэш проверен/пополнен для {len(results)} студентов"
    })

    elapsed = round(time.time() - start, 3)

    return {
        "result": results,
        "steps": steps,
        "query_path": "ES → Neo4j → Redis",
        "execution_time_sec": elapsed,
        "justification": {
            "Elasticsearch": "Полнотекстовый поиск (BM25, fuzziness, russian_custom) — эффективнее LIKE в PostgreSQL",
            "Neo4j": "Обход графа: SHOULD_ATTEND + ATTENDED — вычисление attendance_pct без CTE MATERIALIZED, граф естественным образом хранит связи студент↔расписание↔лекция",
            "Redis": "O(1) pipeline HGETALL student:{id} для 10 студентов — кэш-проверка вместо повторного обхода графа"
        }
    }


@app.get("/")
def root():
    return {"service": "lab1", "description": "Attendance flow: ES → Neo4j → Redis"}
