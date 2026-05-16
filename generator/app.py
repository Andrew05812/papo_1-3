"""
Модуль app.py — тонкий FastAPI-фасад для сервиса генерации тестовых данных.

Генератор заполняет все 5 баз данных (PostgreSQL, Elasticsearch, Neo4j, Redis,
MongoDB) напрямую, без использования Kafka или CDC. Каждый эндпоинт делегирует
вызов в модуль generator.py, где сосредоточена вся бизнес-логика.
"""
from fastapi import FastAPI
import generator

app = FastAPI(title="Data Generator Service")

# POST /generate — создаёт тестовые данные во всех 5 хранилищах
@app.post("/generate")
def generate_data():
    return generator.generate_data()

# DELETE /clear — полностью очищает все хранилища (PG, ES, Neo4j, Redis, Mongo)
@app.delete("/clear")
def clear_data():
    return generator.clear_all_stores()

# GET /status — проверяет наличие данных (ready/empty) по числу студентов в PG
@app.get("/status")
def get_status():
    return generator.get_status()

# GET /groups — возвращает список групп для выпадающего списка в Lab3
@app.get("/groups")
def list_groups():
    return generator.list_groups()

# GET / — health-check, возвращает имя и описание сервиса
@app.get("/")
def root():
    return {"service": "generator", "description": "Data generation service"}
