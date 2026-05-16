"""
API Gateway - klient container

Role: single entry point for user.
1. User authenticates via OAuth2 (simplified scheme - token issued directly)
2. To call lab services, the gateway:
   a) verifies user JWT
   b) creates service JWT (type=service) for authorization inside labs
   c) sends HTTPS request to nginx with client certificate (mTLS)
3. Nginx verifies client cert and proxies request to lab container
4. Lab service verifies service JWT and executes query to its DBs

Request path:
  User -> [HTTP] -> API Gateway -> [HTTPS + client cert] -> Nginx -> [HTTP] -> Lab Service -> DBs
"""
# FastAPI — веб-фреймворк для создания REST API с автогенерацией OpenAPI-документации
# HTTPException — выброс HTTP-ошибок (401, 400 и т.д.) с деталями
# Depends — механизм внедрения зависимостей (DI), используется для проверки токена
# Request — объект HTTP-запроса, нужен для чтения тела запроса в произвольном формате
from fastapi import FastAPI, HTTPException, Depends, Request
# HTMLResponse — возврат HTML-страницы (веб-интерфейс gateway)
# JSONResponse — возврат JSON-ответа с явным указанием типа
from fastapi.responses import HTMLResponse, JSONResponse
# HTTPBearer — схема безопасности: ожидает заголовок Authorization: Bearer <token>
# HTTPAuthorizationCredentials — объект с полем .credentials (сам JWT-токен)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# OAuth2PasswordRequestForm — стандартная форма OAuth2 (grant_type, username, password)
# используется для эндпоинта /auth/token по спецификации OAuth2 RFC 6749
from fastapi.security import OAuth2PasswordRequestForm
# BaseModel — базовый класс Pydantic для валидации и сериализации данных запросов/ответов
from pydantic import BaseModel
# jwt (PyJWT) — библиотека для создания и проверки JWT-токенов (HS256 подпись)
import jwt
# httpx — асинхронный HTTP-клиент для запросов к nginx (mTLS) и generator
import httpx
# ssl — модуль для создания SSL-контекста с клиентским сертификатом (mTLS)
import ssl
# os — чтение переменных окружения (JWT_SECRET, пути к сертификатам, URL-адреса)
import os
# logging — логирование событий (INFO-уровень) для отладки и мониторинга
import logging
# datetime, timedelta — работа с временем: iat (выдача) и exp (срок действия) JWT
from datetime import datetime, timedelta
# quote — URL-кодирование кириллицы и спецсимволов в параметрах запроса
from urllib.parse import quote

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="API Gateway - OAuth2 + mTLS", docs_url="/docs")

# Упрощённая схема OAuth2: токен выдаётся напрямую пользователю без авторизационного кода.
# JWT_SECRET — общий секрет для подписи всех JWT (HS256). В продакшене берётся из окружения,
# здесь — фиксированный ключ для демонстрации.
# Два типа токенов:
#   password grant → type=user, TTL=24ч — для людей (браузер, curl)
#   client_credentials grant → type=service, TTL=1ч — для сервисных клиентов (lab1/2/3)
JWT_SECRET = os.environ.get("JWT_SECRET", "polyglot_jwt_secret_key_2026")
# JWT_ALGORITHM — алгоритм симметричной подписи HMAC-SHA256
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")

# NGINX_URL — адрес nginx-прокси внутри Docker-сети.
# Gateway общается с nginx по HTTPS с клиентским сертификатом (mTLS).
# Nginx проверяет client.crt (ssl_verify_client on) и проксирует запрос
# к соответствующему лаб-контейнеру по обычному HTTP внутри Docker-сети.
NGINX_URL = os.environ.get("NGINX_URL", "https://nginx:443")
# GENERATOR_URL — адрес генератора данных (внутренний HTTP, mTLS не нужен,
# т.к. генератор находится в той же Docker-сети и не принимает внешние запросы)
GENERATOR_URL = os.environ.get("GENERATOR_URL", "http://generator:8010")

# Пути к сертификатам для mTLS (примонтированы из генератора сертификатов):
# CERT_CA — корневой CA-сертификат (ca.crt), которым проверяется подлинность
#   серверного сертификата nginx (server.crt). Убедиться, что nginx — тот, за кого себя выдаёт.
# CERT_CLIENT_CRT — клиентский сертификат gateway (client.crt), подписан тем же CA.
#   Nginx проверяет его при ssl_verify_client on — подтверждает, что запрос от доверенного клиента.
# CERT_CLIENT_KEY — закрытый ключ gateway (client.key), используется для TLS-handshake
#   при установке зашифрованного канала с nginx.
CERT_CA = os.environ.get("CERT_CA", "/certs/ca.crt")
CERT_CLIENT_CRT = os.environ.get("CERT_CLIENT_CRT", "/certs/client.crt")
CERT_CLIENT_KEY = os.environ.get("CERT_CLIENT_KEY", "/certs/client.key")

# Предустановленные тестовые пользователи для демонстрации OAuth2 password grant.
# В реальной системе заменяются на БД пользователей + хеши паролей (bcrypt/argon2).
#   admin — администратор, полный доступ
#   demo — демо-пользователь для демонстрации
#   test — тестовый пользователь для проверки
HARDCODED_USERS = {
    "admin": "admin123",
    "demo": "demo123",
    "test": "test123",
}

# Сервисные клиенты для OAuth2 client_credentials grant (RFC 6749 §4.4).
# Каждая лаборатория может самостоятельно получить service-токен, предъявив
# свой client_id и client_secret. Полученный токен содержит type=service,
# что позволяет лабам обращаться к другим лабам без участия пользователя.
#   lab1-service — клиент ЛР1 (ES + PG + Redis)
#   lab2-service — клиент ЛР2 (PG + Neo4j + Redis + MongoDB)
#   lab3-service — клиент ЛР3 (ES + Neo4j + PG)
SERVICE_CLIENTS = {
    "lab1-service": "lab1-secret",
    "lab2-service": "lab2-secret",
    "lab3-service": "lab3-secret",
}

# Экземпляр схемы Bearer — FastAPI будет автоматически извлекать токен
# из заголовка Authorization: Bearer <token> и передавать в Depends()
security = HTTPBearer()


# Создание JWT-токена с заданными параметрами.
# Структура payload (полезная нагрузка токена):
#   sub — субъект токена: имя пользователя (для type=user) или client_id (для type=service)
#   type — тип токена: "user" (пользовательский, 24ч) или "service" (сервисный, 1ч)
#   iat — issued at: время выдачи токена (для аудита и проверки свежести)
#   exp — expiration: срок действия, после которого токен считается недействительным
# Токен подписан алгоритмом HS256 с общим секретом JWT_SECRET.
def create_jwt_token(sub: str, token_type: str = "user", ttl_hours: int = 24) -> str:
    payload = {
        "sub": sub,
        "type": token_type,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=ttl_hours),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


# Создание сервисного JWT-токена (type=service), который gateway отправляет
# в лаб-контейнер через nginx. Лаборатория проверяет, что type=service
# (не "user"!), — это гарантирует, что запрос пришёл от доверенного gateway,
# а не напрямую от пользователя. TTL=1ч, sub="gateway" — идентификатор эмитента.
def create_service_token() -> str:
    return create_jwt_token("gateway", token_type="service", ttl_hours=1)


# Проверка пользовательского JWT-токена для защиты API-эндпоинтов.
# FastAPI автоматически извлекает токен из заголовка Authorization через Depends(security).
# Если токен просрочен (ExpiredSignatureError) или невалиден (InvalidTokenError) — 401.
# Возвращает раскодированный payload (dict) для дальнейшего использования.
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Создание SSL-контекста для взаимной аутентификации (mTLS):
# 1. ssl.create_default_context(cafile=CERT_CA) — загружает CA-сертификат для
#    проверки серверного сертификата nginx (убедиться, что nginx подписан доверенным CA)
# 2. load_cert_chain — загружает клиентский сертификат и закрытый ключ gateway;
#    nginx проверит этот сертификат при ssl_verify_client on
# 3. check_hostname=False — отключает проверку CN/hostname (в Docker-сети имя "nginx"
#    может не совпадать с CN в сертификате)
# 4. verify_mode=CERT_REQUIRED — строгая проверка: соединение разорвётся,
#    если серверный сертификат не подписан доверенным CA
def get_mtls_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=CERT_CA)
    ctx.load_cert_chain(certfile=CERT_CLIENT_CRT, keyfile=CERT_CLIENT_KEY)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


# Создание асинхронного HTTP-клиента с mTLS-контекстом для запросов к nginx.
# Таймаут 120с — лабораторные запросы могут быть длительными (несколько БД).
# Если mTLS-контекст не удалось создать (нет сертификатов), fallback на verify=False
# (только для разработки! в продакшене сертификаты обязательны)
def get_httpx_client() -> httpx.AsyncClient:
    try:
        ssl_ctx = get_mtls_ssl_context()
        return httpx.AsyncClient(verify=ssl_ctx, timeout=httpx.Timeout(120.0))
    except Exception as e:
        logger.warning(f"mTLS context failed, falling back to default: {e}")
        return httpx.AsyncClient(verify=False, timeout=httpx.Timeout(120.0))


# Эндпоинт выдачи JWT-токена по спецификации OAuth2 (RFC 6749).
# Поддерживает два типа грантов (grant_type):
# 1. "password" — для пользователей: проверяет логин/пароль из HARDCODED_USERS,
#    выдаёт type=user токен с TTL=24ч. Пользователь затем передаёт его
#    в Authorization: Bearer при каждом запросе к API.
# 2. "client_credentials" — для сервисных клиентов: проверяет client_id/client_secret
#    из SERVICE_CLIENTS, выдаёт type=service токен с TTL=1ч.
#    Используется лабораториями для межсервисного взаимодействия.
@app.post("/auth/token")
async def auth_token(form: OAuth2PasswordRequestForm = Depends()):
    grant_type = form.grant_type

    if grant_type == "password":
        username = form.username
        password = form.password
        if username not in HARDCODED_USERS or HARDCODED_USERS[username] != password:
            raise HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Bearer"})
        token = create_jwt_token(username, token_type="user", ttl_hours=24)
        return {"access_token": token, "token_type": "Bearer", "expires_in": 86400}

    elif grant_type == "client_credentials":
        client_id = form.username
        client_secret = form.password
        if client_id not in SERVICE_CLIENTS or SERVICE_CLIENTS[client_id] != client_secret:
            raise HTTPException(status_code=401, detail="Invalid client credentials", headers={"WWW-Authenticate": "Bearer"})
        token = create_jwt_token(client_id, token_type="service", ttl_hours=1)
        return {"access_token": token, "token_type": "Bearer", "expires_in": 3600}

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported grant_type: {grant_type}")


# Альтернативный эндпоинт авторизации — принимает JSON {username, password}
# вместо стандартной OAuth2-формы. Удобен для веб-интерфейса (fetch POST с JSON-body).
# Выдаёт тот же type=user токен, что и /auth/token с grant_type=password.
@app.post("/auth/login")
async def auth_login_legacy(request: Request):
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")
    if username not in HARDCODED_USERS or HARDCODED_USERS[username] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_jwt_token(username, token_type="user", ttl_hours=24)
    return {"access_token": token, "token_type": "Bearer", "expires_in": 86400}


# Основная функция проксирования запроса к лаборатории.
# Полный поток:
# 1. Создаёт сервисный JWT-токен (type=service, sub="gateway", TTL=1ч)
# 2. Создаёт httpx-клиент с mTLS-контекстом (клиентский сертификат + проверка сервера)
# 3. Отправляет HTTPS GET-запрос к nginx с параметрами и заголовком Authorization
# 4. Nginx проверяет client.crt (mTLS), снимает SSL, проксирует HTTP-запрос в лаб-контейнер
# 5. Лаб проверяет service JWT и выполняет запрос к своим БД
# 6. Ответ возвращается по обратному пути: лаб → nginx → gateway → пользователь
async def call_lab(path: str, params: dict) -> dict:
    service_token = create_service_token()
    client = get_httpx_client()
    try:
        resp = await client.get(
            f"{NGINX_URL}{path}",
            params=params,
            headers={"Authorization": f"Bearer {service_token}"}
        )
        resp.raise_for_status()
        return resp.json()
    finally:
        await client.aclose()


# Функция проксирования запросов к генератору данных.
# В отличие от call_lab, здесь mTLS не нужен — генератор доступен
# только внутри Docker-сети по обычному HTTP. Таймаут 300с — генерация
# большого объёма данных может занимать несколько минут.
# Поддерживает методы GET (статус, список групп), POST (генерация),
# DELETE (очистка всех хранилищ).
async def call_generator(method: str, path: str, **kwargs) -> dict:
    async with httpx.AsyncClient(timeout=httpx.Timeout(300.0)) as client:
        url = f"{GENERATOR_URL}{path}"
        if method == "GET":
            resp = await client.get(url, **kwargs)
        elif method == "POST":
            resp = await client.post(url, **kwargs)
        elif method == "DELETE":
            resp = await client.delete(url, **kwargs)
        else:
            raise ValueError(f"Unsupported method: {method}")
        resp.raise_for_status()
        return resp.json()


# ЛР1: 10 студентов с минимальным % посещения лекций, содержащих заданный термин, за период.
# Цепочка БД: Elasticsearch (BM25-поиск термина → lecture_ids) →
#   PostgreSQL (CTE MATERIALIZED: top-10 студентов с мин % посещения) →
#   Redis (HGETALL student:{id} — кэш данных студентов, TTL=2ч)
@app.get("/attendance/low")
async def lab1_query(term: str, start_date: str, end_date: str, _=Depends(verify_token)):
    return await call_lab("/lab1/query", {"term": term, "start_date": start_date, "end_date": end_date})


# ЛР2: Необходимый объём аудитории для проведения занятий по курсу заданного семестра/года
# с требованиями к оборудованию. Состав: курс, лекции, количество слушателей, иерархия вуза.
# Цепочка БД: PostgreSQL (фильтрация лекций + COUNT студентов) →
#   Neo4j (обход графа: Lecture→Course, Schedule→Group — сужение множества групп) →
#   Redis (HGETALL student:{id} — только для групп из Neo4j) →
#   MongoDB (findOne: University→Institutes→Departments→Specialities — иерархия вуза)
@app.get("/schedule/capacity")
async def lab2_query(semester: int, year: int, equipment: str = "", _=Depends(verify_token)):
    return await call_lab("/lab2/query", {"semester": semester, "year": year, "equipment": equipment})


# ЛР3: Отчёт по группе — объём прослушанных и запланированных часов лекций
# со спец. тегами дисциплины кафедры. 1 лекция = 2 академических часа.
# Цепочка БД: PostgreSQL (lookup group_id по group_name) →
#   Elasticsearch (фильтрация по спец. тегам: terms query) →
#   Neo4j (обход графа: Student→Group→Schedule→Lecture→Course) →
#   PostgreSQL (batch attendance + lecture_hours + student details)
@app.get("/hours/report")
async def lab3_query(group_name: str, _=Depends(verify_token)):
    return await call_lab("/lab3/query", {"group_name": group_name})


# Проксирование запроса к генератору: заполнение всех 5 БД тестовыми данными.
# Внутренний HTTP-запрос к generator:8010 (mTLS не нужен, Docker-сеть).
# Требует авторизации (verify_token) — только аутентифицированные пользователи
# могут инициировать генерацию данных.
@app.post("/generator/generate")
async def generate_data(_=Depends(verify_token)):
    return await call_generator("POST", "/generate")


# Проксирование запроса к генератору: очистка всех 5 хранилищ (PG, ES, Neo4j, Redis, MongoDB).
# Требует авторизации — предотвращает случайную или несанкционированную очистку данных.
@app.delete("/generator/clear")
async def clear_data(_=Depends(verify_token)):
    return await call_generator("DELETE", "/clear")


# Проксирование запроса к генератору: проверка текущего состояния хранилищ
# (ready / empty / ошибка, количество студентов и курсов).
# НЕ требует авторизации — статус доступен без логина (для индикации в UI).
@app.get("/generator/status")
async def generator_status():
    return await call_generator("GET", "/status")


# Проксирование запроса к генератору: получение списка всех групп из PostgreSQL.
# Требует авторизации — используется для выбора группы в интерфейсе ЛР3.
@app.get("/groups")
async def list_groups(_=Depends(verify_token)):
    return await call_generator("GET", "/groups")


# Веб-интерфейс gateway: отдаёт HTML-страницу с формами авторизации, генерации данных
# и выполнения лабораторных запросов. Не требует авторизации — это статическая страница,
# авторизация происходит при фактических API-вызовах через JavaScript (fetch + Bearer token).
@app.get("/", response_class=HTMLResponse)
def ui_page():
    return HTML_TEMPLATE


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Polyglot Persistence - Система управления учебным процессом</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0b1120;--surface:#131d30;--surface2:#1a2744;--border:#1e3050;--text:#d4dae5;--muted:#6b7fa0;--accent:#3b82f6;--pg:#3b82f6;--es:#ef4444;--neo:#6366f1;--redis:#22c55e;--mongo:#f59e0b}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.container{max-width:1400px;margin:0 auto;padding:16px 24px}

header{text-align:center;padding:20px 0 6px}
header h1{font-size:1.5em;background:linear-gradient(135deg,#60a5fa,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
header .subtitle{color:var(--muted);font-size:0.82em}

.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px 20px;margin-bottom:14px}
.card-header{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.card-header h2{font-size:1em;color:#93c5fd;flex:1}
.card-header .icon{font-size:1.2em}

.row{display:flex;gap:12px;margin-bottom:10px;flex-wrap:wrap;align-items:center}
label{min-width:100px;color:var(--muted);font-size:0.82em;font-weight:500}
input,select{flex:1;min-width:160px;padding:7px 11px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:13px;transition:border .2s}
input:focus,select:focus{border-color:var(--accent);outline:none;box-shadow:0 0 0 3px rgba(59,130,246,.15)}

button{padding:8px 20px;border:none;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600;transition:all .15s;display:inline-flex;align-items:center;gap:5px}
.btn-blue{background:#3b82f6;color:#fff}.btn-blue:hover{background:#2563eb}
.btn-green{background:#16a34a;color:#fff}.btn-green:hover{background:#15803d}
.btn-red{background:#dc2626;color:#fff}.btn-red:hover{background:#b91c1c}
.btn-gray{background:#475569;color:#fff}.btn-gray:hover{background:#334155}

.badge{display:inline-flex;align-items:center;gap:3px;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;font-family:'JetBrains Mono','Consolas',monospace;letter-spacing:.2px}
.badge-pg{background:#1e3a5f;color:#93c5fd;border:1px solid #2563eb}
.badge-es{background:#450a0a;color:#fca5a5;border:1px solid #dc2626}
.badge-neo{background:#1e1b4b;color:#c4b5fd;border:1px solid #6366f1}
.badge-redis{background:#14532d;color:#86efac;border:1px solid #16a34a}
.badge-mongo{background:#451a03;color:#fcd34d;border:1px solid #d97706}
.badge-mtls{background:#312e81;color:#c4b5fd;border:1px solid #6366f1}
.badge-jwt{background:#064e3b;color:#6ee7b7;border:1px solid #059669}
.badge-ok{background:#052e16;color:#4ade80;border:1px solid #166534}
.badge-warn{background:#431407;color:#fb923c;border:1px solid #9a3412}
.badge-err{background:#450a0a;color:#fca5a5;border:1px solid #991b1b}

.arch-diagram{display:flex;flex-direction:column;gap:10px;padding:12px;background:var(--bg);border-radius:8px;border:1px solid var(--border)}
.arch-row{display:flex;align-items:center;gap:0;justify-content:center;flex-wrap:wrap}
.arch-box{padding:8px 14px;border-radius:6px;font-weight:700;font-size:12px;text-align:center;min-width:90px;position:relative;border:2px solid}
.arch-box.gw{background:#1e1b4b;border-color:#6366f1;color:#c4b5fd}
.arch-box.ng{background:#312e81;border-color:#818cf8;color:#c4b5fd}
.arch-box.l1{background:#1e3a5f;border-color:#3b82f6;color:#93c5fd}
.arch-box.l2{background:#451a03;border-color:#f59e0b;color:#fcd34d}
.arch-box.l3{background:#14532d;border-color:#22c55e;color:#86efac}
.arch-box.db{border-radius:50%;min-width:70px;padding:6px 10px;font-size:11px}
.arch-box.pg{background:#1e3a5f;border-color:#3b82f6;color:#93c5fd}
.arch-box.es{background:#450a0a;border-color:#ef4444;color:#fca5a5}
.arch-box.neo{background:#1e1b4b;border-color:#6366f1;color:#c4b5fd}
.arch-box.redis{background:#14532d;border-color:#22c55e;color:#86efac}
.arch-box.mongo{background:#451a03;border-color:#f59e0b;color:#fcd34d}
.arch-arrow{color:#475569;font-size:1.2em;margin:0 3px;font-weight:700}
.arch-sub{font-size:9px;color:var(--muted);margin-top:2px;font-weight:400}
.arch-conn{display:flex;align-items:center;gap:4px;font-size:10px;color:var(--muted);justify-content:center;margin:2px 0}
.arch-conn .dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.dot-pg{background:#3b82f6}.dot-es{background:#ef4444}.dot-neo{background:#6366f1}.dot-redis{background:#22c55e}.dot-mongo{background:#f59e0b}

.auth-flow{display:flex;flex-direction:column;gap:6px;margin:10px 0}
.auth-step{display:flex;align-items:center;gap:8px;padding:6px 10px;background:var(--bg);border-radius:6px;font-size:12px;border-left:3px solid var(--border)}
.auth-step.st-user{border-left-color:#3b82f6}
.auth-step.st-gw{border-left-color:#6366f1}
.auth-step.st-nginx{border-left-color:#818cf8}
.auth-step.st-lab{border-left-color:#22c55e}
.auth-step.st-db{border-left-color:#f59e0b}
.auth-step .anum{width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0;color:#fff;background:#475569}
.auth-step.st-user .anum{background:#3b82f6}.auth-step.st-gw .anum{background:#6366f1}.auth-step.st-nginx .anum{background:#818cf8}.auth-step.st-lab .anum{background:#22c55e}.auth-step.st-db .anum{background:#f59e0b}
.auth-step .atxt{flex:1;color:#cbd5e1;line-height:1.4}
.auth-step .adet{font-size:10px;color:var(--muted);margin-top:1px}

.jwt-box{background:#064e3b;border:1px solid #059669;border-radius:6px;padding:8px 12px;margin:8px 0;font-size:11px;font-family:'JetBrains Mono','Consolas',monospace;color:#6ee7b7;word-break:break-all}
.jwt-label{font-size:10px;color:var(--muted);margin-bottom:2px;font-family:'Segoe UI',system-ui,sans-serif}

.mtls-viz{display:flex;gap:12px;align-items:center;justify-content:center;padding:10px;background:var(--bg);border-radius:8px;border:1px solid var(--border);margin:8px 0}
.mtls-side{text-align:center;font-size:11px}
.mtls-side .box{padding:6px 12px;border-radius:6px;font-weight:700;font-size:12px;margin-bottom:4px}
.mtls-side .box.client{background:#1e1b4b;border:2px solid #6366f1;color:#c4b5fd}
.mtls-side .box.server{background:#312e81;border:2px solid #818cf8;color:#c4b5fd}
.mtls-exchange{display:flex;flex-direction:column;gap:3px;min-width:180px}
.mtls-msg{font-size:10px;padding:3px 8px;border-radius:4px;text-align:center}
.mtls-msg.to-r{background:#1e1b4b;color:#c4b5fd;border:1px dashed #6366f1}
.mtls-msg.to-l{background:#312e81;color:#c4b5fd;border:1px dashed #818cf8}
.mtls-msg.ok{background:#052e16;color:#4ade80;border:1px solid #166534}

.steps-list{margin:10px 0}
.step-item{display:flex;align-items:flex-start;gap:10px;padding:10px 12px;border-left:3px solid var(--border);margin-left:6px;background:var(--bg);border-radius:0 8px 8px 0;margin-bottom:5px}
.step-item.step-es{border-left-color:#ef4444}.step-item.step-pg{border-left-color:#3b82f6}.step-item.step-neo{border-left-color:#6366f1}.step-item.step-redis{border-left-color:#22c55e}.step-item.step-mongo{border-left-color:#f59e0b}
.step-num{width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0;color:#fff}
.step-num.sn-es{background:#ef4444}.step-num.sn-pg{background:#3b82f6}.step-num.sn-neo{background:#6366f1}.step-num.sn-redis{background:#22c55e}.step-num.sn-mongo{background:#f59e0b}
.step-body{flex:1}
.step-action{font-size:12px;color:#cbd5e1;line-height:1.4}
.step-result{font-size:11px;color:var(--muted);margin-top:2px}

.tabs{display:flex;gap:4px;margin-bottom:0;border-bottom:1px solid var(--border)}
.tab{padding:9px 20px;cursor:pointer;border-radius:8px 8px 0 0;background:transparent;color:var(--muted);font-size:13px;font-weight:600;border:1px solid transparent;border-bottom:none;transition:all .15s}
.tab:hover{color:#94a3b8}
.tab.active{background:var(--surface);color:#60a5fa;border-color:var(--border);border-bottom-color:var(--surface)}
.tab-content{display:none;padding-top:12px}
.tab-content.active{display:block}

.meta-row{display:flex;gap:16px;margin:8px 0;flex-wrap:wrap;font-size:12px}
.meta-item{display:flex;align-items:center;gap:5px}
.meta-label{color:var(--muted);font-weight:500}
.meta-val{font-weight:700}

.result-table{width:100%;border-collapse:collapse;margin:8px 0;font-size:12px}
.result-table th{background:var(--surface2);color:#60a5fa;padding:7px 9px;text-align:left;border-bottom:2px solid var(--border);font-weight:600;white-space:nowrap;font-size:11px}
.result-table td{padding:6px 9px;border-bottom:1px solid #1a2744;vertical-align:top;font-size:12px}
.result-table tr:hover td{background:#162035}

.pct-bar{width:50px;height:7px;background:#1e293b;border-radius:3px;display:inline-block;vertical-align:middle;margin-left:5px}
.pct-fill{height:100%;border-radius:3px;transition:width .3s}
.pct-low{background:#ef4444}.pct-mid{background:#f59e0b}.pct-high{background:#22c55e}

.raw-toggle{font-size:10px;color:var(--muted);cursor:pointer;text-decoration:underline;margin-top:8px;display:inline-block}
pre.raw-json{background:var(--bg);padding:12px;border-radius:6px;font-size:11px;max-height:350px;overflow:auto;border:1px solid var(--border);margin-top:6px;display:none;font-family:'JetBrains Mono','Consolas',monospace}

.gen-counts{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:6px;margin-top:10px}
.gen-count{text-align:center;padding:6px;background:var(--bg);border-radius:6px;border:1px solid var(--border)}
.gen-count .val{font-size:1.2em;font-weight:700;color:#60a5fa}
.gen-count .lbl{font-size:10px;color:var(--muted);margin-top:1px}

.loading-bar{height:3px;background:var(--border);border-radius:2px;margin:8px 0;overflow:hidden;display:none}
.loading-bar.active{display:block}
.loading-bar .fill{height:100%;width:30%;background:linear-gradient(90deg,var(--accent),#a78bfa);animation:loading 1.2s infinite}
@keyframes loading{0%{transform:translateX(-100%)}100%{transform:translateX(400%)}}

.hierarchy-chain{display:flex;gap:3px;align-items:center;flex-wrap:wrap;margin:4px 0;font-size:11px}
.hierarchy-chain .sep{color:var(--muted)}
.hierarchy-chain .item{padding:1px 7px;border-radius:3px;background:var(--bg);border:1px solid var(--border);color:#93c5fd}

.course-card{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;margin:8px 0}
.course-card h4{color:#93c5fd;margin-bottom:6px;font-size:13px}

.status-pill{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:18px;font-size:11px;font-weight:600}
.pill-ok{background:#052e16;color:#4ade80;border:1px solid #166534}
.pill-empty{background:#431407;color:#fb923c;border:1px solid #9a3412}
.pill-err{background:#450a0a;color:#fca5a5;border:1px solid #991b1b}

.collapsible{cursor:pointer;padding:6px 10px;background:var(--surface2);border-radius:6px;font-size:12px;font-weight:600;color:#93c5fd;margin:6px 0;user-select:none}
.collapsible:hover{background:#1e3050}
.collapsible+.coll-body{display:none;padding:8px 0}
.collapsible.open+.coll-body{display:block}
</style>
<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
<script>mermaid.initialize({startOnLoad:false,theme:'base',themeVariables:{primaryColor:'#3b82f6',primaryTextColor:'#1e293b',primaryBorderColor:'#94a3b8',lineColor:'#64748b',secondaryColor:'#f1f5f9',tertiaryColor:'#e2e8f0'}});</script>
</head>
<body>
<div class="container">
    <header>
        <h1>Polyglot Persistence - Система управления учебным процессом</h1>
        <div class="subtitle">PostgreSQL &bull; Elasticsearch &bull; Neo4j &bull; Redis &bull; MongoDB &bull; <span class="badge badge-mtls">mTLS</span> &bull; <span class="badge badge-jwt">JWT OAuth2</span></div>
    </header>

    <!-- ARCHITECTURE DIAGRAM -->
    <div class="card">
        <div class="card-header">
            <h2>Архитектура системы (диаграмма контейнеров)</h2>
        </div>
        <div class="arch-diagram">
            <div style="text-align:center;font-size:11px;color:var(--muted);margin-bottom:4px">Полный путь запроса: Пользователь → [HTTP+JWT] → Gateway → [HTTPS+mTLS] → Nginx → [HTTP+service JWT] → Lab → DB</div>
            <div class="arch-row">
                <div class="arch-box gw">Gateway<div class="arch-sub">OAuth2 + mTLS client</div></div>
                <span class="arch-arrow">&#10145;</span>
                <div class="arch-box ng">Nginx<div class="arch-sub">mTLS verify + proxy</div></div>
                <span class="arch-arrow">&#10145;</span>
                <div style="display:flex;gap:8px">
                    <div class="arch-box l1">Lab1<div class="arch-sub">ES+PG+Redis</div></div>
                    <div class="arch-box l2">Lab2<div class="arch-sub">PG+Neo+Redis+Mongo</div></div>
                    <div class="arch-box l3">Lab3<div class="arch-sub">ES+Neo+PG</div></div>
                </div>
            </div>
            <div style="display:flex;justify-content:center;gap:24px;margin-top:6px">
                <div class="arch-conn"><span class="dot dot-pg"></span>PostgreSQL</div>
                <div class="arch-conn"><span class="dot dot-es"></span>Elasticsearch</div>
                <div class="arch-conn"><span class="dot dot-neo"></span>Neo4j</div>
                <div class="arch-conn"><span class="dot dot-redis"></span>Redis</div>
                <div class="arch-conn"><span class="dot dot-mongo"></span>MongoDB</div>
            </div>
        </div>
    </div>

    <!-- AUTH SECTION -->
    <div class="card">
        <div class="card-header">
            <h2>Шаг 1: Авторизация OAuth2 (упрощённая схема)</h2>
        </div>
        <div style="font-size:11px;color:var(--muted);margin-bottom:8px">
            Упрощённая схема OAuth2: пользователь вводит логин/парол → сервер сразу выдаёт JWT-токен на руки.
            В полной схеме токен пользователю не выдаётся, но по ТЗ разрешена упрощённая схема.
            Токен содержит: <span class="badge badge-jwt">sub</span> (имя), <span class="badge badge-jwt">type</span> (user/service), <span class="badge badge-jwt">exp</span> (срок действия).
        </div>

        <div class="auth-flow" id="auth-flow-visual">
            <div class="auth-step st-user">
                <div class="anum">1</div>
                <div><div class="atxt">Пользователь вводит логин/парол → POST /auth/login</div><div class="adet">grant_type=password, username=admin, password=admin123</div></div>
            </div>
            <div class="auth-step st-gw">
                <div class="anum">2</div>
                <div><div class="atxt">Gateway проверяет логин/пароль, создаёт JWT (type=user, TTL=24ч)</div><div class="adet">Payload: {"sub":"admin","type":"user","iat":...,"exp":...}</div></div>
            </div>
            <div class="auth-step st-gw">
                <div class="anum">3</div>
                <div><div class="atxt">Gateway возвращает access_token пользователю</div><div class="adet">Пользователь хранит токен и отправляет в Authorization: Bearer &lt;token&gt;</div></div>
            </div>
        </div>

        <div class="row">
            <label>Логин</label><input id="login-user" value="admin" style="max-width:160px"/>
            <label>Пароль</label><input id="login-pass" type="password" value="admin123" style="max-width:160px"/>
            <button class="btn-blue" onclick="doLogin()">Войти</button>
            <span id="auth-indicator" style="font-size:11px;color:var(--muted)"></span>
        </div>
        <div id="token-area"></div>
    </div>

    <!-- mTLS EXPLANATION -->
    <div class="card">
        <div class="card-header">
            <h2>Шаг 2: Взаимная проверка сертификатов (mTLS)</h2>
        </div>
        <div style="font-size:11px;color:var(--muted);margin-bottom:6px">
            Когда gateway вызывает лаб-контейнер, он идёт через nginx с взаимной проверкой сертификатов (mTLS).
            Nginx проверяет клиентский сертификат gateway (client.crt), а gateway проверяет серверный сертификат nginx (server.crt).
            Оба сертификата подписаны единым Root CA (ca.crt).
        </div>
        <div class="mtls-viz">
            <div class="mtls-side">
                <div class="box client">Gateway (клиент)</div>
                <div style="font-size:10px;color:var(--muted)">client.crt + client.key</div>
            </div>
            <div class="mtls-exchange">
                <div class="mtls-msg to-r">1. ClientHello + client.crt →</div>
                <div class="mtls-msg to-l">← 2. ServerHello + server.crt</div>
                <div class="mtls-msg to-r">3. Проверка server.crt по ca.crt →</div>
                <div class="mtls-msg to-l">← 4. Проверка client.crt по ca.crt</div>
                <div class="mtls-msg ok">5. mTLS-handshake OK! Зашифрованный канал установлен</div>
                <div class="mtls-msg to-r">6. Service JWT + запрос → (через HTTPS)</div>
                <div class="mtls-msg to-l">← 7. Ответ лаб-контейнера</div>
            </div>
            <div class="mtls-side">
                <div class="box server">Nginx (сервер)</div>
                <div style="font-size:10px;color:var(--muted)">server.crt + server.key<br>ssl_verify_client on</div>
            </div>
        </div>
        <div style="font-size:11px;color:var(--muted);margin-top:4px">
            После успешного mTLS: Nginx проксирует HTTP-запрос в лаб-контейнер + передаёт Service JWT в заголовке Authorization.
            Лаб проверяет, что JWT содержит type=service (не user!).
        </div>
    </div>

    <!-- GENERATOR -->
    <div class="card">
        <div class="card-header">
            <h2>Генератор данных (заполняет все 5 БД напрямую)</h2>
            <span id="gen-status" class="status-pill pill-empty">проверка...</span>
        </div>
        <div class="row">
            <button class="btn-green" onclick="generateData()">Сгенерировать данные</button>
            <button class="btn-red" onclick="clearData()">Очистить все хранилища</button>
            <button class="btn-gray" onclick="checkStatus()">Обновить статус</button>
        </div>
        <div id="gen-result" style="display:none"></div>
        <div class="loading-bar" id="gen-loading"><div class="fill"></div></div>
    </div>

    <!-- LAB QUERIES -->
    <div class="card">
        <div class="card-header">
            <h2>Шаг 3: Лабораторные запросы</h2>
        </div>
        <div class="tabs">
            <div class="tab active" onclick="switchTab('lab1',this)">ЛР1: Посещаемость</div>
            <div class="tab" onclick="switchTab('lab2',this)">ЛР2: Вместимость</div>
            <div class="tab" onclick="switchTab('lab3',this)">ЛР3: Часы</div>
            <div class="tab" onclick="switchTab('diagrams',this)">Схемы</div>
        </div>

        <!-- LAB 1 -->
        <div id="tab-lab1" class="tab-content active">
            <div style="color:var(--muted);font-size:12px;margin-bottom:8px">
                <b>Задание ЛР1:</b> 10 студентов с минимальным % посещения лекций, содержащих заданный термин, за определённый период.
                <br>Состав полей: полная информация о студенте, процент посещения, период отчёта, термин в занятиях курса.
            </div>
            <div class="collapsible" onclick="this.classList.toggle('open')">Показать/скрыть путь запроса и объяснение БД</div>            <div class="coll-body">
                <div class="auth-flow">
                    <div class="auth-step st-user"><div class="anum">A</div><div><div class="atxt">Пользователь отправляет запрос с user JWT в заголовке</div><div class="adet">GET /attendance/low?term=...&start_date=...&end_date=... + Authorization: Bearer &lt;user_jwt&gt;</div></div></div>
                    <div class="auth-step st-gw"><div class="anum">B</div><div><div class="atxt">Gateway проверяет user JWT (type=user), создаёт service JWT (type=service)</div><div class="adet">Два типа токенов: user (24ч) и service (1ч). Лаб пропускает только service.</div></div></div>
                    <div class="auth-step st-nginx"><div class="anum">C</div><div><div class="atxt">Gateway отправляет HTTPS-запрос к nginx с клиентским сертификатом (mTLS)</div><div class="adet">client.crt подписан Root CA → nginx проверяет ssl_verify_client on → OK</div></div></div>
                    <div class="auth-step st-lab"><div class="anum">D</div><div><div class="atxt">Nginx проксирует в Lab1, лаб проверяет service JWT</div><div class="adet">POST /lab1/query + Authorization: Bearer &lt;service_jwt&gt;</div></div></div>
                    <div class="auth-step st-db"><div class="anum">1</div><div><div class="atxt"><span class="badge badge-es">Elasticsearch</span> BM25-поиск термина в лекциях → список lecture_id</div><div class="adet">multi_match: title, annotation, content_text + fuzziness=AUTO + russian_custom анализатор</div></div></div>
                    <div class="auth-step st-db"><div class="anum">2</div><div><div class="atxt"><span class="badge badge-pg">PostgreSQL</span> CTE MATERIALIZED: top-10 студентов с мин % посещения</div><div class="adet">matching_schedule + group_sched_count + attended -> ORDER BY pct ASC LIMIT 10, partition pruning</div></div></div>
                    <div class="auth-step st-db"><div class="anum">3</div><div><div class="atxt"><span class="badge badge-redis">Redis</span> Pipeline HGETALL student:{id} для top-10 студентов</div><div class="adet">O(1) pipeline, TTL=2ч, пополнение кэша из PG при промахе</div></div></div>
                </div>
            </div>
            <div class="arch-row" style="margin:6px 0">
                <span class="badge badge-mtls">mTLS</span><span class="arch-arrow">&#10145;</span>
                <span class="badge badge-es">ES</span><span class="arch-arrow">&#10145;</span>
                <span class="badge badge-pg">PG</span><span class="arch-arrow">&#10145;</span>
                <span class="badge badge-redis">Redis</span>
            </div>
            <div class="row">
                <label>Термин/фраза</label><input id="lab1-term" value="микропроцессоров"/>
                <label>Начало</label><input id="lab1-start" value="2025-09-01" style="max-width:140px"/>
                <label>Конец</label><input id="lab1-end" value="2026-01-31" style="max-width:140px"/>
                <button class="btn-blue" onclick="runLab1()">Выполнить</button>
            </div>
        </div>

        <!-- LAB 2 -->
        <div id="tab-lab2" class="tab-content">
            <div style="color:var(--muted);font-size:12px;margin-bottom:8px">
                <b>Задание ЛР2:</b> Необходимый объём аудитории для проведения занятий по курсу заданного семестра и года с требованиями к оборудованию.
                <br>Состав полей: полная информация о курсе, лекции и количестве слушателей.
            </div>
            <div class="collapsible" onclick="this.classList.toggle('open')">Показать/скрыть путь запроса и объяснение БД</div>            <div class="coll-body">
                <div class="auth-flow">
                    <div class="auth-step st-user"><div class="anum">A</div><div><div class="atxt">Пользователь отправляет запрос с user JWT</div><div class="adet">GET /schedule/capacity?semester=1&year=2025&equipment=... + Bearer token</div></div></div>
                    <div class="auth-step st-gw"><div class="anum">B</div><div><div class="atxt">Gateway проверяет user JWT, создаёт service JWT, mTLS к nginx</div></div></div>
                    <div class="auth-step st-nginx"><div class="anum">C</div><div><div class="atxt">Nginx проверяет client.crt, прокси в Lab2</div></div></div>
                    <div class="auth-step st-lab"><div class="anum">D</div><div><div class="atxt">Lab2 проверяет service JWT, выполняет запрос к 4 БД</div></div></div>
                    <div class="auth-step st-db"><div class="anum">1</div><div><div class="atxt"><span class="badge badge-pg">PostgreSQL</span> Фильтрация лекций по семестру + оборудование, schedule по году, COUNT студентов</div><div class="adet">Batch ANY(%s::uuid[]), composite index (lecture_id, week_start_date)</div></div></div>
                    <div class="auth-step st-db"><div class="anum">2</div><div><div class="atxt"><span class="badge badge-neo">Neo4j</span> Обход графа: Lecture-[BELONGS_TO]->Course, Lecture<-[PART_OF]-Schedule<-[CONTAINS]-Group</div><div class="adet">Сужение множества групп для Redis (не все студенты, а только из Neo4j)</div></div></div>
                    <div class="auth-step st-db"><div class="anum">3</div><div><div class="atxt"><span class="badge badge-redis">Redis</span> Pipeline HGETALL student:{id} - только для групп из Neo4j</div><div class="adet">Batch 2000, fallback к PG при промахах, заполнение кэша</div></div></div>
                    <div class="auth-step st-db"><div class="anum">4</div><div><div class="atxt"><span class="badge badge-mongo">MongoDB</span> findOne: University->Institutes->Departments->Specialities</div><div class="adet">O(1) чтение вложенного документа вместо 4 JOIN в PostgreSQL</div></div></div>
                </div>
            </div>
            <div class="arch-row" style="margin:6px 0">
                <span class="badge badge-mtls">mTLS</span><span class="arch-arrow">&#10145;</span>
                <span class="badge badge-pg">PG</span><span class="arch-arrow">&#10145;</span>
                <span class="badge badge-neo">Neo4j</span><span class="arch-arrow">&#10145;</span>
                <span class="badge badge-redis">Redis</span><span class="arch-arrow">&#10145;</span>
                <span class="badge badge-mongo">Mongo</span>
            </div>
            <div class="row">
                <label>Семестр</label><input id="lab2-semester" type="number" value="1" min="1" max="8" style="max-width:80px"/>
                <label>Год</label><input id="lab2-year" type="number" value="2025" style="max-width:100px"/>
                <label>Оборудование</label><input id="lab2-equipment" value="проектор"/>
                <button class="btn-blue" onclick="runLab2()">Выполнить</button>
            </div>
        </div>

        <!-- LAB 3 -->
        <div id="tab-lab3" class="tab-content">
            <div style="color:var(--muted);font-size:12px;margin-bottom:8px">
                <b>Задание ЛР3:</b> Отчёт по заданной группе с указанием объёма прослушанных и запланированных часов лекций.
                1 лекция = 2 академических часа. В отчёт попадают только лекции со спец. тегом дисциплины кафедры.
                <br>Состав полей: полная информация о группе, студенте, курсе, запланированных и посещённых часах.
            </div>
            <div class="collapsible" onclick="this.classList.toggle('open')">Показать/скрыть путь запроса и объяснение БД</div>            <div class="coll-body">
                <div class="auth-flow">
                    <div class="auth-step st-user"><div class="anum">A</div><div><div class="atxt">Пользователь отправляет запрос с user JWT</div><div class="adet">GET /hours/report?group_name=Группа-001 + Bearer token</div></div></div>
                    <div class="auth-step st-gw"><div class="anum">B</div><div><div class="atxt">Gateway проверяет user JWT, создаёт service JWT, mTLS к nginx</div></div></div>
                    <div class="auth-step st-nginx"><div class="anum">C</div><div><div class="atxt">Nginx проверяет client.crt, прокси в Lab3</div></div></div>
                    <div class="auth-step st-lab"><div class="anum">D</div><div><div class="atxt">Lab3 проверяет service JWT, выполняет запрос к 3 БД</div></div></div>
                    <div class="auth-step st-db"><div class="anum">0</div><div><div class="atxt"><span class="badge badge-pg">PostgreSQL</span> Lookup group_id по group_name (пользователь вводит название, не UUID)</div></div></div>
                    <div class="auth-step st-db"><div class="anum">1</div><div><div class="atxt"><span class="badge badge-es">Elasticsearch</span> Фильтрация по тегам спец. дисциплин (terms query: specdisciplina и т.д.)</div><div class="adet">Только лекции со спец. тегами попадают в отчёт, lecture_type=лекции</div></div></div>
                    <div class="auth-step st-db"><div class="anum">2</div><div><div class="atxt"><span class="badge badge-neo">Neo4j</span> Обход графа: Student-[MEMBER_OF]->Group-[CONTAINS]->Schedule-[PART_OF]->Lecture-[BELONGS_TO]->Course</div><div class="adet">1 стартовая нода Group, O(E) по индексу</div></div></div>
                    <div class="auth-step st-db"><div class="anum">3</div><div><div class="atxt"><span class="badge badge-pg">PostgreSQL</span> Batch attendance + lecture_hours + student details</div><div class="adet">attended_hours = attended_count * 2 (1 лекция = 2 ак.ч.), ANY(%s::uuid[]) batch</div></div></div>
                </div>
            </div>
            <div class="arch-row" style="margin:6px 0">
                <span class="badge badge-mtls">mTLS</span><span class="arch-arrow">&#10145;</span>
                <span class="badge badge-es">ES</span><span class="arch-arrow">&#10145;</span>
                <span class="badge badge-neo">Neo4j</span><span class="arch-arrow">&#10145;</span>
                <span class="badge badge-pg">PG</span>
            </div>
            <div class="row">
                <label>Группа</label>
                <input id="lab3-group" value="Группа-001" style="max-width:200px"/>
                <button class="btn-blue" onclick="runLab3()">Выполнить</button>
            </div>
        </div>

        <!-- DIAGRAMS -->
        <div id="tab-diagrams" class="tab-content">
            <div style="font-size:11px;color:var(--muted);margin-bottom:10px">
                Диаграммы архитектуры и распределения данных. Рендеринг через Mermaid.js.
            </div>
            <div class="collapsible open" onclick="this.classList.toggle('open')">C4 — Контекст (Уровень 1)</div>
            <div class="coll-body" style="display:block"><div id="dia-c4ctx" style="background:#fff;padding:12px;border-radius:8px;overflow:auto"></div></div>
            <div class="collapsible open" onclick="this.classList.toggle('open')">C4 — Контейнеры (Уровень 2)</div>
            <div class="coll-body" style="display:block"><div id="dia-c4cont" style="background:#fff;padding:12px;border-radius:8px;overflow:auto"></div></div>
            <div class="collapsible" onclick="this.classList.toggle('open')">C4 — Компоненты (Уровень 3)</div>
            <div class="coll-body"><div id="dia-c4comp" style="background:#fff;padding:12px;border-radius:8px;overflow:auto"></div></div>
            <div class="collapsible" onclick="this.classList.toggle('open')">DFD — Уровень 0</div>
            <div class="coll-body"><div id="dia-dfd0" style="background:#fff;padding:12px;border-radius:8px;overflow:auto"></div></div>
            <div class="collapsible" onclick="this.classList.toggle('open')">DFD — Уровень 1</div>
            <div class="coll-body"><div id="dia-dfd1" style="background:#fff;padding:12px;border-radius:8px;overflow:auto"></div></div>
            <div class="collapsible" onclick="this.classList.toggle('open')">ER-диаграмма PostgreSQL</div>
            <div class="coll-body"><div id="dia-er" style="background:#fff;padding:12px;border-radius:8px;overflow:auto"></div></div>
        </div>

        <div class="loading-bar" id="query-loading"><div class="fill"></div></div>
        <div id="result-area"></div>
    </div>
</div>

<script>
let TOKEN='';
let lastRawData=null;

const STORE_CSS={Elasticsearch:'es',PostgreSQL:'pg',Neo4j:'neo',Redis:'redis',MongoDB:'mongo'};

function b64decode(s){
    try{
        let b=s.replace(/-/g,'+').replace(/_/g,'/');
        while(b.length%4)b+='=';
        return decodeURIComponent(atob(b).split('').map(c=>'%'+('00'+c.charCodeAt(0).toString(16)).slice(-2)).join(''));
    }catch(e){return s}
}

async function api(method,url,body){
    const opts={method,headers:{}};
    if(TOKEN)opts.headers['Authorization']='Bearer '+TOKEN;
    if(body){opts.headers['Content-Type']='application/json';opts.body=JSON.stringify(body)}
    const resp=await fetch(url,opts);
    const data=await resp.json();
    if(!resp.ok)throw new Error(data.detail||JSON.stringify(data));
    return data
}

async function doLogin(){
    try{
        const u=document.getElementById('login-user').value;
        const p=document.getElementById('login-pass').value;

        const indicator=document.getElementById('auth-indicator');
        indicator.innerHTML='<span style="color:#fbbf24">... Ожидание</span>';

        const r=await api('POST','/auth/login',{username:u,password:p});
        TOKEN=r.access_token;

        let payloadStr='';
        try{
            const parts=TOKEN.split('.');
            const header=JSON.parse(b64decode(parts[0]));
            const payload=JSON.parse(b64decode(parts[1]));
            payloadStr=JSON.stringify(payload,null,2);
        }catch(e){payloadStr='(не удалось декодировать)'}

        document.getElementById('token-area').innerHTML=
            '<div class="jwt-label">Полученный JWT-токен (сохраняйте в Authorization: Bearer):</div>'+
            '<div class="jwt-box">'+TOKEN.substring(0,80)+'...</div>'+
            '<div class="jwt-label" style="margin-top:6px">Декодированный payload (содержимое токена):</div>'+
            '<div class="jwt-box">'+payloadStr+'</div>'+
            '<div class="auth-flow" style="margin-top:8px">'+
            '<div class="auth-step st-gw"><div class="anum">4</div><div><div class="atxt">Теперь при каждом запросе gateway: проверяет user JWT → создаёт service JWT (type=service, TTL=1ч)</div><div class="adet">Service JWT отправляется в nginx, не пользователю</div></div></div>'+
            '<div class="auth-step st-nginx"><div class="anum">5</div><div><div class="atxt">Gateway отправляет HTTPS-запрос с client.crt (mTLS) + service JWT в заголовке</div><div class="adet">Взаимная проверка: nginx проверяет client.crt, gateway проверяет server.crt</div></div></div>'+
            '</div>';

        indicator.innerHTML='<span style="color:#4ade80">&#10003; OAuth2 password grant ('+u+'), TTL 24ч</span>';
    }catch(e){
        document.getElementById('auth-indicator').innerHTML='<span style="color:#fca5a5">&#10060; Ошибка: '+e.message+'</span>';
    }
}

async function checkStatus(){
    try{
        const r=await api('GET','/generator/status');
        const el=document.getElementById('gen-status');
        if(r.status==='ready'){el.textContent='готов ('+r.students+' студентов, '+r.courses+' курсов)';el.className='status-pill pill-ok'}
        else if(r.status==='empty'){el.textContent='пусто - сгенерируйте данные';el.className='status-pill pill-empty'}
        else{el.textContent=r.status;el.className='status-pill pill-err'}
    }catch(e){document.getElementById('gen-status').textContent='ошибка';document.getElementById('gen-status').className='status-pill pill-err'}
}

async function generateData(){
    if(!TOKEN){alert('Сначала авторизуйтесь');return}
    const bar=document.getElementById('gen-loading');bar.classList.add('active');
    const res=document.getElementById('gen-result');res.style.display='none';
    try{
        const r=await api('POST','/generator/generate',{});
        const c=r.counts;
        let html='<div class="gen-counts">';
        const labels={university:'Университет',institutes:'Институты',departments:'Кафедры',specialities:'Специальности',department_specialities:'Каф.<->Спец.',lecture_courses:'Курсы',lectures:'Лекции',lecture_materials:'Материалы',student_groups:'Группы',students:'Студенты',schedule:'Расписание',attendance:'Посещения'};
        for(const[k,v]of Object.entries(c)){
            html+='<div class="gen-count"><div class="val">'+v+'</div><div class="lbl">'+(labels[k]||k)+'</div></div>';
        }
        html+='</div>';
        res.innerHTML=html;res.style.display='block';
        checkStatus();
    }catch(e){res.innerHTML='<div style="color:#fca5a5">Ошибка: '+e.message+'</div>';res.style.display='block'}
    finally{bar.classList.remove('active')}
}

async function clearData(){
    if(!TOKEN){alert('Сначала авторизуйтесь');return}
    if(!confirm('Очистить ВСЕ данные из всех 5 хранилищ?'))return;
    try{
        await api('DELETE','/generator/clear');
        document.getElementById('gen-result').style.display='none';
        document.getElementById('result-area').innerHTML='';
        checkStatus();
    }catch(e){alert('Ошибка: '+e.message)}
}

function renderSteps(steps){
    if(!steps||!steps.length)return'';
    let html='<div class="steps-list">';
    steps.forEach(s=>{
        const css=STORE_CSS[s.store]||'pg';
        html+='<div class="step-item step-'+css+'">';
        html+='<div class="step-num sn-'+css+'">'+s.step+'</div>';
        html+='<div class="step-body"><div class="step-action">'+s.action+'</div>';
        html+='<div class="step-result">'+s.result+'</div></div>';
        html+='</div>';
    });
    html+='</div>';
    return html
}

function pctBar(pct){
    const cls=pct<50?'pct-low':pct<75?'pct-mid':'pct-high';
    return '<span class="pct-bar"><span class="pct-fill '+cls+'" style="width:'+Math.min(pct,100)+'%"></span></span>'
}

function renderLab1(data){
    let html='';
    html+='<div class="meta-row">';
    html+='<div class="meta-item"><span class="meta-label">Путь:</span><span class="badge badge-mtls">mTLS</span><span style="color:var(--muted)">&#10145;</span><span class="badge badge-es">ES</span><span style="color:var(--muted)">&#10145;</span><span class="badge badge-pg">PG</span><span style="color:var(--muted)">&#10145;</span><span class="badge badge-redis">Redis</span></div>';
    html+='<div class="meta-item"><span class="meta-label">Время:</span><span class="meta-val">'+data.execution_time_sec+'s</span></div>';
    html+='<div class="meta-item"><span class="meta-label">Результатов:</span><span class="meta-val">'+data.result.length+'</span></div>';
    html+='</div>';
    html+=renderSteps(data.steps);
    if(data.result.length){
        html+='<table class="result-table"><thead><tr><th>#</th><th>ФИО студента</th><th>Email</th><th>Номер билета</th><th>Группа</th><th>Пос.</th><th>Из</th><th>%</th><th>Курс</th><th>Термин</th><th>Период</th></tr></thead><tbody>';
        data.result.forEach((r,i)=>{
            const s=r.student;
            const pct=r.attendance_pct;
            html+='<tr><td>'+(i+1)+'</td>';
            html+='<td>'+s.last_name+' '+s.first_name+' '+(s.patronymic||'')+'</td>';
            html+='<td style="font-size:11px">'+(s.email||'')+'</td>';
            html+='<td style="font-size:11px">'+(s.student_card_number||'')+'</td>';
            html+='<td style="font-size:11px">'+(r.group_id||'').substring(0,8)+'...</td>';
            html+='<td>'+r.total_attended+'</td><td>'+r.total_scheduled+'</td>';
            html+='<td>'+pct.toFixed(1)+'%'+pctBar(pct)+'</td>';
            html+='<td style="font-size:11px">'+(r.term_in_course?.course_name||'')+'</td>';
            html+='<td style="font-size:11px">'+(r.term_in_course?.lecture_title||'')+'</td>';
            html+='<td style="font-size:11px">'+(r.period?.start_date||'')+' - '+(r.period?.end_date||'')+'</td>';
            html+='</tr>';
        });
        html+='</tbody></table>';
    }
    html+='<span class="raw-toggle" onclick="toggleRaw()">Показать/скрыть raw JSON</span>';
    html+='<pre class="raw-json" id="raw-json"></pre>';
    return html
}

function renderLab2(data){
    let html='';
    html+='<div class="meta-row">';
    html+='<div class="meta-item"><span class="meta-label">Путь:</span><span class="badge badge-mtls">mTLS</span><span style="color:var(--muted)">&#10145;</span><span class="badge badge-pg">PG</span><span style="color:var(--muted)">&#10145;</span><span class="badge badge-neo">Neo4j</span><span style="color:var(--muted)">&#10145;</span><span class="badge badge-redis">Redis</span><span style="color:var(--muted)">&#10145;</span><span class="badge badge-mongo">Mongo</span></div>';
    html+='<div class="meta-item"><span class="meta-label">Время:</span><span class="meta-val">'+data.execution_time_sec+'s</span></div>';
    html+='</div>';
    html+=renderSteps(data.steps);
    data.result.forEach(r=>{
        html+='<div class="course-card">';
        html+='<h4>'+r.course.name+' (семестр '+r.course.semester+')</h4>';
        html+='<div class="meta-row" style="font-size:11px">';
        html+='<div class="meta-item"><span class="meta-label">Часы:</span><span class="meta-val">'+r.course.total_hours+' ('+r.course.lecture_hours+'л/'+r.course.practice_hours+'пр/'+r.course.lab_hours+'лаб)</span></div>';
        html+='<div class="meta-item"><span class="meta-label">Слушателей:</span><span class="meta-val" style="color:#fbbf24">'+r.total_listeners+'</span></div>';
        html+='<div class="meta-item"><span class="meta-label">Вместимость:</span><span class="meta-val" style="color:#fbbf24">'+r.required_classroom_capacity+'</span></div>';
        html+='</div>';
        if(r.hierarchy&&r.hierarchy.university){
            html+='<div class="hierarchy-chain">';
            html+='<span class="item">'+r.hierarchy.university+'</span><span class="sep">&#9656;</span>';
            html+='<span class="item">'+r.hierarchy.institute+'</span><span class="sep">&#9656;</span>';
            html+='<span class="item">'+r.hierarchy.department+'</span><span class="sep">&#9656;</span>';
            html+='<span class="item">'+r.hierarchy.speciality+' ('+r.hierarchy.speciality_code+')</span>';
            html+='</div>';
        }
        if(r.lectures&&r.lectures.length){
            html+='<table class="result-table"><thead><tr><th>Лекция</th><th>Тип</th><th>Оборудование</th><th>Аудитория</th><th>Дата</th><th>Время</th><th>Преподаватель</th><th>Слушателей</th></tr></thead><tbody>';
            r.lectures.forEach(l=>{
                html+='<tr><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">'+l.title+'</td>';
                html+='<td>'+l.type+'</td><td>'+l.equipment_req+'</td>';
                html+='<td>'+l.classroom+'</td><td>'+l.date+'</td><td>'+l.time+'</td>';
                html+='<td>'+l.teacher+'</td><td>'+l.listeners+'</td></tr>';
            });
            html+='</tbody></table>';
        }
        if(r.groups&&r.groups.length){
            html+='<div style="margin-top:6px;font-size:11px;color:var(--muted)">Группы: ';
            r.groups.forEach(g=>{html+='<span class="badge badge-redis" style="font-size:9px;margin:2px">'+g.name+' ('+g.student_count+')</span> '});
            html+='</div>';
        }
        html+='</div>';
    });
    html+='<span class="raw-toggle" onclick="toggleRaw()">Показать/скрыть raw JSON</span>';
    html+='<pre class="raw-json" id="raw-json"></pre>';
    return html
}

function renderLab3(data){
    let html='';
    html+='<div class="meta-row">';
    html+='<div class="meta-item"><span class="meta-label">Путь:</span><span class="badge badge-mtls">mTLS</span><span style="color:var(--muted)">&#10145;</span><span class="badge badge-es">ES</span><span style="color:var(--muted)">&#10145;</span><span class="badge badge-neo">Neo4j</span><span style="color:var(--muted)">&#10145;</span><span class="badge badge-pg">PG</span></div>';
    html+='<div class="meta-item"><span class="meta-label">Время:</span><span class="meta-val">'+data.execution_time_sec+'s</span></div>';
    html+='<div class="meta-item"><span class="meta-label">1 лекция =</span><span class="meta-val">'+data.hours_per_lecture+' ак.ч.</span></div>';
    html+='</div>';
    if(data.group){
        html+='<div class="meta-row"><div class="meta-item"><span class="meta-label">Группа:</span><span class="meta-val">'+data.group.name+'</span></div>';
        html+='<div class="meta-item"><span class="meta-label">Год поступления:</span><span class="meta-val">'+data.group.enrollment_year+'</span></div>';
        html+='<div class="meta-item"><span class="meta-label">Студентов:</span><span class="meta-val">'+data.students.length+'</span></div></div>';
    }
    if(data.hierarchy&&data.hierarchy.institute){
        html+='<div class="hierarchy-chain">';
        html+='<span class="item">'+data.hierarchy.institute+'</span><span class="sep">&#9656;</span>';
        html+='<span class="item">'+data.hierarchy.department+'</span>';
        html+='</div>';
    }
    html+=renderSteps(data.steps);
    if(data.students&&data.students.length){
        html+='<table class="result-table"><thead><tr><th>Студент</th><th>Курс</th><th>Сем.</th><th>Теги</th><th>Запл. часов</th><th>Посещ. лекций</th><th>Посещ. часов</th><th>%</th></tr></thead><tbody>';
        data.students.forEach(s=>{
            const numCourses=s.courses.length;
            const totalPct=s.total_planned_hours>0?((s.total_attended_hours/s.total_planned_hours)*100):0;
            s.courses.forEach((c,ci)=>{
                const pct=c.planned_hours>0?((c.attended_hours/c.planned_hours)*100):0;
                if(ci===0){
                    html+='<tr>';
                    html+='<td rowspan="'+numCourses+'" style="font-weight:600;vertical-align:top;border-right:1px solid var(--border)">'+s.student_name+'<div style="font-size:10px;color:#fbbf24;margin-top:3px">Итого: '+s.total_attended_hours+'/'+s.total_planned_hours+' ак.ч. ('+totalPct.toFixed(1)+'%)'+pctBar(totalPct)+'</div></td>';
                }
                html+='<td>'+c.course_name+'</td><td>'+c.semester+'</td>';
                html+='<td>'+(c.special_tags||[]).map(t=>'<span class="badge badge-es" style="font-size:8px">'+t+'</span>').join(' ')+'</td>';
                html+='<td>'+c.planned_hours+'</td><td>'+c.attended_lectures+'/'+c.total_scheduled_lectures+'</td>';
                html+='<td style="color:#fbbf24;font-weight:700">'+c.attended_hours+'</td>';
                html+='<td>'+pct.toFixed(1)+'%'+pctBar(pct)+'</td></tr>';
            });
        });
        html+='</tbody></table>';
    }
    html+='<span class="raw-toggle" onclick="toggleRaw()">Показать/скрыть raw JSON</span>';
    html+='<pre class="raw-json" id="raw-json"></pre>';
    return html
}

function toggleRaw(){
    const pre=document.getElementById('raw-json');
    if(pre){pre.style.display=pre.style.display==='none'?'block':'none';pre.textContent=JSON.stringify(lastRawData,null,2)}
}

async function runLab1(){
    if(!TOKEN){alert('Сначала авторизуйтесь');return}
    const term=document.getElementById('lab1-term').value;
    const start=document.getElementById('lab1-start').value;
    const end=document.getElementById('lab1-end').value;
    const bar=document.getElementById('query-loading');bar.classList.add('active');
    document.getElementById('result-area').innerHTML='<div style="color:#60a5fa;padding:8px;font-size:12px">Gateway <span class="badge badge-mtls">mTLS</span> &#10145; nginx &#10145; <span class="badge badge-es">ES</span> &#10145; <span class="badge badge-pg">PG</span> &#10145; <span class="badge badge-redis">Redis</span> ...</div>';
    try{
        const r=await api('GET','/attendance/low?term='+encodeURIComponent(term)+'&start_date='+start+'&end_date='+end);
        lastRawData=r;
        document.getElementById('result-area').innerHTML=renderLab1(r);
    }catch(e){document.getElementById('result-area').innerHTML='<div style="color:#fca5a5;padding:8px">&#10060; Ошибка: '+e.message+'</div>'}
    finally{bar.classList.remove('active')}
}

async function runLab2(){
    if(!TOKEN){alert('Сначала авторизуйтесь');return}
    const sem=document.getElementById('lab2-semester').value;
    const yr=document.getElementById('lab2-year').value;
    const eq=document.getElementById('lab2-equipment').value;
    const bar=document.getElementById('query-loading');bar.classList.add('active');
    document.getElementById('result-area').innerHTML='<div style="color:#60a5fa;padding:8px;font-size:12px">Gateway <span class="badge badge-mtls">mTLS</span> &#10145; nginx &#10145; <span class="badge badge-pg">PG</span> &#10145; <span class="badge badge-neo">Neo4j</span> &#10145; <span class="badge badge-redis">Redis</span> &#10145; <span class="badge badge-mongo">Mongo</span> ...</div>';
    try{
        const r=await api('GET','/schedule/capacity?semester='+sem+'&year='+yr+'&equipment='+encodeURIComponent(eq));
        lastRawData=r;
        document.getElementById('result-area').innerHTML=renderLab2(r);
    }catch(e){document.getElementById('result-area').innerHTML='<div style="color:#fca5a5;padding:8px">&#10060; Ошибка: '+e.message+'</div>'}
    finally{bar.classList.remove('active')}
}

async function runLab3(){
    if(!TOKEN){alert('Сначала авторизуйтесь');return}
    const gname=document.getElementById('lab3-group').value;
    if(!gname){alert('Введите название группы');return}
    const bar=document.getElementById('query-loading');bar.classList.add('active');
    document.getElementById('result-area').innerHTML='<div style="color:#60a5fa;padding:8px;font-size:12px">Gateway <span class="badge badge-mtls">mTLS</span> &#10145; nginx &#10145; <span class="badge badge-es">ES</span> &#10145; <span class="badge badge-neo">Neo4j</span> &#10145; <span class="badge badge-pg">PG</span> ...</div>';
    try{
        const r=await api('GET','/hours/report?group_name='+encodeURIComponent(gname));
        lastRawData=r;
        document.getElementById('result-area').innerHTML=renderLab3(r);
    }catch(e){document.getElementById('result-area').innerHTML='<div style="color:#fca5a5;padding:8px">&#10060; Ошибка: '+e.message+'</div>'}
    finally{bar.classList.remove('active')}
}

function switchTab(tab,el){
    document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
    el.classList.add('active');
    document.getElementById('tab-'+tab).classList.add('active');
    if(tab==='diagrams'){renderDiagrams()}
}

const DIAGRAMS={

c4ctx:`graph LR
    U(["Пользователь"]) -->|"HTTPS + JWT"| S["Система полиглотных отчётов"]
    S -->|"JSON-отчёт"| U`,

c4cont:`graph TB
    U(["Пользователь"])
    subgraph SYS["Система полиглотных отчётов"]
        GW["API Gateway<br/>FastAPI :8000<br/>OAuth2 + mTLS"]
        NX["Nginx :443<br/>mTLS verify + proxy"]
        L1["Lab1 :8001<br/>ES-PG-Redis"]
        L2["Lab2 :8002<br/>PG-Neo4j-Redis-Mongo"]
        L3["Lab3 :8003<br/>ES-Neo4j-PG"]
        GEN["Генератор :8010<br/>Заполняет 5 БД"]
        CERT["Генератор сертификатов<br/>Alpine"]
        PG[("PostgreSQL :5432")]
        RD[("Redis :6379")]
        MG[("MongoDB :27017")]
        N4[("Neo4j :7687")]
        ES[("Elasticsearch :9200")]
    end
    U -->|"HTTPS JWT"| GW
    GW -->|"HTTPS client cert"| NX
    NX -->|"/lab1/"| L1
    NX -->|"/lab2/"| L2
    NX -->|"/lab3/"| L3
    GEN -->|"SQL"| PG
    GEN -->|"Redis cmd"| RD
    GEN -->|"Mongo Driver"| MG
    GEN -->|"Cypher"| N4
    GEN -->|"Bulk API"| ES
    L1 -->|"BM25 поиск"| ES
    L1 -->|"CTE top-10"| PG
    L1 -->|"HGETALL"| RD
    L2 -->|"Лекции+группы"| PG
    L2 -->|"Граф связей"| N4
    L2 -->|"Студенты"| RD
    L2 -->|"Иерархия вуза"| MG
    L3 -->|"Фильтр тегов"| ES
    L3 -->|"Обход графа"| N4
    L3 -->|"Посещаемость+часы"| PG`,

c4comp:`graph TB
    subgraph GW["API Gateway"]
        AUTH["OAuth2 Auth Module<br/>JWT HS256"]
        MTLS["mTLS Client<br/>ssl + httpx"]
        PROXY["Request Proxy<br/>FastAPI routes"]
        GPROXY["Generator Proxy<br/>httpx"]
        WUI["Web UI<br/>HTML/JS"]
    end
    subgraph NX["Nginx"]
        SSL["SSL Termination<br/>verify_client on"]
        ROUTE["Route Mapper<br/>/lab1 /lab2 /lab3"]
    end
    subgraph LB1["Lab1"]
        L1A["Token Verifier"]
        L1ES["ES Search<br/>BM25"]
        L1PG["PG CTE Query<br/>top-10"]
        L1R["Redis Cache<br/>HGETALL"]
    end
    subgraph LB2["Lab2"]
        L2A["Token Verifier"]
        L2PG["PG Batch Query"]
        L2N["Neo4j Traversal"]
        L2R["Redis Pipeline"]
        L2M["MongoDB Hierarchy"]
    end
    subgraph LB3["Lab3"]
        L3A["Token Verifier"]
        L3ES["ES Filter"]
        L3N["Neo4j Traversal"]
        L3PG["PG Attendance"]
    end
    subgraph GNC["Генератор"]
        GPG["PG Writer<br/>12 таблиц"]
        GES["ES Indexer"]
        GNN["Neo4j Builder"]
        GRR["Redis Writer"]
        GMM["MongoDB Builder"]
    end
    U(["Пользователь"])
    U -->|"POST /auth/token"| AUTH
    U -->|"POST /generator/generate"| GPROXY
    AUTH --> MTLS
    MTLS -->|"HTTPS + cert"| SSL
    SSL --> ROUTE
    ROUTE --> L1A
    ROUTE --> L2A
    ROUTE --> L3A
    L1A --> L1ES --> L1PG --> L1R
    L2A --> L2PG --> L2N --> L2R --> L2M
    L3A --> L3ES --> L3N --> L3PG
    GPG --> GES
    GPG --> GNN
    GPG --> GRR
    GPG --> GMM`,

dfd0:`graph LR
    U["Пользователь"] -->|"JWT-токен, параметры отчёта"| S["Полиглотная система управления учебным процессом"]
    S -->|"JSON-отчёт"| U`,

dfd1:`graph TB
    U["Пользователь"]
    A["1.0 Аутентификация OAuth2 JWT"]
    P["2.0 Проверка mTLS и проксирование nginx"]
    R1["3.1 ЛР1: Посещаемость по термину<br/>ES-PG-Redis"]
    R2["3.2 ЛР2: Нагрузка аудиторий<br/>PG-Neo4j-Redis-Mongo"]
    R3["3.3 ЛР3: Часы спец. дисциплин<br/>ES-Neo4j-PG"]
    PG[("PostgreSQL")]
    RD[("Redis")]
    MG[("MongoDB")]
    N4[("Neo4j")]
    ES[("Elasticsearch")]
    U -->|"логин/пароль"| A
    A -->|"service JWT + cert"| P
    P -->|"term, dates"| R1
    P -->|"semester, year, equip"| R2
    P -->|"group_name"| R3
    R1 -->|"полнотекстовый поиск"| ES
    ES -->|"lecture_ids"| R1
    R1 -->|"CTE top-10"| PG
    PG -->|"student rows"| R1
    R1 -->|"HGETALL"| RD
    RD -->|"student cache"| R1
    R2 -->|"lectures+groups"| PG
    PG -->|"course data"| R2
    R2 -->|"graph traversal"| N4
    N4 -->|"group links"| R2
    R2 -->|"HGETALL"| RD
    RD -->|"student details"| R2
    R2 -->|"findOne"| MG
    MG -->|"hierarchy"| R2
    R3 -->|"filter tags"| ES
    ES -->|"lecture_ids"| R3
    R3 -->|"graph traversal"| N4
    N4 -->|"student/schedule"| R3
    R3 -->|"attendance+hours"| PG
    PG -->|"attendance stats"| R3
    R1 -->|"JSON"| P
    R2 -->|"JSON"| P
    R3 -->|"JSON"| P
    P -->|"JSON"| A
    A -->|"JSON-отчёт"| U`,

er:`erDiagram
    University ||--o{ Institute : "1:N"
    Institute ||--o{ Department : "1:N"
    Department ||--o{ DeptSpecialty : "M:N"
    Speciality ||--o{ DeptSpecialty : "M:N"
    Speciality ||--o{ LectureCourse : "1:N"
    LectureCourse ||--o{ Lecture : "1:N"
    Lecture ||--o{ LectureMaterial : "1:N"
    Speciality ||--o{ StudentGroup : "1:N"
    StudentGroup ||--o{ Student : "1:N"
    Lecture ||--o{ Schedule : "1:N"
    StudentGroup ||--o{ Schedule : "1:N"
    Schedule ||--o{ Attendance : "1:N"
    Student ||--o{ Attendance : "1:N"
    University {
        uuid id PK
        varchar name UK
        varchar short_name
        text address
        int founded_year
    }
    Institute {
        uuid id PK
        uuid university_id FK
        varchar name
        varchar short_name
        varchar dean
    }
    Department {
        uuid id PK
        uuid institute_id FK
        varchar name
        varchar short_name
        varchar head
    }
    Speciality {
        uuid id PK
        varchar name
        varchar code
        varchar degree_level
        int duration_years
    }
    DeptSpecialty {
        uuid id PK
        uuid department_id FK
        uuid speciality_id FK
        boolean is_primary
    }
    LectureCourse {
        uuid id PK
        uuid speciality_id FK
        varchar name
        text description
        int semester
        int total_hours
        int lecture_hours
        int practice_hours
        int lab_hours
    }
    Lecture {
        uuid id PK
        uuid course_id FK
        varchar title
        text annotation
        varchar lecture_type
        int order_number
        int duration_minutes
        varchar equipment_req
        text tags
    }
    LectureMaterial {
        uuid id PK
        uuid lecture_id FK
        varchar content_type
        varchar title
        text content_text
        varchar file_url
        json metadata
    }
    StudentGroup {
        uuid id PK
        uuid speciality_id FK
        varchar name
        int enrollment_year
        varchar curator
    }
    Student {
        uuid id PK
        uuid group_id FK
        varchar first_name
        varchar last_name
        varchar patronymic
        varchar email
        varchar student_card_number
        date enrollment_date
        varchar status
    }
    Schedule {
        uuid id PK
        uuid lecture_id FK
        uuid group_id FK
        date scheduled_date
        date week_start_date
        time start_time
        time end_time
        varchar classroom
        varchar teacher_name
        varchar status
    }
    Attendance {
        uuid id PK
        uuid schedule_id FK
        uuid student_id FK
        date week_start_date
        timestamp marked_at
    }`
};

let diagramsRendered=false;
async function renderDiagrams(){
    if(diagramsRendered)return;
    try{
        await mermaid.initialize({startOnLoad:false,theme:'base',themeVariables:{primaryColor:'#3b82f6',primaryTextColor:'#1e293b',primaryBorderColor:'#94a3b8',lineColor:'#64748b',secondaryColor:'#f1f5f9',tertiaryColor:'#e2e8f0'}});
        const ids={c4ctx:'dia-c4ctx',c4cont:'dia-c4cont',c4comp:'dia-c4comp',dfd0:'dia-dfd0',dfd1:'dia-dfd1',er:'dia-er'};
        for(const[key,divId]of Object.entries(ids)){
            const el=document.getElementById(divId);
            if(!el||!DIAGRAMS[key])continue;
            try{
                const{svg}=await mermaid.render('mermaid-'+key,DIAGRAMS[key]);
                el.innerHTML=svg;
            }catch(err){
                el.innerHTML='<div style="color:#991b1b;font-size:12px;padding:8px">Ошибка рендеринга: '+err.message+'</div>';
            }
        }
        diagramsRendered=true;
    }catch(e){console.error('Mermaid init error:',e)}
}

checkStatus();
</script>
</body>
</html>"""
