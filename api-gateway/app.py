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
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
import jwt
import httpx
import ssl
import os
import logging
from datetime import datetime, timedelta
from urllib.parse import quote

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="API Gateway - OAuth2 + mTLS", docs_url="/docs")

JWT_SECRET = os.environ.get("JWT_SECRET", "polyglot_jwt_secret_key_2026")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")

NGINX_URL = os.environ.get("NGINX_URL", "https://nginx:443")
GENERATOR_URL = os.environ.get("GENERATOR_URL", "http://generator:8010")

CERT_CA = os.environ.get("CERT_CA", "/certs/ca.crt")
CERT_CLIENT_CRT = os.environ.get("CERT_CLIENT_CRT", "/certs/client.crt")
CERT_CLIENT_KEY = os.environ.get("CERT_CLIENT_KEY", "/certs/client.key")

HARDCODED_USERS = {
    "admin": "admin123",
    "demo": "demo123",
    "test": "test123",
}

SERVICE_CLIENTS = {
    "lab1-service": "lab1-secret",
    "lab2-service": "lab2-secret",
    "lab3-service": "lab3-secret",
}

security = HTTPBearer()


def create_jwt_token(sub: str, token_type: str = "user", ttl_hours: int = 24) -> str:
    payload = {
        "sub": sub,
        "type": token_type,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=ttl_hours),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_service_token() -> str:
    return create_jwt_token("gateway", token_type="service", ttl_hours=1)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_mtls_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=CERT_CA)
    ctx.load_cert_chain(certfile=CERT_CLIENT_CRT, keyfile=CERT_CLIENT_KEY)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def get_httpx_client() -> httpx.AsyncClient:
    try:
        ssl_ctx = get_mtls_ssl_context()
        return httpx.AsyncClient(verify=ssl_ctx, timeout=httpx.Timeout(120.0))
    except Exception as e:
        logger.warning(f"mTLS context failed, falling back to default: {e}")
        return httpx.AsyncClient(verify=False, timeout=httpx.Timeout(120.0))


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


@app.post("/auth/login")
async def auth_login_legacy(request: Request):
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")
    if username not in HARDCODED_USERS or HARDCODED_USERS[username] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_jwt_token(username, token_type="user", ttl_hours=24)
    return {"access_token": token, "token_type": "Bearer", "expires_in": 86400}


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


@app.get("/attendance/low")
async def lab1_query(term: str, start_date: str, end_date: str, _=Depends(verify_token)):
    return await call_lab("/lab1/query", {"term": term, "start_date": start_date, "end_date": end_date})


@app.get("/schedule/capacity")
async def lab2_query(semester: int, year: int, equipment: str = "", _=Depends(verify_token)):
    return await call_lab("/lab2/query", {"semester": semester, "year": year, "equipment": equipment})


@app.get("/hours/report")
async def lab3_query(group_name: str, _=Depends(verify_token)):
    return await call_lab("/lab3/query", {"group_name": group_name})


@app.post("/generator/generate")
async def generate_data(_=Depends(verify_token)):
    return await call_generator("POST", "/generate")


@app.delete("/generator/clear")
async def clear_data(_=Depends(verify_token)):
    return await call_generator("DELETE", "/clear")


@app.get("/generator/status")
async def generator_status():
    return await call_generator("GET", "/status")


@app.get("/groups")
async def list_groups(_=Depends(verify_token)):
    return await call_generator("GET", "/groups")


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
                <label>Термин/фраза</label><input id="lab1-term" value="mikroprocessorov"/>
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
                <label>Оборудование</label><input id="lab2-equipment" value="proektor"/>
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
                    <div class="auth-step st-user"><div class="anum">A</div><div><div class="atxt">Пользователь отправляет запрос с user JWT</div><div class="adet">GET /hours/report?group_name=Gruppa-001 + Bearer token</div></div></div>
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
                <input id="lab3-group" value="Gruppa-001" style="max-width:200px"/>
                <button class="btn-blue" onclick="runLab3()">Выполнить</button>
            </div>
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
        const labels={university:'Университет',institutes:'Институты',departments:'Кафедры',specialities:'Специальности',department_specialities:'Kaf.<->Spec.',lecture_courses:'Курсы',lectures:'Лекции',lecture_materials:'Материалы',student_groups:'Группы',students:'Студенты',schedule:'Расписание',attendance:'Посещения'};
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
}

checkStatus();
</script>
</body>
</html>"""
