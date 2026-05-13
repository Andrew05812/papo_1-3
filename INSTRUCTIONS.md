# Инструкции для запуска, проверки и защиты лабораторных работ

---

## 1. Запуск системы

### Предварительно
- Docker Desktop запущен (`docker ps` не выдаёт ошибку)
- Порты свободны: 8000, 443, 5432, 6379, 7474, 7687, 27017, 9200, 8010

### Запуск

```bash
# Полная пересборка (первый раз или после изменений в коде)
docker compose up -d --build

# Проверить что все 11 сервисов запущены
docker compose ps
```

Должно быть 11 сервисов в статусе Up/healthy:
- **5 БД**: postgres, elasticsearch, neo4j, redis, mongodb
- **cert-init**: exited (это нормально — он создаёт сертификаты и завершается)
- **nginx**: Up
- **generator**: Up
- **api-gateway**: Up
- **lab1, lab2, lab3**: Up

### Генерация данных

```bash
# Заполнить все 5 хранилищ данными (1000 студентов, ~1200 лекций, ~28000 посещений)
curl -X POST http://localhost:8010/generate

# Проверить что данные есть
curl http://localhost:8010/status
# → {"students": 1000, "courses": 120, "status": "ready"}

# Очистить все данные перед повторной генерацией
curl -X DELETE http://localhost:8010/clear

# Полная очистка (данные + Docker volumes + сертификаты)
docker compose down -v
```

---

## 2. Авторизация — пошагово

### Что происходит при авторизации

Система использует **упрощённую схему OAuth2** — токен выдаётся пользователю напрямую на руки (в классической схеме OAuth2 токен пользователю не даётся, но по ТЗ разрешено упрощение).

**Два типа JWT-токенов:**

| Тип | Кто получает | Что содержит | TTL | Куда используется |
|-----|-------------|-------------|-----|-------------------|
| user | Пользователь (через пароль) | `sub=username, type=user` | 24ч | Для доступа к маршрутам шлюза |
| service | Шлюз (автоматически) | `sub=gateway, type=service` | 1ч | Для доступа шлюза к лабам |

**Зачем два токена?** Defence in depth: пользовательский токен проверяется в шлюзе, сервисный — в лабе. Даже если кто-то перехватит user-токен, без service-токена лаба откажет.

### Получение пользовательского токена (password grant)

```bash
curl -X POST http://localhost:8000/auth/token \
  -d "grant_type=password&username=admin&password=admin123"
```

**Ответ:**
```json
{"access_token": "eyJhbGciOiJIUzI1NiIs...", "token_type": "Bearer", "expires_in": 86400}
```

**Что произошло:**
1. Пользователь отправил логин/пароль на `POST /auth/token`
2. Шлюз проверил логин/пароль в словаре `HARDCODED_USERS`
3. Шлюз создал JWT с payload `{sub: "admin", type: "user", iat: ..., exp: ...}`
4. Токен подписан ключом `JWT_SECRET` (алгоритм HS256)
5. Токен выдан пользователю — теперь он подставляет его в заголовок `Authorization: Bearer <token>`

Доступные пользователи: `admin/admin123`, `demo/demo123`, `test/test123`

### Что происходит при запросе к лабе

Когда пользователь вызывает, например, `/attendance/low?term=алгоритм`:

1. **Шлюз проверяет user JWT** — функция `verify_token()` декодирует токен, проверяет подпись и срок
2. **Шлюз создаёт service JWT** — `create_service_token()` генерирует токен с `type=service`
3. **Шлюз открывает mTLS-соединение** к nginx — загружает `client.crt` + `client.key`
4. **Отправляет HTTPS-запрос** к `https://nginx:443/lab1/query` с заголовком `Authorization: Bearer <service_token>`
5. **nginx проверяет клиентский сертификат** — `ssl_verify_client on`, если сертификат не подписан CA → 400
6. **nginx проксирует HTTP-запрос** к `http://lab1:8001/query`
7. **Lab1 проверяет service JWT** — `verify_service_token()`, если `type != service` → 403
8. **Lab1 выполняет запрос** к своим БД (ES → PG → Redis)
9. **Ответ идёт обратно**: Lab1 → nginx → шлюз → пользователь

---

## 3. mTLS — взаимная проверка сертификатов

### Кто создаёт сертификаты

Контейнер `cert-init` (alpine:3.19) при старте:
1. Генерирует **Root CA** (`ca.key` + `ca.crt`, CN="Polyglot Root CA")
2. Подписывает **серверный сертификат** (`server.key` + `server.crt`, CN="nginx") — для nginx
3. Подписывает **клиентский сертификат** (`client.key` + `client.crt`, CN="gateway") — для шлюза
4. Все сертификаты RSA 2048, действительны 365 дней
5. Лежат в Docker volume `certs`

### Как работает взаимная проверка

```
┌────────────┐                        ┌────────────┐                    ┌──────────┐
│ API Gateway│   1. HTTPS-запрос      │    Nginx    │   3. HTTP-запрос  │Lab Service│
│ (клиент)   │───────────────────────▶│  (сервер)  │──────────────────▶│          │
│            │                        │            │                   │          │
│ Предъявляет│   client.crt           │ Проверяет   │  service JWT      │Проверяет │
│ client.crt │──────────────▶         │ client.crt │  в заголовке      │type=svc  │
│            │                        │            │                   │          │
│ Проверяет  │   server.crt           │ Предъявляет│                   │          │
│ server.crt │◀──────────────         │ server.crt │                   │          │
└────────────┘                        └────────────┘                    └──────────┘
```

**Шлюз → nginx**: шлюз проверяет что `server.crt` подписан `ca.crt` (чтобы не подключиться к подделке)
**nginx → шлюз**: nginx проверяет что `client.crt` подписан `ca.crt` (чтобы не пустить чужого)

Это **взаимная проверка** (mutual TLS), поэтому `ssl_verify_client on` в nginx и `ctx.verify_mode = ssl.CERT_REQUIRED` в шлюзе.

### Проверка mTLS вручную

```bash
# Без сертификата — nginx вернёт 400
curl -k https://localhost:443/lab1/query

# С сертификатом — но без JWT — лаба вернёт 401/403
curl -k --cert scripts/client.crt --key scripts/client.key https://localhost:443/lab1/query
```

---

## 4. Выполнение лабораторных запросов

### Получить токен и выполнить запросы

```bash
# 1. Получить токен
TOKEN=$(curl -s -X POST http://localhost:8000/auth/token \
  -d "grant_type=password&username=admin&password=admin123" \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 2. ЛР1: 10 студентов с минимальным % посещения лекций с термином "алгоритм"
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/attendance/low?term=%D0%B0%D0%BB%D0%B3%D0%BE%D1%80%D0%B8%D1%82%D0%BC&start_date=2025-09-01&end_date=2026-01-31"

# 3. ЛР2: Необходимый объём аудитории для семестра 1 года 2025
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/schedule/capacity?semester=1&year=2025"

# 4. ЛР3: Часы по спец. дисциплинам для группы "Группа-001"
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/hours/report?group_name=%D0%93%D1%80%D1%83%D0%BF%D0%BF%D0%B0-001"
```

### Через Web UI

1. Открыть `http://localhost:8000` в браузере
2. Ввести логин `admin` / пароль `admin123` → нажать «Войти»
3. Нажать «Сгенерировать данные» → дождаться счётчиков
4. Переключаться между вкладками ЛР1/ЛР2/ЛР3, вводить параметры, нажимать «Выполнить»
5. Результат включает пошаговое описание каждого этапа (какая БД, что делается, сколько данных)

---

## 5. Как рассказывать на защите

### Общая схема (рассказывать первым)

«Система состоит из 11 Docker-контейнеров: 5 баз данных (PostgreSQL, Elasticsearch, Neo4j, Redis, MongoDB), контейнер генерации сертификатов, nginx-прокси, генератор данных, клиентский контейнер (API Gateway) и 3 контейнера лабораторных сервисов.

Пользователь обращается к API Gateway, аутентифицируется по OAuth2 — получает JWT-токен на руки. Шлюз проверяет токен и проксирует запрос к nginx по HTTPS с клиентским сертификатом (mTLS — взаимная проверка). Nginx проверяет клиентский сертификат, снимает TLS и проксирует HTTP-запрос к лабораторному сервису. Лабораторный сервис проверяет сервисный JWT и выполняет запрос к своим базам данных.»

### mTLS (показать логи)

```bash
docker compose logs nginx --tail 5
```

«Вот в логах nginx видно, что запрос пришёл от API Gateway (client: 172.x.x.x) по HTTPS. Это значит что mTLS-рукопожатие прошло успешно — nginx проверил клиентский сертификат gateway'я и пропустил запрос. Если бы сертификата не было — nginx вернул бы 400.»

### OAuth2 (показать получение токена)

«У нас упрощённая схема OAuth2 — пользователь вводит логин/пароль, получает JWT на руки. В стандартной схеме токен пользователю не выдаётся, но по ТЗ разрешено упрощение. Шлюз поддерживает два grant type: password (для пользователей) и client_credentials (для сервисов). При каждом запросе к лабе шлюз автоматически создаёт сервисный JWT с type=service — лабы пропускают только такие токены.»

### ЛР1 — подробно

**Задание**: «10 студентов с минимальным процентом посещения лекций, содержащих заданный термин или фразу, за определённый период. Состав полей: полная информация о студенте, процент посещения, период отчёта, термин в занятиях курса.»

**Рассказывать так:**

«Запрос идёт по трём хранилищам: Elasticsearch → PostgreSQL → Redis.

**Шаг 1 — Elasticsearch.** Мы ищем термин в индексе "lectures". Используем полнотекстовый поиск BM25 с fuzziness AUTO и кастомным анализатором russian_custom (standard tokenizer → lowercase → стоп-слова → стеммер). Это быстрее и точнее чем LIKE в PostgreSQL. Получаем список lecture_id.

**Шаг 2 — PostgreSQL.** По этим lecture_id находим расписание в заданном периоде, студентов в соответствующих группах и их посещаемость. Используем CTE MATERIALIZED с LIMIT 10 — PostgreSQL выполняет heapsort O(N·log10) вместо полной сортировки. Таблица attendance партиционирована по week_start_date, поэтому partition pruning отсекает ненужные партиции. Batch-запрос через ANY(%s::uuid[]) вместо построчных.

**Шаг 3 — Redis.** Для топ-10 студентов проверяем кэш — pipeline HGETALL student:{uuid}. При промахе заполняем из данных PostgreSQL. TTL 2 часа — кэш автоматически очищается.»

### ЛР2 — подробно

**Задание**: «Необходимый объём аудитории для проведения занятий по курсу заданного семестра и года обучения с требованиями к использованию технических средств. Результат: полная информация о курсе, лекции и количестве слушателей.»

**Рассказывать так:**

«Запрос идёт по четырём хранилищам: PostgreSQL → Neo4j → Redis → MongoDB.

**Шаг 1 — PostgreSQL.** Фильтруем лекции по семестру, типу "лекция" и требованиям к оборудованию. Находим расписание за указанный год. Считаем количество студентов в каждой группе.

**Шаг 2 — Neo4j.** Обходим граф: от найденных лекций через BELONGS_TO к курсам, через PART_OF к расписанию, через CONTAINS к группам. Это сужает множество групп — мы запрашиваем Redis только для групп из расписания, а не для всех групп курса.

**Шаг 3 — Redis.** Pipeline HGETALL для студентов из Neo4j-групп, batch=2000. При промахе — fallback к PostgreSQL с заполнением кэша.

**Шаг 4 — MongoDB.** Один findOne — загружает вложенный документ University→Institutes→Departments→Specialities. Это вместо 4 JOIN в PostgreSQL — один запрос вместо четырёх.»

### ЛР3 — подробно

**Задание**: «Отчёт по заданной группе учащихся с указанием объёма прослушанных часов лекций и необходимого объёма запланированных часов. Одна лекция = 2 академических часа. Только лекции с тегом специальной дисциплины кафедры. Результат: полная информация о группе, студенте, курсе, запланированных и посещённых часах.»

**Рассказывать так:**

«Запрос идёт по трём хранилищам: Elasticsearch → Neo4j → PostgreSQL.

**Шаг 0 — PostgreSQL.** Пользователь вводит название группы (например "Группа-001"). Сначала lookup — находим UUID группы по имени.

**Шаг 1 — Elasticsearch.** Фильтруем лекции по тегам специальной дисциплины (спецдисциплина, кафедральная_дисциплина, профильная_дисциплина и т.д.) + lecture_type=лекция. Это terms query на keyword-поле — точная фильтрация, не полнотекстовый поиск.

**Шаг 2 — Neo4j.** Обходим граф от одной стартовой группы: Student-[MEMBER_OF]->Group-[CONTAINS]->Schedule-[PART_OF]->Lecture-[BELONGS_TO]->Course, где Lecture.id входит в список из ES. Получаем: для каждого студента — какие курсы спец. дисциплин и какие занятия.

**Шаг 3 — PostgreSQL.** Batch ANY(%s::uuid[]) для посещаемости, planned hours из lecture_course.ute_hours, student details. Считаем: attended_hours = attended_count × 2 (одна лекция = 2 ак.ч.). Hierarchy JOIN для институт/кафедра.»

### Что показать преподу

1. **Web UI** (`http://localhost:8000`) — авторизация, генерация, выполнение запросов
2. **Ответ с пошаговым описанием** — каждый шаг показывает: хранилище, действие, результат
3. **Логи nginx** — `docker compose logs nginx --tail 10` — видно mTLS-соединения
4. **Логи gateway** — `docker compose logs api-gateway --tail 10` — видно создание service-токена и mTLS-запросы
5. **Схемы C4 + DFD** — в папке `Схемы/` (PlantUML, рендерить через plantuml.com)

---

## 6. Структура данных (для ответов на вопросы)

### PostgreSQL — 12 таблиц

| Таблица | Поля | Особенности |
|---------|------|-------------|
| university | id, name(V500), short_name, address, founded_year | |
| institute | id, university_id FK, name(V500), short_name, dean | name = VARCHAR(500) |
| department | id, institute_id FK, name(V500), short_name, head | name = VARCHAR(500) |
| speciality | id, name(V500), code, degree_level, duration_years | |
| department_specialities | id, department_id FK, speciality_id FK, is_primary | Junction M:N |
| lecture_course | id, speciality_id FK, name(V500), description, semester, total/lecture/practice/lab_hours | |
| lecture | id, course_id FK, title(V500), annotation, lecture_type, **order_number**, duration_minutes, **equipment_req**(V200), **tags**(TEXT[]) | order_number не order; equipment_req + tags для ЛР2/3 |
| lecture_material | id, lecture_id FK, content_type, title, content_text, file_url, metadata(JSONB) | content_text → ES |
| student_group | id, speciality_id FK, name(V50), enrollment_year, curator | |
| student | id, group_id FK, first_name, last_name, patronymic, email, student_card_number, enrollment_date, status | |
| schedule | id, lecture_id FK, group_id FK, scheduled_date, week_start_date, start_time, end_time, classroom, teacher_name, **status**='scheduled' | |
| attendance | id, schedule_id(**no FK**), student_id(**no FK**), week_start_date(**partition key**), marked_at | PK(id, week_start_date), PARTITION BY RANGE, 4 партиции 2025Q3–2026Q2 |

### Neo4j — 5 типов узлов, 5 типов связей

| Узел | Свойства |
|------|----------|
| Student | id, name, card_number |
| StudentGroup | id, name |
| Schedule | id, date, time, classroom |
| Lecture | id, title, type |
| LectureCourse | id, name, semester |

| Связь | Направление | Описание |
|-------|-------------|----------|
| MEMBER_OF | Student → StudentGroup | Студент состоит в группе |
| SHOULD_ATTEND | Student → Schedule | Студент должен присутствовать |
| CONTAINS | StudentGroup → Schedule | Группа имеет занятие |
| PART_OF | Schedule → Lecture | Занятие = часть лекции |
| BELONGS_TO | Lecture → LectureCourse | Лекция относится к курсу |

### Redis — только студенты

- Ключ: `student:{uuid}`, тип Hash, TTL=7200с
- Поля: first_name, last_name, patronymic, email, student_card_number, group_id, status, enrollment_date
- Групп в Redis нет

### MongoDB — иерархия университета

Один документ: University → Institutes[] → Departments[] → Specialities[]

### Elasticsearch — индекс "lectures"

- Поля: lecture_id, course_id, course_name, title, annotation, content_text, lecture_type(keyword), tags(keyword), equipment_req, semester
- Анализатор `russian_custom`: standard → lowercase → russian_stop → russian_stemmer
- text-поля с russian_custom (полнотекстовый поиск), keyword-поля для точной фильтрации

---

## 7. Контейнеры — кто за что отвечает

| Контейнер | Порт | Роль |
|-----------|------|------|
| postgres | 5432 | Master БД — все 12 таблиц, attendance партиционирована |
| elasticsearch | 9200 | Полнотекстовый поиск лекций |
| neo4j | 7687 | Граф связей студент–группа–расписание–лекция |
| redis | 6379 | Кэш данных студентов (Hash, TTL=2ч) |
| mongodb | 27017 | Иерархия университета (вложенный документ) |
| cert-init | — | Создаёт CA + server + client сертификаты (завершается) |
| nginx | 443 | mTLS-прокси: проверяет client cert, проксирует к лабам |
| generator | 8010 | Заполняет все 5 БД напрямую |
| api-gateway | 8000 | OAuth2 + mTLS-клиент + проксирование + Web UI |
| lab1 | 8001 | ЛР1: ES → PG → Redis |
| lab2 | 8002 | ЛР2: PG → Neo4j → Redis → MongoDB |
| lab3 | 8003 | ЛР3: ES → Neo4j → PG |

---

## 8. Быстрая шпаргалка

```bash
# Запуск
docker compose up -d --build

# Генерация
curl -X POST http://localhost:8010/generate

# Токен
TOKEN=$(curl -s -X POST http://localhost:8000/auth/token -d "grant_type=password&username=admin&password=admin123" | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# ЛР1: термин "алгоритм" за осенний семестр 2025
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8000/attendance/low?term=%D0%B0%D0%BB%D0%B3%D0%BE%D1%80%D0%B8%D1%82%D0%BC&start_date=2025-09-01&end_date=2026-01-31"

# ЛР2: семестр 1, год 2025
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8000/schedule/capacity?semester=1&year=2025"

# ЛР3: группа "Группа-001"
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8000/hours/report?group_name=%D0%93%D1%80%D1%83%D0%BF%D0%BF%D0%B0-001"

# Логи
docker compose logs nginx --tail 10
docker compose logs api-gateway --tail 10

# Очистка
docker compose down -v
```
