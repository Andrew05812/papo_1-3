"""
Модуль generator.py — основная логика генератора тестовых данных.

Заполняет 5 хранилищ:
  • PostgreSQL — 12 таблиц, включая партиционированную таблицу attendance
  • Elasticsearch — индекс lectures с анализатором russian_custom
  • Neo4j — 5 типов узлов (Student, StudentGroup, Schedule, Lecture, LectureCourse)
            и 6 типов связей (MEMBER_OF, CONTAINS, PART_OF, BELONGS_TO, SHOULD_ATTEND, ATTENDED)
  • Redis     — кэш студентов в Hash-ключах student:{uuid} с TTL=2 ч (7200 с)
  • MongoDB   — вложенный документ иерархии University→Institutes→Departments→Specialities
"""
# psycopg2: драйвер PostgreSQL — master-источник всех сущностей (12 таблиц + partitioned attendance)
import psycopg2
# execute_values: batch-вставка строк (по 500) вместо отдельных INSERT — в 10-100 раз быстрее
from psycopg2.extras import execute_values
# Elasticsearch + helpers: полнотекстовый индекс lectures (BM25, russian_custom анализатор, bulk-индексация)
from elasticsearch import Elasticsearch, helpers
# Neo4j GraphDatabase: граф связей студент↔группа↔расписание↔лекция↔курс (5 узлов, 6 связей)
from neo4j import GraphDatabase
# redis: кэш данных студентов (Hash student:{uuid}, TTL=7200с, pipeline-вставка)
import redis
# pymongo: MongoClient для вложенного документа иерархии университета (findOne O(1))
from pymongo import MongoClient
# bson.ObjectId: работа с MongoDB _id (в текущей генерации используется str(university_id))
from bson import ObjectId
# uuid: генерация UUID v4 для всех первичных ключей (совместимость с PostgreSQL UUID-типом)
import uuid
# random: стохастическая генерация данных (посещаемость 50-95%, теги 30%, оборудование 40%)
import random
# hashlib: зарезервировано для хеширования (в текущей версии не используется)
import hashlib
# date, time, datetime, timedelta: работа с датами расписания и посещаемости
from datetime import date, time, datetime, timedelta
# Optional: аннотации типов для функций (в текущей версии не используется активно)
from typing import Optional
# logging: протоколирование процесса генерации (INFO-уровень)
import logging
# os: чтение переменных окружения для конфигурации подключений к 5 БД
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Мужские имена для генерации тестовых данных студентов
FIRST_NAMES_M = [
    "Александр", "Дмитрий", "Максим", "Сергей", "Андрей", "Алексей", "Артём",
    "Илья", "Кирилл", "Михаил", "Никита", "Матвей", "Роман", "Егор", "Арсений",
    "Иван", "Денис", "Евгений", "Даниил", "Тимофей", "Владислав", "Игорь",
    "Владимир", "Павел", "Руслан", "Марк", "Константин", "Тимур", "Олег", "Ярослав"
]
# Женские имена
FIRST_NAMES_F = [
    "Анастасия", "Мария", "Дарья", "Елена", "Анна", "Виктория", "Екатерина",
    "Алина", "Ирина", "Полина", "Ольга", "Татьяна", "Ксения", "Валерия", "Софья",
    "Юлия", "Марина", "Людмила", "Наталья", "Светлана", "Елизавета", "Вероника",
    "Александра", "Мирослава", "Варвара", "Диана", "Кристина", "Надежда", "Оксана", "Евгения"
]
# Мужские фамилии
LAST_NAMES_M = [
    "Иванов", "Смирнов", "Кузнецов", "Попов", "Васильев", "Петров", "Соколов",
    "Михайлов", "Новиков", "Фёдоров", "Морозов", "Волков", "Алексеев", "Лебедев",
    "Семёнов", "Егоров", "Павлов", "Козлов", "Степанов", "Николаев", "Орлов",
    "Андреев", "Макаров", "Никитов", "Захаров", "Зайцев", "Соловьёв", "Борисов",
    "Яковлев", "Григорьев"
]
# Женские фамилии
LAST_NAMES_F = [
    "Иванова", "Смирнова", "Кузнецова", "Попова", "Васильева", "Петрова", "Соколова",
    "Михайлова", "Новикова", "Фёдорова", "Морозова", "Волкова", "Алексеева", "Лебедева",
    "Семёнова", "Егорова", "Павлова", "Козлова", "Степанова", "Николаева", "Орлова",
    "Андреева", "Макарова", "Никитина", "Захарова", "Зайцева", "Соловьёва", "Борисова",
    "Яковлева", "Григорьева"
]
# Мужские отчества
PATRONYMICS_M = [
    "Александрович", "Дмитриевич", "Сергеевич", "Андреевич", "Алексеевич",
    "Михайлович", "Владимирович", "Игоревич", "Николаевич", "Евгеньевич",
    "Павлович", "Иванович", "Олегович", "Романович", "Кириллович"
]
# Женские отчества
PATRONYMICS_F = [
    "Александровна", "Дмитриевна", "Сергеевна", "Андреевна", "Алексеевна",
    "Михайловна", "Владимировна", "Игоревна", "Николаевна", "Евгеньевна",
    "Павловна", "Ивановна", "Олеговна", "Романовна", "Кирилловна"
]

# 5 институтов университета (справочник)
INSTITUTES = [
    {"name": "Институт информационных технологий", "short": "ИИТ", "dean": "Петров П.П."},
    {"name": "Институт радиотехнических систем", "short": "ИРТС", "dean": "Сидоров С.С."},
    {"name": "Институт компьютерных технологий", "short": "ИКТ", "dean": "Козлов К.К."},
    {"name": "Институт кибербезопасности", "short": "ИКБ", "dean": "Волков В.В."},
    {"name": "Институт перспективных технологий и индустрии", "short": "ИПТИ", "dean": "Морозов М.М."},
]

# 15 кафедр (inst — индекс института в массиве INSTITUTES)
DEPARTMENTS = [
    {"name": "Кафедра программной инженерии", "short": "КПИ", "head": "Белов Б.Б.", "inst": 0},
    {"name": "Кафедра информационных систем", "short": "КИС", "head": "Громов Г.Г.", "inst": 0},
    {"name": "Кафедра вычислительной техники", "short": "КВТ", "head": "Орлов О.О.", "inst": 0},
    {"name": "Кафедра радиотехники", "short": "КРТ", "head": "Лебедев Л.Л.", "inst": 1},
    {"name": "Кафедра телекоммуникаций", "short": "КТел", "head": "Соколов С.С.", "inst": 1},
    {"name": "Кафедра сигнальных систем", "short": "КСС", "head": "Зайцев З.З.", "inst": 1},
    {"name": "Кафедра искусственного интеллекта", "short": "КИИ", "head": "Мишин М.М.", "inst": 2},
    {"name": "Кафедра системного анализа", "short": "КСА", "head": "Воронов В.В.", "inst": 2},
    {"name": "Кафедра машинного обучения", "short": "КМО", "head": "Фролов Ф.Ф.", "inst": 2},
    {"name": "Кафедра информационной безопасности", "short": "КИБ", "head": "Крутов К.К.", "inst": 3},
    {"name": "Кафедра криптографии", "short": "ККрипт", "head": "Жуков Ж.Ж.", "inst": 3},
    {"name": "Кафедра сетевой безопасности", "short": "КСБ", "head": "Громов Г.Г.", "inst": 3},
    {"name": "Кафедра нанотехнологий", "short": "КНТ", "head": "Титов Т.Т.", "inst": 4},
    {"name": "Кафедра биотехнологий", "short": "КБТ", "head": "Лисов Л.Л.", "inst": 4},
    {"name": "Кафедра оптоэлектроники", "short": "КОЭ", "head": "Медведев М.М.", "inst": 4},
]

# 30 специальностей с кодами, уровнем и длительностью обучения
SPECIALITIES = [
    {"name": "Программная инженерия", "code": "09.03.04", "degree": "бакалавр", "duration": 4},
    {"name": "Информационные системы и технологии", "code": "09.03.02", "degree": "бакалавр", "duration": 4},
    {"name": "Вычислительные машины, комплексы и системы", "code": "09.03.01", "degree": "бакалавр", "duration": 4},
    {"name": "Радиотехника", "code": "11.03.01", "degree": "бакалавр", "duration": 4},
    {"name": "Инфокоммуникационные технологии и системы связи", "code": "11.03.02", "degree": "бакалавр", "duration": 4},
    {"name": "Конструирование и технология электронных средств", "code": "11.03.03", "degree": "бакалавр", "duration": 4},
    {"name": "Интеллектуальные системы в гуманитарной сфере", "code": "09.03.03", "degree": "бакалавр", "duration": 4},
    {"name": "Прикладная информатика", "code": "09.03.03", "degree": "бакалавр", "duration": 4},
    {"name": "Математическое обеспечение и администрирование информационных систем", "code": "09.03.03", "degree": "бакалавр", "duration": 4},
    {"name": "Информационная безопасность автоматизированных систем", "code": "10.03.01", "degree": "бакалавр", "duration": 4},
    {"name": "Информационная безопасность", "code": "10.05.01", "degree": "специалист", "duration": 5},
    {"name": "Криптография и кибербезопасность", "code": "10.05.02", "degree": "специалист", "duration": 5},
    {"name": "Нанотехнологии и микросистемная техника", "code": "28.03.01", "degree": "бакалавр", "duration": 4},
    {"name": "Биотехнология", "code": "19.03.01", "degree": "бакалавр", "duration": 4},
    {"name": "Оптотехника", "code": "12.03.02", "degree": "бакалавр", "duration": 4},
    {"name": "Компьютерные науки", "code": "09.03.04", "degree": "бакалавр", "duration": 4},
    {"name": "Сетевая безопасность", "code": "10.03.02", "degree": "бакалавр", "duration": 4},
    {"name": "Системный анализ и управление", "code": "27.03.03", "degree": "бакалавр", "duration": 4},
    {"name": "Машинное обучение и data science", "code": "09.03.04", "degree": "бакалавр", "duration": 4},
    {"name": "Телекоммуникационные системы", "code": "11.03.02", "degree": "бакалавр", "duration": 4},
    {"name": "Программирование и алгоритмика", "code": "09.03.04", "degree": "бакалавр", "duration": 4},
    {"name": "Кибернетика", "code": "09.03.01", "degree": "бакалавр", "duration": 4},
    {"name": "Электроника и наноэлектроника", "code": "11.03.04", "degree": "бакалавр", "duration": 4},
    {"name": "Биоинформатика", "code": "19.03.01", "degree": "бакалавр", "duration": 4},
    {"name": "Инженерия программного обеспечения", "code": "09.03.04", "degree": "бакалавр", "duration": 4},
    {"name": "Анализ данных", "code": "09.03.04", "degree": "бакалавр", "duration": 4},
    {"name": "Защита информации", "code": "10.03.01", "degree": "бакалавр", "duration": 4},
    {"name": "Робототехника", "code": "09.03.04", "degree": "бакалавр", "duration": 4},
    {"name": "Цифровая обработка сигналов", "code": "11.03.01", "degree": "бакалавр", "duration": 4},
    {"name": "Архитектура вычислительных систем", "code": "09.03.01", "degree": "бакалавр", "duration": 4},
]

# Названия 60 учебных курсов
COURSE_NAMES = [
    "Основы программирования", "Алгоритмы и структуры данных", "Базы данных",
    "Операционные системы", "Компьютерные сети", "Дискретная математика",
    "Математический анализ", "Линейная алгебра", "Теория вероятностей",
    "Объектно-ориентированное программирование", "Функциональное программирование",
    "Веб-технологии", "Мобильная разработка", "Проектирование информационных систем",
    "Интеллектуальные системы", "Машинное обучение", "Нейронные сети",
    "Компьютерная графика", "Обработка изображений", "Робототехника",
    "Информационная безопасность", "Криптография", "Сетевая безопасность",
    "Системное программирование", "Параллельные вычисления", "Распределённые системы",
    "Архитектура ЭВМ", "Микропроцессорные системы", "Цифровая обработка сигналов",
    "Радиотехнические цепи и сигналы", "Теория электрических цепей",
    "Электроника", "Схемотехника", "Телекоммуникационные технологии",
    "Оптоволоконные системы связи", "Антенные системы", "Распространение радиоволн",
    "Наноматериалы", "Биоинформатика", "Оптоэлектронные приборы",
    "Квантовые вычисления", "Блокчейн-технологии", "DevOps и CI/CD",
    "Data Engineering", "Big Data", "Облачные технологии",
    "Интернет вещей", "Кибербезопасность", "Цифровая трансформация",
    "Программная инженерия", "Управление проектами", "Системный анализ",
    "Математическое моделирование", "Численные методы", "Статистика",
    "Физика", "Прикладная механика", "Экология",
    "Философия", "История", "Иностранный язык",
    "Правоведение", "Экономика", "Менеджмент",
]

# Типы компьютерного обеспечения
COMPUTER_TYPES = [
    "проектор", "компьютерный класс", "интерактивная доска", "лабораторное оборудование",
    "микроконтроллеры", "осциллограф", "мультимедийный проектор", "документ-камера",
    "система видеоконференцсвязи", "VR-оборудование", "серверное оборудование",
    "сетевое оборудование", "3D-принтер", "робототехнический комплект",
    "плата Arduino", "плата Raspberry Pi", "GPU-ускоритель", "кластер HPC",
]

# Типы занятий: лекция, практика, лабораторная
LECTURE_TYPES = ["лекция", "практика", "лабораторная"]

# Описания курсов (для лекций с подробным содержанием)
COURSE_DESCRIPTIONS = {
    "Основы программирования": "Изучение базовых принципов программирования на языках высокого уровня. Переменные, типы данных, операторы, циклы, функции. Введение в алгоритмику.",
    "Алгоритмы и структуры данных": "Классические алгоритмы сортировки, поиска, графовые алгоритмы. Структуры данных: списки, деревья, хеш-таблицы, графы.",
    "Базы данных": "Реляционные модели данных, SQL, проектирование баз данных, нормализация, индексирование, транзакции.",
    "Операционные системы": "Архитектура ОС, управление процессами, памятью, файловыми системами. Linux, Windows Server.",
    "Компьютерные сети": "Модель OSI, TCP/IP, маршрутизация, коммутация, протоколы прикладного уровня, сетевая безопасность.",
    "Машинное обучение": "Методы обучения с учителем и без учителя. Регрессия, классификация, кластеризация, нейронные сети.",
    "Нейронные сети": "Архитектуры нейронных сетей: CNN, RNN, Transformer. Обучение, регуляризация, оптимизация.",
    "Информационная безопасность": "Угрозы информационной безопасности, методы защиты, криптографические протоколы, аутентификация.",
    "Микропроцессорные системы": "Архитектура микропроцессоров, система команд, прерывания, периферийные устройства, встраиваемые системы.",
    "Криптография": "Симметричное и асимметричное шифрование, хеш-функции, цифровые подписи, протоколы TLS/SSL.",
}

# Шаблоны аннотаций лекций
LECTURE_ANNOTATIONS = [
    "Введение в предметную область. Основные понятия и определения.",
    "Обзор литературы и источников. Методология исследования.",
    "Классификация и систематизация материала. Базовые концепции.",
    "Практическое применение теоретических знаний. Разбор примеров.",
    "Анализ современных подходов и методов. Сравнительный обзор.",
    "Углублённое изучение ключевых аспектов. Расширенный анализ.",
    "Решение типовых задач. Практические задания и упражнения.",
    "Обзор инструментальных средств. Среды разработки и отладки.",
    "Проектирование и моделирование. Архитектурные паттерны.",
    "Тестирование и верификация. Методы контроля качества.",
    "Оптимизация и масштабирование. Производительность систем.",
    "Интеграция и развёртывание. DevOps-практики.",
]

# Шаблоны текстов материалов лекций ({topic} — подставляется тема)
LECTURE_CONTENT_TEMPLATES = [
    "Рассматриваются принципы работы {topic}. Основные характеристики и параметры. Примеры использования в реальных системах. Методы анализа и синтеза.",
    "Изучение методов {topic}. Теоретические основы и практическое применение. Алгоритмы реализации и оптимизации. Современные тенденции развития.",
    "Анализ архитектуры {topic}. Компоненты и их взаимодействие. Проектирование и отладка. Инструменты разработки и тестирования.",
    "Обзор технологий {topic}. Сравнение подходов и решений. Критерии выбора и оценки. Перспективы развития и применения.",
    "Практикум по {topic}. Пошаговое выполнение заданий. Типичные ошибки и способы их устранения. Рекомендации по улучшению.",
]

# Теги специальных дисциплин для фильтрации в ЛР3
SPECIAL_TAGS = [
    "спецдисциплина", "кафедральная_дисциплина", "профильная_дисциплина",
    "дисциплина_кафедры", "специализация"
]

# Номера аудиторий
CLASSROOMS = [
    "А-101", "А-102", "А-201", "А-202", "А-301", "А-302",
    "Б-101", "Б-102", "Б-201", "Б-202", "Б-301", "Б-302",
    "В-101", "В-102", "В-201", "В-202", "В-301", "В-302",
    "ИВЦ-101", "ИВЦ-102", "ИВЦ-201", "ИВЦ-202", "ИВЦ-301", "ИВЦ-302",
    "К-101", "К-102", "К-201", "К-202", "К-301", "К-302",
]

# ФИО преподавателей
TEACHER_NAMES = [
    "Проф. Иванов И.И.", "Доц. Петров П.П.", "Доц. Сидоров С.С.",
    "Проф. Козлов К.К.", "Доц. Волков В.В.", "Проф. Морозов М.М.",
    "Доц. Лебедев Л.Л.", "Проф. Соколов С.С.", "Доц. Зайцев З.З.",
    "Проф. Орлов О.О.", "Доц. Макаров М.М.", "Проф. Белов Б.Б.",
    "Доц. Громов Г.Г.", "Проф. Мишин М.М.", "Доц. Фролов Ф.Ф.",
    "Проф. Крутов К.К.", "Доц. Жуков Ж.Ж.", "Проф. Титов Т.Т.",
    "Доц. Лисов Л.Л.", "Проф. Медведев М.М.", "Доц. Воронов В.В.",
]


# Подключение к PostgreSQL (реляционная БД — master-источник всех сущностей)
def get_pg_conn():
    return psycopg2.connect(
        host=os.environ["POSTGRES_HOST"],
        port=int(os.environ.get("POSTGRES_PORT", 5432)),
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"]
    )


# Подключение к Elasticsearch (полнотекстовый поиск лекций)
def get_es():
    return Elasticsearch(f"http://{os.environ['ES_HOST']}:{os.environ['ES_PORT']}")


# Подключение к Neo4j (граф связей студент-группа-расписание-лекция)
def get_neo4j_driver():
    return GraphDatabase.driver(
        os.environ["NEO4J_URI"],
        auth=(os.environ["NEO4J_USER"], os.environ["NEO4J_PASSWORD"])
    )


# Подключение к Redis (кэш данных студентов, TTL=2ч)
def get_redis():
    return redis.Redis(host=os.environ["REDIS_HOST"], port=int(os.environ.get("REDIS_PORT", 6379)), decode_responses=True)


# Подключение к MongoDB (вложенный документ иерархии университета)
def get_mongo():
    return MongoClient(
        host=os.environ["MONGO_HOST"],
        port=int(os.environ.get("MONGO_PORT", 27017)),
        username=os.environ["MONGO_USER"],
        password=os.environ["MONGO_PASSWORD"]
    )


def generate_data(student_count=1000):
    """
    Главная функция генерации. Общий поток:
    1. Очистка всех хранилищ (clear_all_stores)
    2. Заполнение PostgreSQL (12 таблиц: university → institute → department →
       speciality → department_specialities → lecture_course → lecture →
       lecture_material → student_group → student → schedule → attendance)
    3. Заполнение Elasticsearch (индекс lectures из PG)
    4. Заполнение Neo4j (узлы + связи из PG)
    5. Заполнение Redis (кэш студентов)
    6. Заполнение MongoDB (иерархия университета)
    """
    logger.info(f"Starting data generation: {student_count} students")
    clear_all_stores()

    random.seed(42)

    university_id = str(uuid.uuid4())
    institute_ids = [str(uuid.uuid4()) for _ in INSTITUTES]
    department_ids = [str(uuid.uuid4()) for _ in DEPARTMENTS]
    speciality_ids = [str(uuid.uuid4()) for _ in SPECIALITIES]
    dept_spec_ids = []
    course_ids = []
    lecture_ids = []
    lecture_material_ids = []
    group_ids = []
    student_ids = []
    schedule_ids = []

    pg = get_pg_conn()
    cur = pg.cursor()

    try:
        # --- Вставка университета (корневая запись, 1 строка) ---
        cur.execute(
            "INSERT INTO university (id, name, short_name, address, founded_year) VALUES (%s, %s, %s, %s, %s)",
            (university_id, "РТУ МИРЭА", "МИРЭА", "г. Москва, проспект Вернадского, 78", 1947)
        )

        # --- Вставка институтов (5 строк, FK → university) ---
        for i, inst in enumerate(INSTITUTES):
            cur.execute(
                "INSERT INTO institute (id, university_id, name, short_name, dean) VALUES (%s, %s, %s, %s, %s)",
                (institute_ids[i], university_id, inst["name"], inst["short"], inst["dean"])
            )

        # --- Вставка кафедр (15 строк, FK → institute) ---
        for i, dept in enumerate(DEPARTMENTS):
            cur.execute(
                "INSERT INTO department (id, institute_id, name, short_name, head) VALUES (%s, %s, %s, %s, %s)",
                (department_ids[i], institute_ids[dept["inst"]], dept["name"], dept["short"], dept["head"])
            )

        # --- Вставка специальностей (30 строк, справочник) ---
        for i, spec in enumerate(SPECIALITIES):
            cur.execute(
                "INSERT INTO speciality (id, name, code, degree_level, duration_years) VALUES (%s, %s, %s, %s, %s)",
                (speciality_ids[i], spec["name"], spec["code"], spec["degree"], spec["duration"])
            )

        # --- Связь кафедра↔специальность (M:N, ~30 строк) ---
        for i in range(len(DEPARTMENTS)):
            spec_indices = [i * 2, i * 2 + 1] if i * 2 + 1 < len(SPECIALITIES) else [i * 2]
            for si in spec_indices:
                if si < len(SPECIALITIES):
                    ds_id = str(uuid.uuid4())
                    dept_spec_ids.append(ds_id)
                    cur.execute(
                        "INSERT INTO department_specialities (id, department_id, speciality_id, is_primary) VALUES (%s, %s, %s, %s)",
                        (ds_id, department_ids[i], speciality_ids[si], random.choice([True, False]))
                    )

        # Привязка курсов к специальностям (3-5 курсов на специальность)
        spec_courses = {sid: [] for sid in speciality_ids}
        course_data = []
        course_idx = 0
        for si, spec_id in enumerate(speciality_ids):
            courses_per_spec = 3 + (si % 3)
            for j in range(courses_per_spec):
                cid = str(uuid.uuid4())
                course_ids.append(cid)
                spec_courses[spec_id].append(cid)
                semester = (j % 4) + 1
                course_name = COURSE_NAMES[course_idx % len(COURSE_NAMES)]
                total_hours = random.choice([72, 108, 144, 180])
                lecture_hours = total_hours // 3
                practice_hours = total_hours // 3
                lab_hours = total_hours - lecture_hours - practice_hours
                desc = COURSE_DESCRIPTIONS.get(course_name, f"Изучение дисциплины {course_name}. Теоретические основы и практические навыки.")
                course_data.append((cid, spec_id, course_name, desc, semester, total_hours, lecture_hours, practice_hours, lab_hours))
                course_idx += 1

        # --- Вставка учебных курсов lecture_course (batch execute_values, ~100 строк) ---
        execute_values(cur,
            "INSERT INTO lecture_course (id, speciality_id, name, description, semester, total_hours, lecture_hours, practice_hours, lab_hours) VALUES %s",
            course_data
        )

        course_to_idx = {cid: ci for ci, cid in enumerate(course_ids)}
        num_lectures_per_course = 10
        lecture_data = []
        # Генерация лекций (10 лекций на курс, 30% получают спец. тег, 40% — требование оборудования)
        for ci, cid in enumerate(course_ids):
            course_name = COURSE_NAMES[ci % len(COURSE_NAMES)]
            for li in range(num_lectures_per_course):
                lid = str(uuid.uuid4())
                lecture_ids.append(lid)
                ltype = random.choice(LECTURE_TYPES)
                title = f"{course_name}: {LECTURE_ANNOTATIONS[li % len(LECTURE_ANNOTATIONS)]}"
                annotation = LECTURE_ANNOTATIONS[li % len(LECTURE_ANNOTATIONS)]
                order_number = li + 1
                dur = 90 if ltype == "лекция" else 90
                tags = []
                if random.random() < 0.3:
                    tags.append(random.choice(SPECIAL_TAGS))
                if random.random() < 0.5:
                    tags.append(course_name.lower().replace(" ", "_"))
                eq = random.choice(COMPUTER_TYPES) if random.random() < 0.4 else None
                lecture_data.append((lid, cid, title, annotation, ltype, order_number, dur, eq, tags))

        # --- Вставка лекций lecture (batch по 500, ~1000 строк, FK → lecture_course) ---
        batch_size = 500
        for i in range(0, len(lecture_data), batch_size):
            execute_values(cur,
                'INSERT INTO lecture (id, course_id, title, annotation, lecture_type, order_number, duration_minutes, computer_type, tags) VALUES %s',
                lecture_data[i:i+batch_size]
            )

        # --- Вставка материалов к лекциям lecture_material (1-3 материала на лекцию) ---
        # Генерация учебных материалов к лекциям (1-3 материала на лекцию)
        lecture_material_data = []
        for lid in lecture_ids:
            for mi in range(random.randint(1, 3)):
                lmid = str(uuid.uuid4())
                lecture_material_ids.append(lmid)
                template = random.choice(LECTURE_CONTENT_TEMPLATES)
                topic_words = ["микропроцессоров", "баз данных", "нейронных сетей", "криптографии",
                              "телекоммуникаций", "сигналов", "нанотехнологий", "робототехники",
                              "облачных вычислений", "кибербезопасности", "интернета вещей",
                              "машинного обучения", "распределённых систем", "веб-технологий",
                              "графовых баз данных", "микросервисов", "контейнеризации",
                              "CI/CD пайплайнов", "мониторинга", "блокчейна"]
                content = template.format(topic=random.choice(topic_words))
                lecture_material_data.append((lmid, lid, "text", f"Материал к лекции", content, None, None))

        for i in range(0, len(lecture_material_data), batch_size):
            execute_values(cur,
                "INSERT INTO lecture_material (id, lecture_id, content_type, title, content_text, file_url, metadata) VALUES %s",
                lecture_material_data[i:i+batch_size]
            )

        # --- Вставка учебных групп student_group (~30-34 групп, FK → speciality) ---
        num_groups = max(30, student_count // 30)
        group_data = []
        for gi in range(num_groups):
            gid = str(uuid.uuid4())
            group_ids.append(gid)
            spec_idx = gi % len(speciality_ids)
            enrollment_year = random.choice([2022, 2023, 2024, 2025])
            group_name = f"Группа-{gi+1:03d}"
            curator = random.choice(TEACHER_NAMES)
            group_data.append((gid, speciality_ids[spec_idx], group_name, enrollment_year, curator))

        execute_values(cur,
            "INSERT INTO student_group (id, speciality_id, name, enrollment_year, curator) VALUES %s",
            group_data
        )

        # --- Вставка студентов student (batch по 500, FK → student_group) ---
        student_data = []
        for si in range(student_count):
            sid = str(uuid.uuid4())
            student_ids.append(sid)
            gid = group_ids[si % num_groups]
            is_female = random.random() < 0.45
            if is_female:
                fn = random.choice(FIRST_NAMES_F)
                ln = random.choice(LAST_NAMES_F)
                pat = random.choice(PATRONYMICS_F)
            else:
                fn = random.choice(FIRST_NAMES_M)
                ln = random.choice(LAST_NAMES_M)
                pat = random.choice(PATRONYMICS_M)
            email = f"{ln.lower()}.{fn.lower()}@mirea.ru"
            phone = f"+7-9{random.randint(100,999)}-{random.randint(100,999)}-{random.randint(10,99)}"
            card = f"М{random.randint(100000, 999999)}"
            enroll_date = date(random.choice([2022, 2023, 2024, 2025]), 9, 1)
            status = random.choices(["active", "academic_leave", "expelled"], weights=[0.9, 0.05, 0.05])[0]
            student_data.append((sid, gid, fn, ln, pat, email, phone, card, enroll_date, status))

        for i in range(0, len(student_data), batch_size):
            execute_values(cur,
                "INSERT INTO student (id, group_id, first_name, last_name, patronymic, email, phone, student_card_number, enrollment_date, status) VALUES %s",
                student_data[i:i+batch_size]
            )

        # --- Вставка расписания schedule (batch по 500, FK → lecture, student_group) ---
        # Генерация расписания (семестр 1-4: осень 2025, семестр 5-8: весна 2026)
        schedule_data = []
        fall_start = date(2025, 9, 1)
        spring_start = date(2026, 2, 9)

        cur.execute("SELECT id, semester FROM lecture_course")
        course_semester_map = {str(r[0]): r[1] for r in cur.fetchall()}

        for gid_idx, gid in enumerate(group_ids):
            spec_id = group_data[gid_idx][1]
            group_course_ids = spec_courses.get(spec_id, [])

            for cid in group_course_ids[:8]:
                ci = course_to_idx.get(cid)
                if ci is None:
                    continue
                course_lectures = [lecture_ids[ci * num_lectures_per_course + li] for li in range(num_lectures_per_course) if ci * num_lectures_per_course + li < len(lecture_ids)]

                semester = course_semester_map.get(cid, 1)

                if semester <= 4:
                    base_date = fall_start
                else:
                    base_date = spring_start

                semester_weeks = 17
                for li, lid in enumerate(course_lectures):
                    if semester <= 4:
                        week_num = li % semester_weeks
                        day_in_week = random.randint(0, 5)
                        sd = fall_start + timedelta(weeks=week_num, days=day_in_week)
                    else:
                        week_num = li % semester_weeks
                        day_in_week = random.randint(0, 5)
                        sd = spring_start + timedelta(weeks=week_num, days=day_in_week)

                    if sd.year == 2025 and sd.month > 12:
                        continue
                    if sd.year == 2026 and sd.month > 6:
                        continue

                    ws = sd - timedelta(days=sd.weekday())
                    start_h = random.choice([8, 9, 10, 11, 12, 13, 14, 15])
                    end_h = start_h + 1 + (1 if start_h < 14 else 0)
                    classroom = random.choice(CLASSROOMS)
                    teacher = random.choice(TEACHER_NAMES)
                    sched_id = str(uuid.uuid4())
                    schedule_ids.append(sched_id)
                    schedule_data.append((
                        sched_id, lid, gid, sd, ws,
                        time(start_h, 0), time(start_h + 1, 30),
                        classroom, teacher, "scheduled"
                    ))

        for i in range(0, len(schedule_data), batch_size):
            execute_values(cur,
                "INSERT INTO schedule (id, lecture_id, group_id, scheduled_date, week_start_date, start_time, end_time, classroom, teacher_name, status) VALUES %s",
                schedule_data[i:i+batch_size]
            )

        # --- Вставка посещаемости attendance (партиционированная таблица, batch по 500;
        #     каждая запись: студент присутствовал/отсутствовал на занятии, FK → schedule, student) ---
        # Генерация посещаемости (для каждого студента в группе создаётся запись с is_present=True/False)
        logger.info("Generating attendance records...")
        cur.execute("SELECT id, group_id, week_start_date FROM schedule")
        schedule_info = cur.fetchall()

        group_students = {}
        for i, sd_row in enumerate(student_data):
            gid = sd_row[1]
            sid = student_ids[i]
            group_students.setdefault(gid, []).append(sid)

        attendance_data = []
        for sched_row in schedule_info:
            sched_id = str(sched_row[0])
            sched_gid = str(sched_row[1])
            ws = sched_row[2]
            students_in_group = group_students.get(sched_gid, [])
            if not students_in_group:
                continue
            attendance_rate = random.uniform(0.5, 0.95)
            num_attending = max(1, int(len(students_in_group) * attendance_rate))
            attending = set(random.sample(students_in_group, min(num_attending, len(students_in_group))))

            for sid in students_in_group:
                is_present_val = sid in attending
                marked = datetime(ws.year, ws.month, ws.day, random.randint(8, 18), random.randint(0, 59))
                attendance_data.append((str(uuid.uuid4()), sched_id, sid, ws, is_present_val, marked))

        for i in range(0, len(attendance_data), batch_size):
            execute_values(cur,
                "INSERT INTO attendance (id, schedule_id, student_id, week_start_date, is_present, marked_at) VALUES %s",
                attendance_data[i:i+batch_size]
            )

        pg.commit()
        logger.info("PostgreSQL data committed")

    except Exception as e:
        pg.rollback()
        logger.error(f"PostgreSQL error: {e}")
        raise
    finally:
        cur.close()
        pg.close()

    logger.info("Populating Elasticsearch...")
    populate_elasticsearch(course_ids, lecture_ids, lecture_material_ids)

    logger.info("Populating Neo4j...")
    populate_neo4j(course_ids, lecture_ids, group_ids, student_ids, schedule_ids)

    logger.info("Populating Redis...")
    populate_redis(student_ids, student_data)

    logger.info("Populating MongoDB...")
    populate_mongodb(university_id, institute_ids, department_ids, speciality_ids, dept_spec_ids)

    counts = {
        "university": 1,
        "institutes": len(institute_ids),
        "departments": len(department_ids),
        "specialities": len(speciality_ids),
        "department_specialities": len(dept_spec_ids),
        "lecture_courses": len(course_ids),
        "lectures": len(lecture_ids),
        "lecture_materials": len(lecture_material_ids),
        "student_groups": len(group_ids),
        "students": len(student_ids),
        "schedule": len(schedule_ids),
        "attendance": len(attendance_data),
    }

    logger.info(f"Data generation complete: {counts}")
    return {"status": "success", "counts": counts}


def populate_elasticsearch(course_ids, lecture_ids, lecture_material_ids):
    """
    Заполнение Elasticsearch: создание индекса lectures с кастомным анализатором
    russian_custom (standard tokenizer + lowercase + russian_stop + russian_stemmer),
    затем bulk-индексация документов, собранных из PG (lecture + lecture_course + lecture_material).
    """
    es = get_es()

    if es.indices.exists(index="lectures"):
        es.indices.delete(index="lectures")

    # Создание индекса с russian_custom анализатором (standard tokenizer + lowercase + russian_stop + russian_stemmer)
    es.indices.create(index="lectures", body={
        "settings": {
            "analysis": {
                "filter": {
                    "russian_stop": {"type": "stop", "stopwords": "_russian_"},
                    "russian_stemmer": {"type": "stemmer", "language": "russian"}
                },
                "analyzer": {
                    "russian_custom": {
                        "type": "custom",
                        "tokenizer": "standard",
                        "filter": ["lowercase", "russian_stop", "russian_stemmer"]
                    }
                }
            }
        },
        "mappings": {
            "properties": {
                "lecture_id": {"type": "keyword"},
                "course_id": {"type": "keyword"},
                "course_name": {"type": "text", "analyzer": "russian_custom"},
                "title": {"type": "text", "analyzer": "russian_custom"},
                "annotation": {"type": "text", "analyzer": "russian_custom"},
                "content_text": {"type": "text", "analyzer": "russian_custom"},
                "lecture_type": {"type": "keyword"},
                "tags": {"type": "keyword"},
                "computer_type": {"type": "text", "analyzer": "russian_custom"},
                "semester": {"type": "integer"}
            }
        }
    })

    # Выгрузка лекций + материалов из PostgreSQL для индексации
    pg = get_pg_conn()
    cur = pg.cursor()
    cur.execute("""
        SELECT l.id, l.course_id, lc.name as course_name, l.title, l.annotation,
               l.lecture_type, l.tags, l.computer_type,
               COALESCE(string_agg(lm.content_text, ' '), '') as content_text,
               lc.semester
        FROM lecture l
        JOIN lecture_course lc ON l.course_id = lc.id
        LEFT JOIN lecture_material lm ON l.id = lm.lecture_id
        GROUP BY l.id, lc.name, lc.semester
    """)

    actions = []
    for row in cur.fetchall():
        tags = row[6]
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        elif tags is None:
            tags = []
        doc = {
            "lecture_id": str(row[0]),
            "course_id": str(row[1]),
            "course_name": row[2],
            "title": row[3],
            "annotation": row[4] or "",
            "lecture_type": row[5],
            "tags": tags,
            "computer_type": row[7] or "",
            "content_text": row[8] or "",
            "semester": row[9]
        }
        # Формирование документов для bulk-индексации
        actions.append({"_index": "lectures", "_id": str(row[0]), "_source": doc})

    # Bulk-индексация (батчами по 500 документов)
    if actions:
        success, errors = helpers.bulk(es, actions, chunk_size=500, raise_on_error=False)
        if errors:
            logger.error(f"ES bulk errors: {errors[:3]}")
        logger.info(f"ES: indexed {success}/{len(actions)} lectures")

    cur.close()
    pg.close()


def populate_neo4j(course_ids, lecture_ids, group_ids, student_ids, schedule_ids):
    """
    Заполнение Neo4j: 5 типов узлов (Student, StudentGroup, Schedule, Lecture,
    LectureCourse) и 6 типов связей:
      • MEMBER_OF     — студент → группа
      • CONTAINS      — группа → расписание
      • PART_OF       — расписание → лекция
      • BELONGS_TO    — лекция → курс
      • SHOULD_ATTEND — студент → расписание (должен присутствовать)
      • ATTENDED      — студент → расписание (фактически присутствовал)
    Данные читаются из PG, узлы и связи создаются пакетами через UNWIND
    (по 500 записей) для производительности.
    """
    driver = get_neo4j_driver()

    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")

        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (s:Student) REQUIRE s.id IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (g:StudentGroup) REQUIRE g.id IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (s:Schedule) REQUIRE s.id IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (l:Lecture) REQUIRE l.id IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (c:LectureCourse) REQUIRE c.id IS UNIQUE")

    pg = get_pg_conn()
    cur = pg.cursor()

    with driver.session() as session:
        # Создание узлов Student (все свойства для замены PG-запросов), батч 500
        cur.execute("SELECT id, first_name, last_name, patronymic, student_card_number, email, phone, status, enrollment_date, group_id FROM student")
        students = cur.fetchall()
        batch = []
        for s in students:
            batch.append({
                "id": str(s[0]), "name": f"{s[1]} {s[2]} {s[3]}", "card_number": s[4],
                "first_name": s[1], "last_name": s[2], "patronymic": s[3] or "",
                "email": s[5], "phone": s[6], "status": s[7], "enrollment_date": str(s[8]), "group_id": str(s[9])
            })
            if len(batch) >= 500:
                session.run(
                    "UNWIND $batch AS row CREATE (s:Student {id: row.id, name: row.name, card_number: row.card_number, first_name: row.first_name, last_name: row.last_name, patronymic: row.patronymic, email: row.email, phone: row.phone, status: row.status, enrollment_date: row.enrollment_date, group_id: row.group_id})",
                    batch=batch
                )
                batch = []
        if batch:
            session.run(
                "UNWIND $batch AS row CREATE (s:Student {id: row.id, name: row.name, card_number: row.card_number, first_name: row.first_name, last_name: row.last_name, patronymic: row.patronymic, email: row.email, phone: row.phone, status: row.status, enrollment_date: row.enrollment_date, group_id: row.group_id})",
                batch=batch
            )

        # Создание узлов StudentGroup (название + год + куратор + специальность)
        cur.execute("SELECT id, name, enrollment_year, curator, speciality_id FROM student_group")
        groups = cur.fetchall()
        batch = [{"id": str(g[0]), "name": g[1], "enrollment_year": g[2], "curator": g[3] or "", "speciality_id": str(g[4])} for g in groups]
        session.run(
            "UNWIND $batch AS row CREATE (g:StudentGroup {id: row.id, name: row.name, enrollment_year: row.enrollment_year, curator: row.curator, speciality_id: row.speciality_id})",
            batch=batch
        )

        # Создание узлов Schedule (дата, время, аудитория, неделя, преподаватель), батч 500
        cur.execute("SELECT id, scheduled_date, start_time, classroom, week_start_date, teacher_name FROM schedule")
        schedules = cur.fetchall()
        batch = [{"id": str(s[0]), "date": str(s[1]), "time": str(s[2]), "classroom": s[3] or "", "week_start_date": str(s[4]), "teacher_name": s[5] or ""} for s in schedules]
        for i in range(0, len(batch), 500):
            session.run(
                "UNWIND $batch AS row CREATE (s:Schedule {id: row.id, date: row.date, time: row.time, classroom: row.classroom, week_start_date: row.week_start_date, teacher_name: row.teacher_name})",
                batch=batch[i:i+500]
            )

        # Создание узлов Lecture (название, тип, оборудование, теги), батч 500
        cur.execute("SELECT id, title, lecture_type, computer_type, tags FROM lecture")
        lectures = cur.fetchall()
        batch = []
        for l in lectures:
            tags = l[4] if l[4] else []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]
            batch.append({"id": str(l[0]), "title": l[1], "type": l[2] or "", "computer_type": l[3] or "", "tags": tags})
        for i in range(0, len(batch), 500):
            session.run(
                "UNWIND $batch AS row CREATE (l:Lecture {id: row.id, title: row.title, type: row.type, computer_type: row.computer_type, tags: row.tags})",
                batch=batch[i:i+500]
            )

        # Создание узлов LectureCourse (название, семестр, часы, описание, специальность)
        cur.execute("SELECT id, name, semester, total_hours, lecture_hours, practice_hours, lab_hours, description, speciality_id FROM lecture_course")
        courses = cur.fetchall()
        batch = [{"id": str(c[0]), "name": c[1], "semester": c[2], "total_hours": c[3] or 0, "lecture_hours": c[4] or 0, "practice_hours": c[5] or 0, "lab_hours": c[6] or 0, "description": c[7] or "", "speciality_id": str(c[8])} for c in courses]
        session.run(
            "UNWIND $batch AS row CREATE (c:LectureCourse {id: row.id, name: row.name, semester: row.semester, total_hours: row.total_hours, lecture_hours: row.lecture_hours, practice_hours: row.practice_hours, lab_hours: row.lab_hours, description: row.description, speciality_id: row.speciality_id})",
            batch=batch
        )

        # Связь MEMBER_OF: Student → StudentGroup (студент состоит в группе)
        cur.execute("SELECT id, group_id FROM student")
        membership = cur.fetchall()
        batch = [{"sid": str(m[0]), "gid": str(m[1])} for m in membership]
        for i in range(0, len(batch), 500):
            session.run(
                "UNWIND $batch AS row MATCH (s:Student {id: row.sid}), (g:StudentGroup {id: row.gid}) CREATE (s)-[:MEMBER_OF]->(g)",
                batch=batch[i:i+500]
            )

        # Связь CONTAINS: StudentGroup → Schedule (группа имеет расписание)
        cur.execute("SELECT id, group_id FROM schedule")
        group_schedule = cur.fetchall()
        batch = [{"sid": str(g[0]), "gid": str(g[1])} for g in group_schedule]
        for i in range(0, len(batch), 500):
            session.run(
                "UNWIND $batch AS row MATCH (s:Schedule {id: row.sid}), (g:StudentGroup {id: row.gid}) CREATE (g)-[:CONTAINS]->(s)",
                batch=batch[i:i+500]
            )

        # Связь PART_OF: Schedule → Lecture (расписание относится к лекции)
        cur.execute("SELECT id, lecture_id FROM schedule")
        sched_lecture = cur.fetchall()
        batch = [{"sid": str(s[0]), "lid": str(s[1])} for s in sched_lecture]
        for i in range(0, len(batch), 500):
            session.run(
                "UNWIND $batch AS row MATCH (s:Schedule {id: row.sid}), (l:Lecture {id: row.lid}) CREATE (s)-[:PART_OF]->(l)",
                batch=batch[i:i+500]
            )

        # Связь BELONGS_TO: Lecture → LectureCourse (лекция принадлежит курсу)
        cur.execute("SELECT id, course_id FROM lecture")
        lecture_course = cur.fetchall()
        batch = [{"lid": str(l[0]), "cid": str(l[1])} for l in lecture_course]
        for i in range(0, len(batch), 500):
            session.run(
                "UNWIND $batch AS row MATCH (l:Lecture {id: row.lid}), (c:LectureCourse {id: row.cid}) CREATE (l)-[:BELONGS_TO]->(c)",
                batch=batch[i:i+500]
            )

        # Связь SHOULD_ATTEND: Student → Schedule (студент должен присутствовать)
        cur.execute("""
            SELECT DISTINCT s.id, sch.id
            FROM student s
            JOIN schedule sch ON sch.group_id = s.group_id
        """)
        should_attend = cur.fetchall()
        batch = [{"sid": str(s[0]), "schid": str(s[1])} for s in should_attend]
        for i in range(0, len(batch), 500):
            session.run(
                "UNWIND $batch AS row MATCH (s:Student {id: row.sid}), (sch:Schedule {id: row.schid}) CREATE (s)-[:SHOULD_ATTEND]->(sch)",
                batch=batch[i:i+500]
            )

        # Связь ATTENDED: Student → Schedule (фактическое посещение — из таблицы attendance)
        cur.execute("SELECT DISTINCT student_id, schedule_id FROM attendance")
        attended = cur.fetchall()
        batch = [{"sid": str(a[0]), "schid": str(a[1])} for a in attended]
        for i in range(0, len(batch), 500):
            session.run(
                "UNWIND $batch AS row MATCH (s:Student {id: row.sid}), (sch:Schedule {id: row.schid}) CREATE (s)-[:ATTENDED]->(sch)",
                batch=batch[i:i+500]
            )

    cur.close()
    pg.close()
    driver.close()
    logger.info("Neo4j populated")


def populate_redis(student_ids, student_data):
    """
    Заполнение Redis: для каждого студента создаётся Hash-ключ student:{uuid}
    с полями ФИО, email, номер зачётки, группа, статус, дата зачисления.
    TTL каждого ключа — 7200 с (2 часа). Вставка через pipeline пакетами по 500
    для снижения числа round-trip.
    """
    r = get_redis()
    # Очистка Redis перед заполнением
    r.flushdb()

    pipe = r.pipeline()
    for i, sid in enumerate(student_ids):
        if i < len(student_data):
            d = student_data[i]
            key = f"student:{sid}"
            # Pipeline HSET student:{uuid} с TTL=7200с (2 часа), батч 500 для экономии памяти
            pipe.hset(key, mapping={
                "first_name": d[2],
                "last_name": d[3],
                "patronymic": d[4] or "",
                "email": d[5],
                "phone": d[6],
                "student_card_number": d[7],
                "group_id": d[1],
                "status": d[9],
                "enrollment_date": str(d[8])
            })
            pipe.expire(key, 7200)
            if i % 500 == 0:
                pipe.execute()
                pipe = r.pipeline()
    pipe.execute()

    logger.info(f"Redis: cached {len(student_ids)} students")


def populate_mongodb(university_id, institute_ids, department_ids, speciality_ids, dept_spec_ids):
    """
    Заполнение MongoDB: создаётся один вложенный документ иерархии
    University → Institutes[] → Departments[] → Specialities[].
    Вместо 4 JOIN-запросов в реляционной схеме здесь достаточно
    одного findOne() для получения всей иерархии целиком.
    """
    client = get_mongo()
    db = client["university"]
    hierarchy = db["hierarchy"]
    # Очистка коллекции перед заполнением
    hierarchy.drop()

    pg = get_pg_conn()
    cur = pg.cursor()

    # Построение вложенного документа: University → Institutes → Departments → Specialities
    inst_docs = []
    for i, inst_id in enumerate(institute_ids):
        cur.execute("SELECT name, short_name, dean FROM institute WHERE id = %s", (inst_id,))
        inst_row = cur.fetchone()
        if not inst_row:
            continue

        dept_docs = []
        cur.execute("SELECT id, name, short_name, head FROM department WHERE institute_id = %s", (inst_id,))
        for dept_row in cur.fetchall():
            dept_doc = {
                "id": str(dept_row[0]),
                "name": dept_row[1],
                "short_name": dept_row[2],
                "head": dept_row[3],
                "specialities": []
            }
            cur.execute("""
                SELECT s.id, s.name, s.code, s.degree_level
                FROM department_specialities ds
                JOIN speciality s ON ds.speciality_id = s.id
                WHERE ds.department_id = %s
            """, (dept_row[0],))
            for spec_row in cur.fetchall():
                dept_doc["specialities"].append({
                    "id": str(spec_row[0]),
                    "name": spec_row[1],
                    "code": spec_row[2],
                    "degree_level": spec_row[3]
                })
            dept_docs.append(dept_doc)

        inst_docs.append({
            "id": str(inst_id),
            "name": inst_row[0],
            "short_name": inst_row[1],
            "dean": inst_row[2],
            "departments": dept_docs
        })

    university_doc = {
        "_id": str(university_id),
        "name": "РТУ МИРЭА",
        "short_name": "МИРЭА",
        "institutes": inst_docs
    }

    # Вставка единого документа иерархии (один findOne вместо 4 JOIN в PostgreSQL)
    hierarchy.insert_one(university_doc)

    cur.close()
    pg.close()
    client.close()
    logger.info("MongoDB: hierarchy document created")


def clear_all_stores():
    """
    Очистка всех 5 хранилищ. В PostgreSQL таблицы очищаются через
    TRUNCATE CASCADE в порядке, учитывающем внешние ключи
    (сначала зависимые, потом родительские). Для ускорения
    временно отключается проверка FK: SET session_replication_role = replica.
    Остальные хранилища очищаются собственными нативными методами.
    """
    logger.info("Clearing all stores...")

    try:
        pg = get_pg_conn()
        cur = pg.cursor()
        # Отключаем FK-проверки для ускорения TRUNCATE
        cur.execute("SET session_replication_role = replica")
        # Таблицы в порядке зависимостей (сначала зависимые, потом главные)
        tables = [
            "attendance", "schedule", "student", "student_group",
            "lecture_material", "lecture", "lecture_course",
            "department_specialities", "speciality", "department",
            "institute", "university"
        ]
        for t in tables:
            cur.execute(f"TRUNCATE TABLE {t} CASCADE")
        # Возвращаем FK-проверки
        cur.execute("SET session_replication_role = DEFAULT")
        pg.commit()
        cur.close()
        pg.close()
        logger.info("PostgreSQL cleared")
    except Exception as e:
        logger.error(f"Error clearing PostgreSQL: {e}")

    try:
        # Удаление индекса lectures
        es = get_es()
        if es.indices.exists(index="lectures"):
            es.indices.delete(index="lectures")
        logger.info("Elasticsearch cleared")
    except Exception as e:
        logger.error(f"Error clearing ES: {e}")

    try:
        # Удаление всех узлов и связей
        driver = get_neo4j_driver()
        with driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
        driver.close()
        logger.info("Neo4j cleared")
    except Exception as e:
        logger.error(f"Error clearing Neo4j: {e}")

    try:
        # Очистка всех ключей
        r = get_redis()
        r.flushdb()
        logger.info("Redis cleared")
    except Exception as e:
        logger.error(f"Error clearing Redis: {e}")

    try:
        # Удаление коллекции hierarchy
        client = get_mongo()
        db = client["university"]
        db["hierarchy"].drop()
        client.close()
        logger.info("MongoDB cleared")
    except Exception as e:
        logger.error(f"Error clearing MongoDB: {e}")

    return {"status": "cleared"}


def get_status():
    """
    Проверка состояния данных: подсчёт студентов и курсов в PostgreSQL.
    Если студент > 0 — статус «ready», иначе «empty».
    """
    try:
        pg = get_pg_conn()
        cur = pg.cursor()
        cur.execute("SELECT COUNT(*) FROM student")
        student_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM lecture_course")
        course_count = cur.fetchone()[0]
        cur.close()
        pg.close()
        return {"students": student_count, "courses": course_count, "status": "ready" if student_count > 0 else "empty"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def list_groups():
    """
    Возвращает список групп (id, name, enrollment_year) из PostgreSQL.
    Используется в Lab3 для заполнения выпадающего списка group_name.
    """
    try:
        pg = get_pg_conn()
        cur = pg.cursor()
        cur.execute("SELECT id, name, enrollment_year FROM student_group ORDER BY name")
        groups = [{"id": str(r[0]), "name": r[1], "enrollment_year": r[2]} for r in cur.fetchall()]
        cur.close()
        pg.close()
        return {"groups": groups}
    except Exception as e:
        return {"groups": [], "error": str(e)}
