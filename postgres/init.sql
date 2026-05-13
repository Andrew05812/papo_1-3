CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE university (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(500) NOT NULL,
    short_name VARCHAR(100),
    address TEXT,
    founded_year INT
);

CREATE TABLE institute (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    university_id UUID NOT NULL REFERENCES university(id),
    name VARCHAR(500) NOT NULL,
    short_name VARCHAR(100),
    dean VARCHAR(300)
);

CREATE TABLE department (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institute_id UUID NOT NULL REFERENCES institute(id),
    name VARCHAR(500) NOT NULL,
    short_name VARCHAR(100),
    head VARCHAR(300)
);

CREATE TABLE speciality (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(500) NOT NULL,
    code VARCHAR(20) NOT NULL,
    degree_level VARCHAR(20),
    duration_years INT
);

CREATE TABLE department_specialities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    department_id UUID NOT NULL REFERENCES department(id),
    speciality_id UUID NOT NULL REFERENCES speciality(id),
    is_primary BOOLEAN DEFAULT TRUE
);

CREATE TABLE lecture_course (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    speciality_id UUID NOT NULL REFERENCES speciality(id),
    name VARCHAR(500) NOT NULL,
    description TEXT,
    semester INT NOT NULL,
    total_hours INT,
    lecture_hours INT,
    practice_hours INT,
    lab_hours INT
);

CREATE TABLE lecture (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    course_id UUID NOT NULL REFERENCES lecture_course(id),
    title VARCHAR(500) NOT NULL,
    annotation TEXT,
    lecture_type TEXT,
    order_number INT,
    duration_minutes INT DEFAULT 90,
    equipment_req VARCHAR(200),
    tags TEXT[]
);

CREATE TABLE lecture_material (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    lecture_id UUID NOT NULL REFERENCES lecture(id),
    content_type TEXT,
    title VARCHAR(500),
    content_text TEXT,
    file_url VARCHAR(1000),
    metadata JSONB
);

CREATE TABLE student_group (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    speciality_id UUID NOT NULL REFERENCES speciality(id),
    name VARCHAR(50) NOT NULL,
    enrollment_year INT,
    curator VARCHAR(300)
);

CREATE TABLE student (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    group_id UUID NOT NULL REFERENCES student_group(id),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    patronymic VARCHAR(100),
    email VARCHAR(255),
    student_card_number VARCHAR(20),
    enrollment_date DATE,
    status VARCHAR(50) DEFAULT 'active'
);

CREATE TABLE schedule (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    lecture_id UUID NOT NULL REFERENCES lecture(id),
    group_id UUID NOT NULL REFERENCES student_group(id),
    scheduled_date DATE NOT NULL,
    week_start_date DATE NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    classroom VARCHAR(50),
    teacher_name VARCHAR(300),
    status VARCHAR(50) DEFAULT 'scheduled'
);

CREATE TABLE attendance (
    id UUID DEFAULT uuid_generate_v4(),
    schedule_id UUID NOT NULL,
    student_id UUID NOT NULL,
    week_start_date DATE NOT NULL,
    marked_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (id, week_start_date)
) PARTITION BY RANGE (week_start_date);

CREATE TABLE attendance_2025_q3 PARTITION OF attendance
    FOR VALUES FROM ('2025-07-01') TO ('2025-10-01');

CREATE TABLE attendance_2025_q4 PARTITION OF attendance
    FOR VALUES FROM ('2025-10-01') TO ('2026-01-01');

CREATE TABLE attendance_2026_q1 PARTITION OF attendance
    FOR VALUES FROM ('2026-01-01') TO ('2026-04-01');

CREATE TABLE attendance_2026_q2 PARTITION OF attendance
    FOR VALUES FROM ('2026-04-01') TO ('2026-07-01');

CREATE INDEX idx_attendance_schedule ON attendance (schedule_id);
CREATE INDEX idx_attendance_student ON attendance (student_id);
CREATE INDEX idx_attendance_student_week ON attendance (student_id, week_start_date);
CREATE INDEX idx_attendance_schedule_student ON attendance (schedule_id, student_id);

CREATE INDEX idx_schedule_lecture ON schedule (lecture_id);
CREATE INDEX idx_schedule_group ON schedule (group_id);
CREATE INDEX idx_schedule_week ON schedule (week_start_date);
CREATE INDEX idx_schedule_date ON schedule (scheduled_date);
CREATE INDEX idx_schedule_lecture_group ON schedule (lecture_id, group_id);

CREATE INDEX idx_student_group ON student (group_id);

CREATE INDEX idx_lecture_course ON lecture (course_id);

CREATE INDEX idx_lecture_course_speciality ON lecture_course (speciality_id);
CREATE INDEX idx_lecture_course_semester ON lecture_course (semester);

CREATE INDEX idx_student_group_speciality ON student_group (speciality_id);

CREATE INDEX idx_schedule_lecture_week ON schedule (lecture_id, week_start_date);
CREATE INDEX idx_attendance_schedule_week_student ON attendance (schedule_id, week_start_date, student_id);
CREATE INDEX idx_lecture_type ON lecture (lecture_type);
CREATE INDEX idx_lecture_course_semester_spec ON lecture_course (semester, speciality_id);
