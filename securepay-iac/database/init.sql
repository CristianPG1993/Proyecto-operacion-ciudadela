-- =============================================
-- SECUREPAY - INICIALIZACIÓN DE BASE DE DATOS
-- Principio CIA Triad + Mínimo Privilegio
-- =============================================

-- Extensión para UUIDs
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================
-- TABLA: users (Gestión de identidades)
-- =============================================
CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(50)  UNIQUE NOT NULL,
    email       VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role        VARCHAR(20)  NOT NULL DEFAULT 'user'
                    CHECK (role IN ('user', 'admin', 'auditor')),
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    failed_attempts INTEGER  NOT NULL DEFAULT 0,
    locked_until TIMESTAMP,
    created_at  TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- =============================================
-- TABLA: accounts (Cuentas bancarias)
-- =============================================
CREATE TABLE IF NOT EXISTS accounts (
    id             SERIAL PRIMARY KEY,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    account_number VARCHAR(20) UNIQUE NOT NULL,
    balance        NUMERIC(15, 2) NOT NULL DEFAULT 0.00
                       CHECK (balance >= 0),
    currency       CHAR(3)  NOT NULL DEFAULT 'EUR',
    is_active      BOOLEAN  NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMP NOT NULL DEFAULT NOW()
);

-- =============================================
-- TABLA: transfers (Transferencias - Núcleo CIA)
-- =============================================
CREATE TABLE IF NOT EXISTS transfers (
    id              SERIAL PRIMARY KEY,
    from_account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    to_account_id   INTEGER NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    amount          NUMERIC(15, 2) NOT NULL CHECK (amount > 0),
    description     TEXT,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'completed', 'failed', 'reversed')),
    -- Integridad: hash SHA-256 del contenido de la transferencia
    integrity_hash  VARCHAR(64) NOT NULL,
    initiated_by    INTEGER NOT NULL REFERENCES users(id),
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMP
);

-- =============================================
-- TABLA: audit_logs (Trazabilidad completa)
-- =============================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id),
    action      VARCHAR(100) NOT NULL,
    resource    VARCHAR(100),
    ip_address  VARCHAR(45),
    user_agent  TEXT,
    details     JSONB,
    severity    VARCHAR(10) NOT NULL DEFAULT 'INFO'
                    CHECK (severity IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL')),
    created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);

-- =============================================
-- ÍNDICES para rendimiento (Disponibilidad)
-- =============================================
CREATE INDEX idx_users_email       ON users(email);
CREATE INDEX idx_users_username    ON users(username);
CREATE INDEX idx_accounts_user_id  ON accounts(user_id);
CREATE INDEX idx_transfers_from    ON transfers(from_account_id);
CREATE INDEX idx_transfers_to      ON transfers(to_account_id);
CREATE INDEX idx_audit_user        ON audit_logs(user_id);
CREATE INDEX idx_audit_created     ON audit_logs(created_at DESC);

-- =============================================
-- USUARIOS DE BASE DE DATOS (Mínimo Privilegio)
-- =============================================

-- Usuario para auth-service: solo users y accounts
CREATE USER auth_svc WITH PASSWORD 'Auth_Svc_P@ss_2024!';
GRANT SELECT, INSERT, UPDATE ON users, accounts TO auth_svc;
GRANT USAGE, SELECT ON SEQUENCE users_id_seq, accounts_id_seq TO auth_svc;

-- Usuario para transfer-service: accounts y transfers
CREATE USER transfer_svc WITH PASSWORD 'Transfer_Svc_P@ss_2024!';
GRANT SELECT, UPDATE ON accounts TO transfer_svc;
GRANT SELECT, INSERT, UPDATE ON transfers TO transfer_svc;
GRANT USAGE, SELECT ON SEQUENCE transfers_id_seq TO transfer_svc;

-- Usuario para audit-service: solo audit_logs (INSERT y SELECT)
CREATE USER audit_svc WITH PASSWORD 'Audit_Svc_P@ss_2024!';
GRANT SELECT, INSERT ON audit_logs TO audit_svc;
GRANT USAGE, SELECT ON SEQUENCE audit_logs_id_seq TO audit_svc;

-- =============================================
-- DATOS INICIALES (Seed)
-- =============================================

-- Admin por defecto (password: Admin1234! -> hash bcrypt)
INSERT INTO users (username, email, password_hash, role)
VALUES (
    'admin',
    'admin@securepay.local',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6QZnH4Oc6.',
    'admin'
) ON CONFLICT DO NOTHING;

-- Cuenta de prueba admin
INSERT INTO accounts (user_id, account_number, balance, currency)
VALUES (
    (SELECT id FROM users WHERE username = 'admin'),
    'ACC-ADMIN-0001',
    10000.00,
    'EUR'
) ON CONFLICT DO NOTHING;
