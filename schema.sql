-- ESTENSIONI
-- Abilitiamo pgcrypto per funzioni crittografiche se servono lato DB
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ==========================================
-- 1. TABELLA UTENTI (L'Anagrafica Blindata)
-- ==========================================
CREATE TYPE account_status_enum AS ENUM ('active', 'locked', 'banned', 'pending_verification');

CREATE TABLE users (
    id UUID PRIMARY KEY, -- UUID v7 generato dall'applicazione Python
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL, -- Argon2id
    
    -- Sicurezza & MFA
    security_stamp UUID NOT NULL, -- Cambia a ogni login/logout/cambio psw
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret_enc TEXT, -- Criptato lato app (AES-256)
    
    -- Stato Account & Anti-Brute Force persistente
    account_status account_status_enum NOT NULL DEFAULT 'pending_verification',
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indici per velocità login
CREATE INDEX idx_users_email ON users(email);

-- ==========================================
-- 2. TABELLA SESSIONI (Gestione Dispositivi)
-- ==========================================
CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    refresh_token_hash VARCHAR(64) NOT NULL UNIQUE, -- SHA-256 del token
    
    -- Fingerprinting per Anti-Hijacking
    device_fingerprint VARCHAR(255), 
    ip_address INET, -- Tipo nativo Postgres per IP
    user_agent TEXT,
    
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_reason VARCHAR(255)
);

CREATE INDEX idx_sessions_token_hash ON sessions(refresh_token_hash);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);

-- ==========================================
-- 3. AUDIT LOGS (Scatola Nera Append-Only)
-- ==========================================
CREATE TYPE event_type_enum AS ENUM (
    'LOGIN_SUCCESS', 
    'LOGIN_FAILED', 
    'LOGOUT',
    'PASSWORD_CHANGE', 
    'MFA_enabled',
    'MFA_FAILED', 
    'SUSPICIOUS_ACTIVITY',
    'ACCOUNT_LOCKED'
);

CREATE TABLE security_audit_logs (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL, -- Nullable se l'user non esiste
    
    event_type event_type_enum NOT NULL,
    risk_score INT DEFAULT 0, -- 0-100
    
    -- Dati Forensi
    ip_address INET NOT NULL,
    user_agent TEXT,
    geo_location JSONB, -- { "country": "IT", "city": "Milan" }
    metadata JSONB, -- { "reason": "wrong_password", "attempt": 3 }
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indice per analisi temporale (es. "dammi tutti i login falliti dell'ultima ora")
CREATE INDEX idx_audit_created_at ON security_audit_logs(created_at);
CREATE INDEX idx_audit_ip_address ON security_audit_logs(ip_address);