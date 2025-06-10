CREATE DATABASE authdb;

CREATE TABLE users (
                       id UUID PRIMARY KEY,
                       login VARCHAR(50) NOT NULL UNIQUE,
                       password_hash VARCHAR(255) NOT NULL,
                       role VARCHAR(20) NOT NULL DEFAULT 'user',
                       created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                       last_login TIMESTAMP,
                       locked_until TIMESTAMP,
                       failed_login_attempts INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_users_login ON users (login);