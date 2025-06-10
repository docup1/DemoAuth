CREATE TABLE "Users" (
                         "Id" UUID PRIMARY KEY,
                         "Login" VARCHAR(50) NOT NULL UNIQUE,
                         "PasswordHash" VARCHAR(255) NOT NULL,
                         "Role" VARCHAR(20) NOT NULL DEFAULT 'user',
                         "CreatedAt" TIMESTAMP NOT NULL,
                         "LastLogin" TIMESTAMP,
                         "LockedUntil" TIMESTAMP,
                         "FailedLoginAttempts" INT NOT NULL DEFAULT 0
);

CREATE INDEX idx_users_login ON "Users" ("Login");