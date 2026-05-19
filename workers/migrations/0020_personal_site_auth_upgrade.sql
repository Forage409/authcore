-- Migration 0020: Personal site auth upgrade
-- PBKDF2 + email verification + refresh tokens
ALTER TABLE users ADD COLUMN salt TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN hash_version INTEGER DEFAULT 0;
UPDATE users SET hash_version = 0 WHERE hash_version IS NULL OR hash_version = 0;
