-- Migration 0014: Add salt column for PBKDF2 password hashing
ALTER TABLE gateway_users ADD COLUMN salt TEXT DEFAULT '';
ALTER TABLE gateway_users ADD COLUMN hash_version INTEGER DEFAULT 0;
-- hash_version: 0 = old SHA-256 (no salt), 1 = PBKDF2 with salt
