-- Migration 0009: Fix gateway_users data isolation
-- Problem: UNIQUE(email) was global, preventing same email across different API keys
-- Fix: Rebuild table with UNIQUE(email, created_by) + add api_key_id column

-- Step 1: Create new table with correct constraints
CREATE TABLE IF NOT EXISTS gateway_users_new (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  username TEXT NOT NULL DEFAULT '',
  created_at TEXT DEFAULT (datetime('now')),
  created_by TEXT,
  api_key_id TEXT,
  UNIQUE(email, created_by)
);

-- Step 2: Copy existing data (api_key_id will be NULL for old records)
INSERT INTO gateway_users_new (id, email, password_hash, username, created_at, created_by)
  SELECT id, email, password_hash, username, created_at, created_by FROM gateway_users;

-- Step 3: Drop old table and rename new one
DROP TABLE gateway_users;
ALTER TABLE gateway_users_new RENAME TO gateway_users;

-- Step 4: Recreate indexes
CREATE INDEX IF NOT EXISTS idx_gateway_users_email ON gateway_users(email);
CREATE INDEX IF NOT EXISTS idx_gateway_users_created_by ON gateway_users(created_by);
CREATE INDEX IF NOT EXISTS idx_gateway_users_api_key_id ON gateway_users(api_key_id);
