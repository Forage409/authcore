-- 移除 api_keys 的外键约束，兼容 gateway_users
CREATE TABLE api_keys_new (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT DEFAULT 'Default',
  key_hash TEXT NOT NULL,
  revoked INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);
INSERT INTO api_keys_new SELECT id, user_id, name, key_hash, revoked, created_at FROM api_keys;
DROP TABLE api_keys;
ALTER TABLE api_keys_new RENAME TO api_keys;
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
