CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  url TEXT NOT NULL,
  events TEXT NOT NULL DEFAULT 'user.registered,user.login',
  secret TEXT DEFAULT '',
  active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhooks(user_id);
