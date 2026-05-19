CREATE TABLE IF NOT EXISTS email_logs (
  id TEXT PRIMARY KEY,
  api_key_id TEXT NOT NULL,
  to_email TEXT NOT NULL,
  success INTEGER NOT NULL DEFAULT 0,
  error TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_el_api_key ON email_logs(api_key_id, created_at);
CREATE INDEX IF NOT EXISTS idx_el_created ON email_logs(created_at);
