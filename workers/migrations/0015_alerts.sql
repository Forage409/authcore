CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  api_key_id TEXT,
  type TEXT NOT NULL DEFAULT 'multi_ip',
  detail TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_api_key ON alerts(api_key_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
