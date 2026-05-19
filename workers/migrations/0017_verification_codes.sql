CREATE TABLE IF NOT EXISTS verification_codes (
  id TEXT PRIMARY KEY,
  api_key_id TEXT NOT NULL,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  type TEXT DEFAULT 'register',
  expires_at TEXT NOT NULL,
  attempts INTEGER DEFAULT 0,
  used INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_vc_email_api ON verification_codes(email, api_key_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_vc_expires ON verification_codes(expires_at);
