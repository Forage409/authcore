-- Migration 0013: Login attempts tracking for account lockout
CREATE TABLE IF NOT EXISTS login_attempts (
  email TEXT NOT NULL,
  ip TEXT NOT NULL,
  success INTEGER DEFAULT 0,
  attempted_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts(email, attempted_at);
