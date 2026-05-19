-- 修复 CSRF 多端互踢：把 user_sessions 改为 (user_id, session_id) 复合主键
-- 每个端登录/refresh 分配独立 session_id，互不影响
CREATE TABLE user_sessions_new (
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  csrf_token TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, session_id)
);
-- 旧数据不迁移：所有现有用户首次访问会自动拿到新 session_id
DROP TABLE IF EXISTS user_sessions;
ALTER TABLE user_sessions_new RENAME TO user_sessions;
CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);
