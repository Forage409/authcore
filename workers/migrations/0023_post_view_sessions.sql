-- 浏览数去重：同 viewer_key 30 分钟内仅计 1 次
CREATE TABLE IF NOT EXISTS post_view_sessions (
  post_id TEXT NOT NULL,
  viewer_key TEXT NOT NULL,  -- userId 或 sha256(ip+UA)
  expires_at TEXT NOT NULL,
  PRIMARY KEY (post_id, viewer_key)
);
CREATE INDEX IF NOT EXISTS idx_pvs_expires ON post_view_sessions(expires_at);
