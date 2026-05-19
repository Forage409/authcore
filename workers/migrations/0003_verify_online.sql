-- 友链验证
ALTER TABLE friend_links ADD COLUMN status TEXT DEFAULT 'verified';
ALTER TABLE friend_links ADD COLUMN verify_token TEXT;
UPDATE friend_links SET status = 'verified';
CREATE INDEX IF NOT EXISTS idx_friend_links_status ON friend_links(status);

-- 在线用户表
CREATE TABLE IF NOT EXISTS online_users (
  id TEXT PRIMARY KEY,
  ip TEXT NOT NULL,
  path TEXT DEFAULT '/',
  last_seen TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_online_last_seen ON online_users(last_seen);
