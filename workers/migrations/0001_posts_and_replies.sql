-- 博客动态表
CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  excerpt TEXT DEFAULT '',
  is_published INTEGER DEFAULT 1,
  views_count INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id);

-- 留言板回复支持
ALTER TABLE guestbook ADD COLUMN parent_id TEXT REFERENCES guestbook(id);
CREATE INDEX IF NOT EXISTS idx_guestbook_parent ON guestbook(parent_id);
