-- Migration 0010: Fix page_views table
-- Problem: INSERTs had no id value, causing all rows to have NULL id
-- Fix: Rebuild with proper PRIMARY KEY that auto-generates

-- Use INTEGER PRIMARY KEY for auto-increment behavior in SQLite
CREATE TABLE IF NOT EXISTS page_views_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path TEXT NOT NULL DEFAULT '/',
  ip TEXT DEFAULT '',
  user_agent TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now'))
);

-- Copy existing data (NULL ids will become auto-incremented)
INSERT INTO page_views_new (path, ip, user_agent, created_at)
  SELECT path, ip, user_agent, created_at FROM page_views;

-- Drop old and rename
DROP TABLE page_views;
ALTER TABLE page_views_new RENAME TO page_views;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_page_views_path ON page_views(path);
CREATE INDEX IF NOT EXISTS idx_page_views_created_at ON page_views(created_at);
