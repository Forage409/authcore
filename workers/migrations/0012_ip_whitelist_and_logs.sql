-- Migration 0012: Add IP whitelist to api_keys and api_key_id to page_views
ALTER TABLE api_keys ADD COLUMN allowed_ips TEXT DEFAULT '';
ALTER TABLE page_views ADD COLUMN api_key_id TEXT;
CREATE INDEX IF NOT EXISTS idx_page_views_api_key ON page_views(api_key_id);
