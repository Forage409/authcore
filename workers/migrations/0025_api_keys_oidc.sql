-- 给 api_keys 加 OIDC 配置字段
ALTER TABLE api_keys ADD COLUMN oidc_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE api_keys ADD COLUMN redirect_uris TEXT DEFAULT '';
ALTER TABLE api_keys ADD COLUMN client_secret_hash TEXT;
ALTER TABLE api_keys ADD COLUMN app_logo TEXT DEFAULT '';
ALTER TABLE api_keys ADD COLUMN app_homepage TEXT DEFAULT '';
