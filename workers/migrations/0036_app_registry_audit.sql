-- 应用注册审计 + 溯源支持
-- 每次应用创建/更新 OIDC 配置/轮换密钥时记录一条审计行：
--   - 开发者注册时的 IP、UA、邮箱（间接关联）
--   - Redirect URI 域名的 DNS 解析（A / AAAA），用于追溯到实际服务器
--   - 关键词扫描结果（pass / rejected / flagged）+ 命中词
-- 用途：收到执法机关请求时，能立即拉出某应用注册者的真实身份线索
CREATE TABLE IF NOT EXISTS app_registry_audit (
  id              TEXT PRIMARY KEY,
  api_key_id      TEXT NOT NULL,
  user_id         TEXT NOT NULL,
  action          TEXT NOT NULL,            -- 'create' | 'update_oidc' | 'rotate_key' | 'generate_key'
  app_name        TEXT,
  client_type     TEXT,
  app_homepage    TEXT,
  redirect_uris   TEXT,
  developer_ip    TEXT,
  developer_ua    TEXT,
  dns_resolutions TEXT,                     -- JSON: {"example.com":{"a":["1.2.3.4"],"aaaa":[]},...}
  scan_result     TEXT NOT NULL DEFAULT 'pass',  -- 'pass' | 'rejected' | 'flagged'
  scan_hits       TEXT,                     -- 命中关键词列表（逗号分隔）+ 类别
  created_at      TEXT NOT NULL DEFAULT (datetime('now', '+8 hours'))
);

CREATE INDEX IF NOT EXISTS idx_audit_api_key      ON app_registry_audit(api_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user         ON app_registry_audit(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_scan_result  ON app_registry_audit(scan_result, created_at DESC);
