-- 账号封禁系统（四网同步）
-- 触发场景：违反 ToS § 3（零容忍违法 / 色情 / 赌博 / 钓鱼 / 仇恨 / 滥用等）
-- 影响范围：
--   ① 登录被拒（个人站 / 网关 / 用户中心 / OIDC SSO 全部）
--   ② 现有 SSO 会话 + refresh_tokens 立即失效
--   ③ 第三方 OIDC 应用通过该账号的授权 + token 撤销
-- 与 `users.banned`、`api_keys.app_review_status='rejected'` 不同：
--   - revoked = 开发者自行撤销（软删）
--   - rejected = 应用层面被站长拒绝（仅影响该 app）
--   - banned  = 账号/key 层面被站长封禁（强追溯审计，含原因 + 操作者）

ALTER TABLE users ADD COLUMN banned INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN banned_at TEXT;
ALTER TABLE users ADD COLUMN banned_reason TEXT;
ALTER TABLE users ADD COLUMN banned_by TEXT;

ALTER TABLE oidc_identities ADD COLUMN banned INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oidc_identities ADD COLUMN banned_at TEXT;
ALTER TABLE oidc_identities ADD COLUMN banned_reason TEXT;
ALTER TABLE oidc_identities ADD COLUMN banned_by TEXT;

ALTER TABLE gateway_users ADD COLUMN banned INTEGER NOT NULL DEFAULT 0;
ALTER TABLE gateway_users ADD COLUMN banned_at TEXT;
ALTER TABLE gateway_users ADD COLUMN banned_reason TEXT;
ALTER TABLE gateway_users ADD COLUMN banned_by TEXT;

ALTER TABLE api_keys ADD COLUMN banned INTEGER NOT NULL DEFAULT 0;
ALTER TABLE api_keys ADD COLUMN banned_at TEXT;
ALTER TABLE api_keys ADD COLUMN banned_reason TEXT;
ALTER TABLE api_keys ADD COLUMN banned_by TEXT;

CREATE INDEX IF NOT EXISTS idx_users_banned ON users(banned);
CREATE INDEX IF NOT EXISTS idx_oidc_identities_banned ON oidc_identities(banned);
CREATE INDEX IF NOT EXISTS idx_gateway_users_banned ON gateway_users(banned);
CREATE INDEX IF NOT EXISTS idx_api_keys_banned ON api_keys(banned);

-- 审计：所有封禁/解封动作都写入 ban_audit_log，永久保留供法律响应
CREATE TABLE IF NOT EXISTS ban_audit_log (
  id           TEXT PRIMARY KEY,
  target_type  TEXT NOT NULL,           -- 'user' | 'oidc_identity' | 'gateway_user' | 'api_key'
  target_id    TEXT NOT NULL,
  target_email TEXT,                    -- 冗余：账号删除后仍能追溯
  action       TEXT NOT NULL,           -- 'ban' | 'unban'
  reason       TEXT,
  operator_email TEXT NOT NULL,         -- 操作者（必须是站长邮箱）
  operator_ip    TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now', '+8 hours'))
);
CREATE INDEX IF NOT EXISTS idx_ban_audit_target ON ban_audit_log(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_ban_audit_email ON ban_audit_log(target_email);
