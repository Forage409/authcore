-- Playground 演示 OIDC：与生产 OIDC 完全隔离的轻量授权码 + token 存储
-- 设计：所有行 60 秒后失效（code 寿命短）；access/id token 1h；不存 refresh（演示无需）
-- 表名 prefix demo_ 让所有相关数据在审计时显眼

CREATE TABLE IF NOT EXISTS demo_oidc_codes (
  code TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,         -- 必须等于 env.PLAYGROUND_DEMO_CLIENT_ID 才能换 token
  redirect_uri TEXT NOT NULL,
  scope TEXT DEFAULT 'openid email profile',
  code_challenge TEXT,
  code_challenge_method TEXT,
  nonce TEXT,
  state TEXT,
  demo_user_id TEXT NOT NULL,      -- 对应 users.id（demo tenant 里的）
  demo_email TEXT NOT NULL,
  demo_username TEXT,
  expires_at TEXT NOT NULL,        -- ISO 8601；60s 寿命
  used_at TEXT DEFAULT NULL        -- 一次性：换过 token 后填值
);

CREATE INDEX IF NOT EXISTS idx_demo_oidc_codes_expires ON demo_oidc_codes(expires_at);

-- access_token / id_token JWT 是 stateless 的（含 sub / exp claim 内）
-- 所以不需要存 token；但需要存"已签发的会话"用于撤销与 userinfo 反查
CREATE TABLE IF NOT EXISTS demo_oidc_sessions (
  session_id TEXT PRIMARY KEY,
  demo_user_id TEXT NOT NULL,
  demo_email TEXT NOT NULL,
  client_id TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_demo_oidc_sessions_expires ON demo_oidc_sessions(expires_at);
