-- OIDC 全局身份池 + 授权码 + SSO 会话 + 签名密钥
-- 与现有 gateway_users (per-app 用户) 完全独立

CREATE TABLE IF NOT EXISTS oidc_identities (
  id TEXT PRIMARY KEY,                                                -- UUID, OIDC sub
  email TEXT UNIQUE NOT NULL,
  email_verified INTEGER NOT NULL DEFAULT 0,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  hash_version INTEGER NOT NULL DEFAULT 1,                            -- 1=PBKDF2 100k
  username TEXT NOT NULL DEFAULT '',
  avatar_url TEXT NOT NULL DEFAULT '',
  created_at TEXT DEFAULT (datetime('now', '+8 hours'))
);
CREATE INDEX IF NOT EXISTS idx_oidc_identities_email ON oidc_identities(email);

-- 全局身份 ↔ 应用授权记录
CREATE TABLE IF NOT EXISTS oidc_grants (
  identity_id TEXT NOT NULL,
  api_key_id TEXT NOT NULL,
  scopes TEXT NOT NULL,
  first_authorized_at TEXT DEFAULT (datetime('now', '+8 hours')),
  last_used_at TEXT DEFAULT (datetime('now', '+8 hours')),
  PRIMARY KEY (identity_id, api_key_id)
);

-- 一次性授权码
CREATE TABLE IF NOT EXISTS oidc_codes (
  code TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL,
  api_key_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  nonce TEXT,
  code_challenge TEXT,
  code_challenge_method TEXT,
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now', '+8 hours'))
);
CREATE INDEX IF NOT EXISTS idx_oidc_codes_expires ON oidc_codes(expires_at);

-- SSO Cookie session
CREATE TABLE IF NOT EXISTS oidc_sso_sessions (
  session_id TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now', '+8 hours'))
);
CREATE INDEX IF NOT EXISTS idx_oidc_sso_expires ON oidc_sso_sessions(expires_at);

-- OIDC access/refresh tokens（与现有 refresh_tokens 分离）
CREATE TABLE IF NOT EXISTS oidc_tokens (
  token_hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL,                                                  -- 'refresh' | 'access'
  identity_id TEXT NOT NULL,
  api_key_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now', '+8 hours'))
);
CREATE INDEX IF NOT EXISTS idx_oidc_tokens_identity ON oidc_tokens(identity_id);

-- RS256 签名密钥
CREATE TABLE IF NOT EXISTS oidc_signing_keys (
  kid TEXT PRIMARY KEY,
  alg TEXT NOT NULL DEFAULT 'RS256',
  public_jwk TEXT NOT NULL,
  private_pkcs8 TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now', '+8 hours'))
);
