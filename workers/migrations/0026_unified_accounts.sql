-- 三表合一：oidc_identities 升级为官方三站统一账号表
-- 个人站 users / 网关 gateway_users 保留只读作为外键源
-- 新注册时双写 oidc_identities + 对应旧表（id 一致，互为镜像）

-- 1. 扩展字段
ALTER TABLE oidc_identities ADD COLUMN is_personal INTEGER NOT NULL DEFAULT 1;
ALTER TABLE oidc_identities ADD COLUMN is_gateway_dev INTEGER NOT NULL DEFAULT 1;
ALTER TABLE oidc_identities ADD COLUMN last_login_at TEXT;

-- 2. 回填：从 users 导入（个人站存量）
INSERT OR IGNORE INTO oidc_identities
  (id, email, email_verified, password_hash, salt, hash_version, username, avatar_url, is_personal, is_gateway_dev, created_at)
SELECT
  id, email, 1, password_hash,
  COALESCE(salt, ''), COALESCE(hash_version, 0),
  COALESCE(username, ''), COALESCE(avatar_url, ''),
  1, 0,
  COALESCE(created_at, datetime('now', '+8 hours'))
FROM users
WHERE email IS NOT NULL AND password_hash IS NOT NULL;

-- 3. 回填：从 gateway_users 导入（网关开发者，仅 id=created_by 的主账号）
INSERT OR IGNORE INTO oidc_identities
  (id, email, email_verified, password_hash, salt, hash_version, username, is_personal, is_gateway_dev, created_at)
SELECT
  id, email, 1, password_hash,
  COALESCE(salt, ''), COALESCE(hash_version, 0),
  COALESCE(username, ''),
  0, 1,
  COALESCE(created_at, datetime('now', '+8 hours'))
FROM gateway_users
WHERE id = created_by AND email IS NOT NULL AND password_hash IS NOT NULL;

-- 4. 同邮箱已在 oidc_identities，但 users/gateway_users 中也有 → 把 flag 打上
UPDATE oidc_identities
SET is_personal = 1
WHERE email IN (SELECT email FROM users);

UPDATE oidc_identities
SET is_gateway_dev = 1
WHERE email IN (SELECT email FROM gateway_users WHERE id = created_by);
