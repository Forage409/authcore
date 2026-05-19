-- 把 oidc_identities 中没有 users/gateway_users 镜像的账号补齐
INSERT OR IGNORE INTO users (id, email, password_hash, username, avatar_url, salt, hash_version)
SELECT id, email, password_hash, COALESCE(username, ''), COALESCE(avatar_url, ''), COALESCE(salt, ''), COALESCE(hash_version, 1)
FROM oidc_identities;

INSERT OR IGNORE INTO gateway_users (id, email, password_hash, username, salt, hash_version, created_by)
SELECT id, email, password_hash, COALESCE(username, email), COALESCE(salt, ''), COALESCE(hash_version, 1), id
FROM oidc_identities;
