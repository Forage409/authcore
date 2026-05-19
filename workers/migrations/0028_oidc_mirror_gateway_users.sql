-- 回填：已有 OIDC 授权但 gateway_users 无记录的用户，创建镜像记录
INSERT OR IGNORE INTO gateway_users (id, email, password_hash, username, salt, hash_version, created_by, api_key_id)
SELECT i.id, i.email, '', COALESCE(i.username, i.email), '', 1, i.id, g.api_key_id
FROM oidc_grants g
JOIN oidc_identities i ON g.identity_id = i.id
LEFT JOIN gateway_users gu ON gu.id = i.id AND gu.api_key_id = g.api_key_id
WHERE gu.id IS NULL;
