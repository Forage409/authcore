-- 把 OIDC 镜像用户的 created_by 从 identity_id 改为 API Key 拥有者
UPDATE gateway_users
SET created_by = (
  SELECT a.user_id FROM api_keys a
  JOIN oidc_grants g ON g.api_key_id = a.id
  WHERE g.identity_id = gateway_users.id
  ORDER BY g.last_used_at DESC
  LIMIT 1
)
WHERE id IN (SELECT identity_id FROM oidc_grants)
  AND created_by = id;  -- created_by 等于自己 id 的是被错误镜像的
