-- 应用审核状态（防 OIDC 重定向钓鱼）
-- pending : 自定义域名未通过验证，仅应用所有者本人可登录（沙盒）
-- approved: localhost / 信任托管子域名 / DNS 已验证 / 站长手动批准
-- rejected: 站长手动拒绝（永久停用）
ALTER TABLE api_keys ADD COLUMN app_review_status TEXT NOT NULL DEFAULT 'pending';

-- 历史应用：在此功能上线前已创建的应用一律标 'approved'，避免破坏现有用户
-- 上线后新创建/编辑的应用会按真实规则重新打标
UPDATE api_keys SET app_review_status = 'approved' WHERE created_at < '2026-05-19';

-- 审核状态查询索引（管理后台按状态筛选用）
CREATE INDEX IF NOT EXISTS idx_api_keys_review_status ON api_keys(app_review_status);
