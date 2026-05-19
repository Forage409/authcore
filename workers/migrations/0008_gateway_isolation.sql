-- 开发者隔离：gateway_users 关联到创建者
ALTER TABLE gateway_users ADD COLUMN created_by TEXT;
CREATE INDEX IF NOT EXISTS idx_gateway_users_created_by ON gateway_users(created_by);
