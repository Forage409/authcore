-- Webhook 按 API Key 过滤
-- 此前 webhooks 表只按 user_id 绑定，一个开发者下所有应用的事件混在一起
-- 加 api_key_id 列：NULL = 该开发者所有应用都触发（向后兼容）；非 NULL = 仅指定 app 触发
ALTER TABLE webhooks ADD COLUMN api_key_id TEXT;

-- 加索引便于 dispatchWebhooks 按 (user_id, api_key_id) 过滤
CREATE INDEX IF NOT EXISTS idx_webhooks_user_app ON webhooks(user_id, api_key_id);
