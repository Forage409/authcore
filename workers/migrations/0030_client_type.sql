-- 添加 client_type 列，区分 backend（后端服务，有 API Key）和 spa（纯前端，无 API Key，仅 OIDC）
ALTER TABLE api_keys ADD COLUMN client_type TEXT DEFAULT 'backend';

-- 将现有已开启 OIDC 且无 key_hash 的应用标记为可能的前端类型（手工判断）
-- 不做自动迁移：历史数据保持 'backend' 默认值，用户可在编辑页自行切换
