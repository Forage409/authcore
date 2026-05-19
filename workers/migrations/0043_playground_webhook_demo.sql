-- Playground Webhook 演示：临时 sink 接收器 + 签名校验
-- 每个访客生成独立的 sink_id + HMAC secret，30 分钟后失效
-- 与生产 webhooks 表完全独立，零数据污染

CREATE TABLE IF NOT EXISTS demo_webhook_sinks (
  sink_id TEXT PRIMARY KEY,
  secret TEXT NOT NULL,                  -- HMAC-SHA256 签名密钥
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL               -- 30 分钟后过期，cron 清理
);

CREATE INDEX IF NOT EXISTS idx_demo_webhook_sinks_expires ON demo_webhook_sinks(expires_at);

CREATE TABLE IF NOT EXISTS demo_webhook_events (
  id TEXT PRIMARY KEY,
  sink_id TEXT NOT NULL,
  event_type TEXT NOT NULL,              -- user.created / user.banned / oidc.token_issued 等
  payload TEXT NOT NULL,                 -- 投递的完整 JSON
  signature_header TEXT NOT NULL,        -- 收到的 X-AuthCore-Signature 值
  signature_valid INTEGER NOT NULL,      -- sink 端校验结果（1=有效 / 0=被篡改）
  received_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_demo_webhook_events_sink ON demo_webhook_events(sink_id, received_at);
