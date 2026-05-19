-- Webhook 投递历史表：每次派发尝试都写一行，前端 Webhooks 页面可读最近 50 条
-- attempt 从 1 开始；status_code 为 0 代表网络失败/超时（看 error_text）
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id TEXT PRIMARY KEY,
  webhook_id TEXT NOT NULL,
  event TEXT NOT NULL,
  attempt INTEGER NOT NULL DEFAULT 1,
  status_code INTEGER NOT NULL DEFAULT 0,
  success INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  error_text TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now', '+8 hours'))
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook
  ON webhook_deliveries(webhook_id, created_at DESC);
