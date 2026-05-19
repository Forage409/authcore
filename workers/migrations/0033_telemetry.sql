-- Telemetry — anonymous SDK/CLI 活跃统计
-- 设计原则：
--   1. device_id 是客户端本地 hash（Node 端：MAC + hostname 的 SHA256 前 32 位；浏览器端：localStorage 内一次性生成的 UUID）
--   2. 不存 IP、不存用户名、不存 API Key 原文（只存 sha256 前 16 位 = app_hash 用于按应用维度聚合）
--   3. 支持 NEXUS_AUTH_TELEMETRY_DISABLED=1 / DO_NOT_TRACK=1 / CI=true 三种环境变量关闭，以及 localStorage 关闭开关
CREATE TABLE IF NOT EXISTS telemetry_active (
  device_id   TEXT NOT NULL,
  sdk_name    TEXT NOT NULL,
  sdk_version TEXT NOT NULL,
  os          TEXT NOT NULL DEFAULT '',
  os_version  TEXT NOT NULL DEFAULT '',
  runtime     TEXT NOT NULL DEFAULT '',
  app_hash    TEXT NOT NULL DEFAULT '',
  first_seen  TEXT DEFAULT (datetime('now', '+8 hours')),
  last_seen   TEXT DEFAULT (datetime('now', '+8 hours')),
  seen_count  INTEGER DEFAULT 1,
  PRIMARY KEY (device_id, sdk_name)
);
CREATE INDEX IF NOT EXISTS idx_telemetry_last_seen ON telemetry_active(last_seen);
CREATE INDEX IF NOT EXISTS idx_telemetry_sdk_name ON telemetry_active(sdk_name);
CREATE INDEX IF NOT EXISTS idx_telemetry_app_hash ON telemetry_active(app_hash);
