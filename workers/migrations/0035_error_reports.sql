-- 前端错误集中上报表
-- 三个站点（personal/gateway/user-center）的浏览器端运行时错误统一发到 auth.miaogou.site/telemetry/errors
-- 客户端 5 分钟内同 signature 去重；服务端按 sha256(source+type+message) 12 小时去重
CREATE TABLE IF NOT EXISTS error_reports (
  id          TEXT PRIMARY KEY,
  source      TEXT NOT NULL,            -- 'personal' | 'gateway' | 'user-center'
  type        TEXT NOT NULL,            -- 'runtime' | 'promise' | 'resource' | 'console' | 'vue' | 'react'
  message     TEXT NOT NULL,            -- 错误消息，截断 500 字符
  filename    TEXT,
  line        INTEGER DEFAULT 0,
  column_no   INTEGER DEFAULT 0,        -- 'column' 是 SQLite 保留字相关，加 _no 避免歧义
  stack       TEXT,                     -- 截断 2000 字符
  url         TEXT,                     -- 当前页面 URL（敏感 query 字段已剥除）
  ua          TEXT,                     -- User-Agent 截断 200
  info        TEXT,                     -- 框架级补充信息（如 Vue errorCaptured info）
  ip          TEXT,                     -- 服务端记录 CF-Connecting-IP
  created_at  TEXT NOT NULL DEFAULT (datetime('now', '+8 hours'))
);

-- 按站点 + 时间倒序查询
CREATE INDEX IF NOT EXISTS idx_error_reports_source_created ON error_reports(source, created_at DESC);
-- 按类型聚合统计
CREATE INDEX IF NOT EXISTS idx_error_reports_type_created ON error_reports(type, created_at DESC);
