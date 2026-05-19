-- 全社区每日邮件配额 + API Key 验证码开关备份/强制关闭
CREATE TABLE IF NOT EXISTS email_quota_daily (
  date TEXT PRIMARY KEY,                  -- 'YYYY-MM-DD' (Asia/Shanghai)
  sent_count INTEGER NOT NULL DEFAULT 0,
  limit_value INTEGER NOT NULL DEFAULT 100,
  locked INTEGER NOT NULL DEFAULT 0,       -- 1 表示该日已耗尽配额，触发降级
  forced_off_at TEXT                       -- 触发强制关 captcha 的时间
);

CREATE TABLE IF NOT EXISTS email_quota_config (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
INSERT OR IGNORE INTO email_quota_config (k, v) VALUES ('daily_limit', '100');

-- API Key 验证码开关：双字段设计
-- captcha_enabled    = 用户意愿（开发者自己的开关）
-- captcha_forced_off = 系统强制关闭（配额耗尽时置 1）
-- 实际生效 = captcha_enabled AND NOT captcha_forced_off
ALTER TABLE api_keys ADD COLUMN captcha_enabled INTEGER NOT NULL DEFAULT 1;
ALTER TABLE api_keys ADD COLUMN captcha_forced_off INTEGER NOT NULL DEFAULT 0;

-- 备份表：审计冗余，确保次日恢复绝不出错
CREATE TABLE IF NOT EXISTS captcha_state_backup (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  date TEXT NOT NULL,
  api_key_id TEXT NOT NULL,
  original_enabled INTEGER NOT NULL,
  restored INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(date, api_key_id)
);
CREATE INDEX IF NOT EXISTS idx_captcha_backup_date_restored ON captcha_state_backup(date, restored);
