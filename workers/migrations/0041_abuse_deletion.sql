-- Feature 1: 公开举报系统
-- 任何访客（包括未登录）可提交针对某 app / 某用户 / 某内容的举报
-- target_type/target_id 软约束：站长复核时人工校验，不在 DB 层强制外键（防告警瀑布）
CREATE TABLE IF NOT EXISTS abuse_reports (
  id              TEXT PRIMARY KEY,
  target_type     TEXT NOT NULL,        -- 'api_key' | 'oidc_app' | 'user_email' | 'content_url' | 'other'
  target_id       TEXT NOT NULL,        -- api_key.id / oidc_identities.id / email / URL
  category        TEXT NOT NULL,        -- 'illegal' | 'porn' | 'gambling' | 'phishing' | 'csam' | 'malware' | 'copyright' | 'harassment' | 'other'
  description     TEXT NOT NULL,
  reporter_email  TEXT,                 -- 可选；匿名举报留空
  reporter_ip     TEXT,
  reporter_ua     TEXT,
  status          TEXT NOT NULL DEFAULT 'pending',  -- 'pending' | 'resolved' | 'rejected' | 'duplicate'
  resolved_by     TEXT,
  resolved_at     TEXT,
  resolution_note TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now', '+8 hours'))
);
CREATE INDEX IF NOT EXISTS idx_abuse_status ON abuse_reports(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_abuse_target ON abuse_reports(target_type, target_id);

-- Feature 3: 账户自助注销 14 天缓冲期（兑现 ToS § 6 承诺）
-- 入表 = 进入冷却；user 仍可登录但页面显示"X 天后注销"黄条 + 撤销按钮
-- scheduled_at 到点后 cron 真删数据；删除前 24h 再发邮件提醒
CREATE TABLE IF NOT EXISTS pending_deletions (
  email          TEXT PRIMARY KEY,
  user_id        TEXT NOT NULL,        -- 冗余存：删除时按 id 清 oidc_identities/users/gateway_users
  requested_at   TEXT NOT NULL DEFAULT (datetime('now', '+8 hours')),
  scheduled_at   TEXT NOT NULL,        -- 注销执行时间 = requested_at + 14 天
  requester_ip   TEXT,
  source         TEXT NOT NULL,        -- 'user-center' | 'personal-site' | 'gateway'
  reminder_sent  INTEGER NOT NULL DEFAULT 0   -- 24h 倒计时邮件是否已发
);
CREATE INDEX IF NOT EXISTS idx_pending_deletions_scheduled ON pending_deletions(scheduled_at);

-- 永久审计：注销完成后写一条，原行删除；用于法律响应时证明"用户确实自助注销了"
CREATE TABLE IF NOT EXISTS deletion_audit_log (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL,
  user_id       TEXT NOT NULL,
  requested_at  TEXT NOT NULL,
  executed_at   TEXT NOT NULL,
  cancelled_at  TEXT,                  -- 非空 = 用户撤销了，未真删
  source        TEXT NOT NULL,
  requester_ip  TEXT
);
CREATE INDEX IF NOT EXISTS idx_deletion_audit_email ON deletion_audit_log(email);
