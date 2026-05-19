-- 举报反馈邮件可追溯性
-- 之前 sendAbuseResolutionEmail 是 fire-and-forget，DB 里完全不记录发送结果
-- 站长无从知道反馈邮件实际有没有到达举报人。补 4 个列让每一次投递都留痕

ALTER TABLE abuse_reports ADD COLUMN email_status TEXT;          -- 'pending' | 'sent' | 'failed' | 'no_email' | 'skipped_breaker'
ALTER TABLE abuse_reports ADD COLUMN email_sent_at TEXT;         -- 末次成功投递时间（北京时间）
ALTER TABLE abuse_reports ADD COLUMN email_last_error TEXT;      -- 末次失败错误（Resend 返回 / 网络错误等）
ALTER TABLE abuse_reports ADD COLUMN email_retry_count INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_abuse_email_status ON abuse_reports(email_status, resolved_at DESC);
