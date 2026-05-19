-- 跨端强制同意协议系统：以邮箱为主键的共享同意状态表
-- 三端共用（personal / gateway / user-center），由所有 Worker 直接读写
-- 用邮箱做主键的原因：三个用户表的唯一共同字段是邮箱
-- consent_version 用于将来 ToS 更新后强制重新弹窗（只需提升版本号）
CREATE TABLE IF NOT EXISTS user_consent (
  email           TEXT PRIMARY KEY,
  consent_version TEXT NOT NULL,
  accepted_at     TEXT NOT NULL DEFAULT (datetime('now', '+8 hours')),
  source          TEXT NOT NULL,   -- 'personal' | 'gateway' | 'user-center'
  ip              TEXT,
  user_agent      TEXT
);

-- 按版本查询的索引：定期统计某个版本的接受率
CREATE INDEX IF NOT EXISTS idx_user_consent_version ON user_consent(consent_version);
