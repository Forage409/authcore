-- 域名所有权验证（DNS TXT 法）
-- 每个 (user_id, domain) 一条记录，verified=1 表示该开发者已证明拥有该域名
-- challenge 是我们生成的随机字符串，开发者需要把它加到自家 DNS 的 TXT 记录里
-- 我们用 Cloudflare DoH 查 TXT 记录，匹配 → verified=1
--
-- 验证按 (user_id, domain) 隔离：devA 验过 example.com 不代表 devB 可以白嫖
CREATE TABLE IF NOT EXISTS domain_verifications (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  domain       TEXT NOT NULL,
  challenge    TEXT NOT NULL,
  verified     INTEGER NOT NULL DEFAULT 0,
  verified_at  TEXT,
  last_check_at TEXT,
  last_check_error TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now', '+8 hours')),
  UNIQUE (user_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_domain_verifications_user ON domain_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_domain_verifications_verified ON domain_verifications(verified);
