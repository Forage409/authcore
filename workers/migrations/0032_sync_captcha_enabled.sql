-- 修复历史 API Key 中 require_email_verification 与 captcha_enabled 不同步的数据
-- 背景：
--   /api/auth/send-code 的闸门 = require_email_verification AND captcha_enabled AND NOT captcha_forced_off
--   CREATE 端正确地把两列同步设置；但旧版 PUT /api/clients/:id 只改 require_email_verification，
--   导致用户「创建时不开 → 编辑时开启」后 captcha_enabled 仍是 0，闸门 false，发送验证码报"未开启"。
--
-- 修复策略：把所有非强制关闭、且 require_email_verification = 1 的行的 captcha_enabled 拉齐为 1。
-- 不动 captcha_forced_off = 1 的行（那些是系统因配额耗尽强制关闭的，要保留意愿位但不让生效）。
UPDATE api_keys
   SET captcha_enabled = 1
 WHERE require_email_verification = 1
   AND captcha_enabled = 0
   AND captcha_forced_off = 0;
