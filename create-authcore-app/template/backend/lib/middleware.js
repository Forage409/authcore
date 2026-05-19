/**
 * AuthCore 鉴权中间件
 * 支持两种 token：
 *   - AuthCore API Key JWT（password 注册/登录）：通过 AuthCore.verify() 验证
 *   - AuthCore OIDC access_token（一键授权登录）：通过 /oauth/userinfo 验证
 *
 * 用法：
 *   const { requireAuth } = require('./lib/middleware');
 *   app.get('/api/protected', requireAuth(auth), (req, res) => {
 *     res.json({ user: req.user });
 *   });
 */
function requireAuth(auth, opts = {}) {
  const userinfoUrl = opts.userinfoUrl || 'https://auth.miaogou.site/oauth/userinfo';

  return async function (req, res, next) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace(/^Bearer /, '');

    if (!token) {
      return res.status(401).json({ error: '未提供认证令牌' });
    }

    // 方案 A：AuthCore API Key JWT
    try {
      const r = await auth.verify(token);
      if (r && r.valid) {
        req.user = r.user || { sub: r.sub };
        req.authMethod = 'apikey';
        return next();
      }
    } catch (_) { /* 不是 AuthCore JWT，继续试 OIDC */ }

    // 方案 B：OIDC access_token → /oauth/userinfo
    try {
      const ui = await fetch(userinfoUrl, {
        headers: { Authorization: 'Bearer ' + token },
      });
      if (ui.ok) {
        const info = await ui.json();
        if (info && info.sub) {
          req.user = info;
          req.authMethod = 'oidc';
          return next();
        }
      }
    } catch (_) { /* userinfo 失败，最终拒绝 */ }

    return res.status(401).json({ error: '安全令牌无效或已过期，请重新登录' });
  };
}

module.exports = { requireAuth };
