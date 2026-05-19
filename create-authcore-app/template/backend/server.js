/**
 * AuthCore 后端转发服务
 * 启动: npm start
 *
 * 支持两种登录方式：
 *   - password: API Key 邮箱注册/登录 → auth.register / auth.login
 *   - oidc:     OIDC 一键授权 → callback.html 拿到 access_token 后通过本服务调用 /oauth/userinfo
 */
const path = require('path');
const express = require('express');
const cors = require('cors');
const { AuthCore } = require('./lib/authcore');
const { requireAuth } = require('./lib/middleware');

require('dotenv').config();

if (!process.env.AUTHCORE_API_KEY || process.env.AUTHCORE_API_KEY === 'nx_your_api_key_here') {
  console.error('请先在 backend/.env 中设置 AUTHCORE_API_KEY');
  console.error('获取 Key: https://auth.miaogou.site');
  process.exit(1);
}

const auth = new AuthCore({ apiKey: process.env.AUTHCORE_API_KEY });
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.resolve(__dirname, '../frontend')));

app.use((req, _res, next) => {
  console.log(`${new Date().toISOString().slice(0, 19)} ${req.method} ${req.path}`);
  next();
});

// ══════ 演示受保护端点 ══════
app.get('/api/user/me', requireAuth(auth), (req, res) => {
  res.json({ user: req.user, authMethod: req.authMethod });
});

// ══════ Auth routes ══════
app.post('/api/user/register', async (req, res) => {
  const { email, password, username } = req.body;
  if (!email || !password) return res.status(400).json({ error: '邮箱和密码必填' });
  try { res.json(await auth.register({ email, password, username })); }
  catch (e) { res.status(e.status || 400).json({ error: e.code || 'request_failed', message: e.message }); }
});

app.post('/api/user/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: '邮箱和密码必填' });
  try { res.json(await auth.login({ email, password })); }
  catch (e) { res.status(e.status || 401).json({ error: e.code || 'invalid_credentials', message: e.message }); }
});

app.post('/api/user/verify', async (req, res) => {
  const token = req.body.token;
  if (!token) return res.status(400).json({ error: 'Token 必填' });
  try {
    const j = await auth.verify(token);
    if (j && j.valid) return res.json(j);
  } catch { /* 不是 AuthCore JWT，降级 OIDC */ }
  try { return res.json(await auth.verifyOidc(token)); }
  catch { return res.json({ valid: false }); }
});

app.post('/api/user/refresh', async (req, res) => {
  try {
    const { refreshToken, oidc, clientId } = req.body;
    if (oidc) return res.json(await auth.refreshOidc(refreshToken, clientId));
    res.json(await auth.refresh(refreshToken));
  } catch (e) { res.status(401).json({ error: e.message }); }
});

app.post('/api/user/revoke', async (req, res) => {
  try {
    const { refreshToken, oidc, clientId } = req.body;
    if (oidc) return res.json(await auth.revokeOidc(refreshToken, clientId));
    res.json(await auth.revoke(refreshToken));
  } catch (e) { res.status(401).json({ error: e.message }); }
});

app.post('/api/user/send-code', async (req, res) => {
  try { res.json(await auth.sendCode({ email: req.body.email })); }
  catch (e) {
    // 透传 code（如 email_registered / verification_disabled）+ HTTP 状态，前端据此精准提示
    res.status(e.status || 400).json({ error: e.code || 'request_failed', message: e.message });
  }
});

app.post('/api/user/verify-code', async (req, res) => {
  try { res.json(await auth.verifyCode({ email: req.body.email, code: req.body.code })); }
  catch (e) {
    res.status(e.status || 400).json({ error: e.code || 'request_failed', message: e.message });
  }
});

app.get('/api/config', async (_req, res) => {
  try { res.json(await auth.getConfig()); }
  catch (e) { res.status(400).json({ error: e.message, require_email_verification: false }); }
});

// OIDC 回调：浏览器从 auth.miaogou.site 带 code 跳回来，后端用 code 换 token
// 仅当控制台开启 OIDC 才会被触发；开发者无需修改即可工作
app.get('/oidc/callback', async (req, res) => {
  const { code, state: returnedState } = req.query;
  if (!code) return res.status(400).send('missing code');
  // CSRF 防护：state 必须与跳转前写入的 cookie 一致（RFC 6749 §10.12）
  const cookieHeader = req.headers.cookie || '';
  const stateCookie = (cookieHeader.match(/(?:^|;\s*)oidc_state=([^;]*)/) || [])[1];
  const expectedState = stateCookie ? decodeURIComponent(stateCookie) : '';
  if (!expectedState || returnedState !== expectedState) {
    res.setHeader('Set-Cookie', ['oidc_state=; path=/; max-age=0; SameSite=Lax', 'oidc_verifier=; path=/; max-age=0; SameSite=Lax']);
    return res.status(400).send('OIDC state 校验失败（可能是 CSRF 攻击或会话过期）');
  }
  try {
    const cfg = await auth.getConfig();
    const proto = req.headers['x-forwarded-proto'] || req.protocol;
    const redirectUri = `${proto}://${req.headers.host}/oidc/callback`;
    // 从 cookie 读取 PKCE code_verifier（前端 index.html OIDC 按钮点击时写入），读后即清
    const cookieMatch = cookieHeader.match(/(?:^|;\s*)oidc_verifier=([^;]*)/);
    const codeVerifier = cookieMatch ? decodeURIComponent(cookieMatch[1]) : '';
    const tokenBody = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: cfg.client_id,
    });
    if (codeVerifier) tokenBody.set('code_verifier', codeVerifier);
    const r = await fetch('https://auth.miaogou.site/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: tokenBody,
    });
    const d = await r.json();
    if (!r.ok) return res.status(400).send('OIDC 换 token 失败：' + (d.error_description || d.error));
    // 用 access_token 拉 userinfo
    const uiRes = await fetch('https://auth.miaogou.site/oauth/userinfo', {
      headers: { Authorization: 'Bearer ' + d.access_token },
    });
    const info = await uiRes.json();
    // 把 token 透传给前端的 callback 页（前端写 localStorage 再跳 dashboard）
    const params = new URLSearchParams({
      access_token: d.access_token,
      refresh_token: d.refresh_token || '',
      user_id: info.sub || '',
      email: info.email || '',
      username: info.name || (info.email || '').split('@')[0],
      client_id: cfg.client_id,
    });
    // 清除 PKCE verifier 与 state cookie（一次性使用，立即作废）
    res.setHeader('Set-Cookie', ['oidc_verifier=; path=/; max-age=0; SameSite=Lax', 'oidc_state=; path=/; max-age=0; SameSite=Lax']);
    res.redirect('/oidc-callback.html?' + params);
  } catch (e) {
    res.setHeader('Set-Cookie', ['oidc_verifier=; path=/; max-age=0; SameSite=Lax', 'oidc_state=; path=/; max-age=0; SameSite=Lax']);
    res.status(500).send('OIDC 回调失败：' + e.message);
  }
});

app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`AuthCore 已启动: http://localhost:${PORT}`);
});
