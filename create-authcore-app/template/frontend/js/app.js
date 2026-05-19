/* ──────────────────────────────────────────────────────────────
 * AuthCore Starter — 前端公共工具
 *  - api()        通用请求 + 401 自动刷新
 *  - getConfig()  应用配置自检（缓存 60s，注册页据此决定是否显示验证 UI）
 *  - 持久化登录：JWT 过期时自动用 refresh_token 续期，无感
 *  - 标签页后台回前台时主动刷新一次，避免 SPA 长时间停留后点击无响应
 *  - 支持两种登录方式：password（API Key 注册/登录）和 oidc（一键授权）
 * ────────────────────────────────────────────────────────────── */
const API_BASE = '/api';

function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

// ── Token / User ──
function saveToken(token) { localStorage.setItem('auth_token', token); }
function getToken() { return localStorage.getItem('auth_token'); }
function clearToken() { localStorage.removeItem('auth_token'); }

function saveUser(user) { localStorage.setItem('auth_user', JSON.stringify(user)); }
function getUser() {
  try { return JSON.parse(localStorage.getItem('auth_user')); }
  catch { return null; }
}
function clearUser() { localStorage.removeItem('auth_user'); }
function getRefreshToken() { return localStorage.getItem('refresh_token'); }
function saveRefreshToken(rt) { if (rt) localStorage.setItem('refresh_token', rt); }
function clearRefreshToken() { localStorage.removeItem('refresh_token'); }

function getLoginMethod() { return localStorage.getItem('login_method') || 'password'; }

// 兼容旧脚手架字段
function saveDevToken(t) { localStorage.setItem('dev_token', t); }
function getDevToken() { return localStorage.getItem('dev_token'); }
function clearDevToken() { localStorage.removeItem('dev_token'); }

// ── 静默刷新（password 走 /api/user/refresh，oidc 走 /oauth/token） ──
let _refreshing = null;
async function tryRefresh() {
  if (_refreshing) return _refreshing;
  const rt = getRefreshToken();
  if (!rt) return Promise.resolve(false);
  const isOidc = getLoginMethod() === 'oidc';
  if (isOidc) {
    const clientId = localStorage.getItem('oidc_client_id') || '';
    _refreshing = fetch(API_BASE + '/user/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: rt, oidc: true, clientId: clientId }),
    })
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(d) {
        if (d && d.access_token) {
          saveToken(d.access_token);
          if (d.refresh_token) saveRefreshToken(d.refresh_token);
          return true;
        }
        return false;
      })
      .catch(function() { return false; })
      .finally(function() { _refreshing = null; });
    return _refreshing;
  }
  _refreshing = fetch(API_BASE + '/user/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken: rt }),
  })
    .then(function(r) { return r.ok ? r.json() : null; })
    .then(function(d) {
      if (d && d.token) {
        saveToken(d.token);
        if (d.refreshToken) saveRefreshToken(d.refreshToken);
        return true;
      }
      return false;
    })
    .catch(function() { return false; })
    .finally(function() { _refreshing = null; });
  return _refreshing;
}

// ── 会话撤销处理（用户在 user.miaogou.site 撤销授权后让本应用自动登出） ──
function handleSessionRevoked() {
  clearToken(); clearUser(); clearRefreshToken();
  localStorage.removeItem('login_method'); localStorage.removeItem('oidc_client_id');
  if (!/\/(index\.html)?$|register\.html$/.test(window.location.pathname)) {
    window.location.replace('/?reason=revoked');
  }
}

// ── 通用请求：401 自动 refresh + 重试一次 ──
async function api(url, opts = {}, _retry = false) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  const tk = getToken();
  if (tk && !headers.Authorization) headers.Authorization = 'Bearer ' + tk;
  const res = await fetch(API_BASE + url, { ...opts, headers });
  if (res.status === 401 && !_retry && getRefreshToken()) {
    if (await tryRefresh()) return api(url, opts, true);
    // 刷新失败：会话已被撤销或彻底失效
    handleSessionRevoked();
  } else if (res.status === 401 && !_retry && !getRefreshToken() && getToken()) {
    // 有 token 无 refresh：直接判定撤销
    handleSessionRevoked();
  }
  return res.json().catch(() => ({}));
}

// ── 会话轮询：每 60 秒静默 verify 一次，及时发现服务端撤销 ──
function startSessionWatch(intervalMs) {
  if (typeof window === 'undefined') return () => {};
  const ms = intervalMs || 60000;
  const id = setInterval(async () => {
    if (!getToken()) return;
    if (document.visibilityState !== 'visible') return;
    try {
      const r = await fetch(API_BASE + '/user/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: getToken() }),
      });
      if (r.status === 401) { handleSessionRevoked(); return; }
      const d = await r.json().catch(() => ({}));
      if (d && d.valid === false) {
        // 尝试 refresh 救一次；不行就判撤销
        if (!(await tryRefresh())) handleSessionRevoked();
      }
    } catch { /* 网络错误忽略，下次再试 */ }
  }, ms);
  return () => clearInterval(id);
}
// 仅在登录态页面启动
if (typeof window !== 'undefined' && !/\/(index\.html)?$|register\.html$/.test(window.location.pathname)) {
  if (getToken()) startSessionWatch(60000);
}

// ── 应用配置自检（缓存 60 秒） ──
let _configCache = null;
let _configCacheAt = 0;
async function getConfig() {
  const now = Date.now();
  if (_configCache && now - _configCacheAt < 60000) return _configCache;
  try {
    const r = await fetch(API_BASE + '/config');
    const d = await r.json();
    _configCache = d;
    _configCacheAt = now;
    return d;
  } catch {
    return { require_email_verification: false };
  }
}

// ── 登录态守卫 ──
function checkAuth() {
  const token = getToken();
  const user = getUser();
  if (!token || !user) { window.location.href = '/'; return null; }
  return { token, user };
}

// ── 登出 ──
async function logout() {
  const rt = getRefreshToken();
  if (rt) {
    try {
      const isOidc = getLoginMethod() === 'oidc';
      await fetch(API_BASE + '/user/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          refreshToken: rt,
          oidc: isOidc,
          clientId: isOidc ? (localStorage.getItem('oidc_client_id') || '') : undefined,
        }),
      });
    } catch { /* 忽略，登出无论如何要清本地 */ }
  }
  clearToken(); clearUser(); clearRefreshToken();
  localStorage.removeItem('login_method'); localStorage.removeItem('oidc_client_id');
  window.location.href = '/';
}

// ── 标签页可见性变化：从后台回到前台时静默刷新一次 token，避免点击无响应 ──
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && getToken() && getRefreshToken()) {
    tryRefresh();
  }
});
