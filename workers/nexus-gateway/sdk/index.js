/**
 * nexus-auth-sdk — Auth as a Service
 * npm install nexus-auth-sdk
 *
 * const { AuthCore } = require('nexus-auth-sdk');
 * const auth = new AuthCore({ apiKey: 'nx_xxx' });
 * const { token, user } = await auth.register({ email, password, username });
 */

const API = 'https://auth.miaogou.site/api';
const SDK_VERSION = '5.9.0';

// ── 命名异常：403 封禁场景 ──
// 普通 Error 只有 code 字符串，调用方写 if (e.code === 'account_banned') 一长串字符串硬编码
// 给到命名类后可以 catch (e) { if (e instanceof AccountBannedError) ... }，IDE 类型/补全友好
// 所有封禁异常共用 reason 字段（站长设置的具体原因），便于前端展示
class BannedError extends Error {
  constructor(message, code, status, reason) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.status = status;
    this.reason = reason || '';
  }
}
class AccountBannedError extends BannedError {}        // 用户账号被封（登录/refresh/认证全部拒）
class ApiKeyBannedError extends BannedError {}         // 该 API Key 被站长封禁
class ApiKeyOwnerBannedError extends BannedError {}    // Key 所属开发者账号被封连带禁用
class AppBannedError extends BannedError {}            // 写操作（编辑/轮换/删除）被拒，仅控制台场景

const BAN_ERROR_CLASS = {
  account_banned: AccountBannedError,
  api_key_banned: ApiKeyBannedError,
  api_key_owner_banned: ApiKeyOwnerBannedError,
  app_banned: AppBannedError,
};
// 匿名遵测（脱敏 · 可关 · 节流），详见 _telemetry.js 注释
let _telemetry = null;
try { _telemetry = require('./_telemetry'); } catch { /* 老环境兜底 */ }

class AuthCore {
  constructor(config = {}) {
    // 两种合法用法：
    // 1) 后端用：传 apiKey（X-API-Key 头会被附加，路径打到 auth.miaogou.site）
    // 2) 前端用：不传 apiKey，传 baseUrl 指向你自己后端的代理路径（如 '/api/auth'），SDK 不会附 X-API-Key 头
    if (!config.apiKey && !config.baseUrl) {
      throw new Error('[AuthCore] 必须提供 apiKey（后端用）或 baseUrl（前端代理用）。详见 https://auth.miaogou.site/docs');
    }
    this.apiKey = config.apiKey || null;
    this.baseUrl = config.baseUrl || API;
    this._configCache = null;
    this._configCacheAt = 0;
    this._revokedHandlers = [];
    // 异步、静默、可关闭。完全不影响构造函数返回
    if (_telemetry) { try { _telemetry.fireTelemetry('nexus-auth-sdk', SDK_VERSION, this.apiKey); } catch {} }
  }

  /**
   * 注册"会话被撤销"回调。当任意 SDK 调用收到 401（token 被撤销、refresh 失效等）时触发。
   * 用法：
   *   const off = auth.onSessionRevoked(() => { localStorage.clear(); location.href = '/login'; });
   * @returns {() => void} 取消订阅函数
   */
  onSessionRevoked(cb) {
    if (typeof cb !== 'function') return () => {};
    this._revokedHandlers.push(cb);
    return () => {
      const i = this._revokedHandlers.indexOf(cb);
      if (i >= 0) this._revokedHandlers.splice(i, 1);
    };
  }

  _emitRevoked() {
    for (const cb of this._revokedHandlers.slice()) {
      try { cb(); } catch (_) { /* 隔离单个回调异常 */ }
    }
  }

  /**
   * 启动轻量会话轮询：每 intervalMs 静默调一次 verify(token)，失败 401 自动触发 onSessionRevoked。
   * 默认不启动，由调用方决定。返回 stop 函数。
   * @param {string} token - 当前 JWT 或 OIDC access_token
   * @param {object} [opts] - { intervalMs = 60000, oidc = false }
   */
  startSessionWatch(token, opts = {}) {
    if (typeof window === 'undefined') return () => {};
    if (!token) return () => {};
    const intervalMs = opts.intervalMs || 60000;
    const oidc = !!opts.oidc;
    let stopped = false;
    const tick = async () => {
      if (stopped) return;
      try {
        if (oidc) await this.verifyOidc(token);
        else {
          const r = await this.verify(token);
          if (r && r.valid === false) this._emitRevoked();
        }
      } catch (_) { /* 401 已经在内部触发 */ }
    };
    const id = setInterval(tick, intervalMs);
    return () => { stopped = true; clearInterval(id); };
  }

  async _fetch(path, body, method) {
    const init = {
      method: method || (body ? 'POST' : 'GET'),
      headers: {},
    };
    // 仅在持有 apiKey 时附加 X-API-Key（前端代理模式 apiKey 为 null，由你的后端注入）
    if (this.apiKey) init.headers['X-API-Key'] = this.apiKey;
    if (body) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    const res = await fetch(this.baseUrl + path, init);
    const data = await res.json();
    if (!res.ok) {
      if (res.status === 401) this._emitRevoked();
      // 封禁类 403 抛命名异常，方便上游 instanceof 判断
      const Cls = res.status === 403 ? BAN_ERROR_CLASS[data.error] : null;
      if (Cls) throw new Cls(data.message || data.error, data.error, 403, data.reason || '');
      const err = new Error(data.message || data.error || `AuthCore API error: ${res.status}`);
      err.code = data.error;
      err.status = res.status;
      throw err;
    }
    return data;
  }

  /**
   * 拉取此 API Key 的运行时配置（含全社区邮件配额联动后的 effective 状态）。
   * 返回字段：
   *   - require_email_verification: boolean — 是否需要邮箱验证（已合并 captcha_forced_off）
   *   - captcha_forced_off: boolean — 是否因社区邮件配额耗尽被系统暂时强制关闭
   *   - password_policy: { min_length, require_upper, require_lower, require_digit }
   * SDK 内部 60 秒缓存，避免高频请求。
   */
  async getConfig({ noCache } = {}) {
    const now = Date.now();
    if (!noCache && this._configCache && (now - this._configCacheAt) < 60_000) {
      return this._configCache;
    }
    const cfg = await this._fetch('/auth/config');
    this._configCache = cfg;
    this._configCacheAt = now;
    return cfg;
  }

  /** Register a new user. Returns { token, user }. */
  async register({ email, password, username }) {
    if (!email || !password) throw new Error('[AuthCore] email and password are required');
    if (password.length < 8) throw new Error('[AuthCore] password must be at least 8 characters');
    return this._fetch('/auth/register', { email, password, username: username || email.split('@')[0] });
  }

  /** Login an existing user. Returns { token, user }. */
  async login({ email, password }) {
    if (!email || !password) throw new Error('[AuthCore] email and password are required');
    return this._fetch('/auth/login', { email, password });
  }

  /** Verify a JWT token. Returns { valid, user? }. */
  async verify(token) {
    if (!token) throw new Error('[AuthCore] token is required');
    return this._fetch('/auth/authenticate', { token });
  }

  /**
   * Verify OIDC access_token via /oauth/userinfo.
   * 当你既有 password 用户又有 OIDC 用户时，先用 verify() 试，失败后降级此方法。
   * @param {string} accessToken - OIDC access_token (非 id_token)
   * @returns {Promise<{sub, email?, name?, picture?, email_verified?}>}
   */
  async verifyOidc(accessToken) {
    if (!accessToken) throw new Error('[AuthCore] accessToken is required');
    const res = await fetch('https://auth.miaogou.site/oauth/userinfo', {
      headers: { Authorization: 'Bearer ' + accessToken },
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      if (res.status === 401) this._emitRevoked();
      const err = new Error(data.error || 'userinfo_failed');
      err.code = data.error;
      err.status = res.status;
      throw err;
    }
    return res.json();
  }

  /**
   * 统一 token 校验：先尝试 AuthCore JWT，失败降级 OIDC userinfo。
   * 让接入方一个方法搞定混合用户群（password 注册 + OIDC 授权两类用户共存场景）。
   * @param {string} token - JWT 或 OIDC access_token
   * @returns {Promise<{valid: boolean, user?: {id, email, username}, source?: 'jwt'|'oidc'}>}
   */
  async verifyAny(token) {
    if (!token) return { valid: false };
    try {
      const r = await this.verify(token);
      if (r && r.valid) return { ...r, source: 'jwt' };
    } catch (_) { /* 不是 JWT 或已过期，降级试 OIDC */ }
    try {
      const info = await this.verifyOidc(token);
      return {
        valid: true,
        source: 'oidc',
        user: { id: info.sub, email: info.email, username: info.name || (info.email || '').split('@')[0] },
      };
    } catch (_) { /* OIDC 也失败 */ }
    return { valid: false };
  }

  /**
   * Refresh an expired JWT using a refresh token. Returns { token, refreshToken }.
   * 单飞锁：同一 refreshToken 的并发刷新共享一个 Promise，避免轮换冲突把用户踢登出。
   */
  async refresh(refreshToken) {
    if (!refreshToken) throw new Error('[AuthCore] refreshToken is required');
    if (this._refreshing) return this._refreshing;
    this._refreshing = (async () => {
      try { return await this._fetch('/auth/refresh', { refreshToken }); }
      finally { this._refreshing = null; }
    })();
    return this._refreshing;
  }

  /**
   * Refresh OIDC access_token using a refresh_token via /oauth/token.
   * 同样使用单飞锁防止并发刷新轮换冲突。
   */
  async refreshOidc(refreshToken, clientId) {
    if (!refreshToken) throw new Error('[AuthCore] refreshToken is required');
    if (!clientId) throw new Error('[AuthCore] clientId is required for OIDC refresh');
    if (this._refreshingOidc) return this._refreshingOidc;
    const self = this;
    this._refreshingOidc = (async () => {
      try {
        const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId });
        const res = await fetch('https://auth.miaogou.site/oauth/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body,
        });
        const data = await res.json();
        if (!res.ok) {
          if (res.status === 400 || res.status === 401) self._emitRevoked();
          const err = new Error(data.error_description || data.error || 'oidc_refresh_failed');
          err.code = data.error;
          err.status = res.status;
          throw err;
        }
        return data;
      } finally { self._refreshingOidc = null; }
    })();
    return this._refreshingOidc;
  }

  /** Revoke a refresh token so it can no longer be used. */
  async revoke(refreshToken) {
    if (!refreshToken) throw new Error('[AuthCore] refreshToken is required');
    return this._fetch('/auth/revoke', { refreshToken });
  }

  /**
   * Revoke OIDC refresh_token via /oauth/revoke.
   * @param {string} refreshToken - OIDC refresh_token
   * @param {string} clientId - 应用 client_id
   */
  async revokeOidc(refreshToken, clientId) {
    if (!refreshToken) throw new Error('[AuthCore] refreshToken is required');
    if (!clientId) throw new Error('[AuthCore] clientId is required');
    await fetch('https://auth.miaogou.site/oauth/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: refreshToken, client_id: clientId }),
    });
    return { success: true };
  }

  /**
   * Send verification code to email. Returns { success, email_sent, expires_in }.
   * 注意：若该应用的 effective `require_email_verification = false`（开发者未启用、或社区配额耗尽被强制关闭），
   * 此调用会返回 verification_disabled 错误。建议先调 `getConfig()` 检查。
   */
  async sendCode({ email }) {
    if (!email) throw new Error('[AuthCore] email is required');
    return this._fetch('/auth/send-code', { email });
  }

  /** Verify a received code. Returns { valid }. */
  async verifyCode({ email, code }) {
    if (!email || !code) throw new Error('[AuthCore] email and code are required');
    return this._fetch('/auth/verify-code', { email, code });
  }
}

// CJS
module.exports = {
  AuthCore,
  // 封禁类异常（5.9.0+）：catch (e) { if (e instanceof AccountBannedError) ... }
  BannedError, AccountBannedError, ApiKeyBannedError, ApiKeyOwnerBannedError, AppBannedError,
};
if (typeof exports !== 'undefined') exports.AuthCore = AuthCore;
