/**
 * nexus-auth-sdk — ESM version (for CDN / <script type="module">)
 * import { AuthCore } from 'https://cdn.jsdelivr.net/npm/nexus-auth-sdk@4/index.mjs';
 */

const API = 'https://auth.miaogou.site/api';
const SDK_VERSION = '5.9.0';

// 命名异常（5.9.0+）— 见 index.js 同段说明
export class BannedError extends Error {
  constructor(message, code, status, reason) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.status = status;
    this.reason = reason || '';
  }
}
export class AccountBannedError extends BannedError {}
export class ApiKeyBannedError extends BannedError {}
export class ApiKeyOwnerBannedError extends BannedError {}
export class AppBannedError extends BannedError {}
const BAN_ERROR_CLASS = {
  account_banned: AccountBannedError,
  api_key_banned: ApiKeyBannedError,
  api_key_owner_banned: ApiKeyOwnerBannedError,
  app_banned: AppBannedError,
};
const TELEMETRY_ENDPOINT = 'https://auth.miaogou.site/telemetry/v1/active';

// 匿名遵测（同构：Node 与浏览器均可，自动选择路径）
//   - 仅采集：device_id（机器哈希）、os、os_version、runtime、sdk 名称版本、app_hash（apiKey sha256 前 16 位）
//   - 关闭开关：env NEXUS_AUTH_TELEMETRY_DISABLED=1 / DO_NOT_TRACK=1 / CI / navigator.doNotTrack / localStorage
//   - 客户端节流：每设备 24 小时一次（tmp 文件或 localStorage）
//   - fire-and-forget：完全异步，绝不影响业务
async function _fireTelemetry(apiKey) {
  try {
    const isNode = typeof process !== 'undefined' && process.versions && process.versions.node;
    const isBrowser = typeof window !== 'undefined' && typeof localStorage !== 'undefined';
    // 关闭开关
    if (isNode) {
      const e = process.env || {};
      if (e.NEXUS_AUTH_TELEMETRY_DISABLED && e.NEXUS_AUTH_TELEMETRY_DISABLED !== '0') return;
      if (e.DO_NOT_TRACK && e.DO_NOT_TRACK !== '0') return;
      if (e.CI && e.CI !== 'false' && e.CI !== '0') return;
    } else if (isBrowser) {
      if (localStorage.getItem('NEXUS_AUTH_TELEMETRY_DISABLED') === '1') return;
      if (typeof navigator !== 'undefined' && (navigator.doNotTrack === '1' || navigator.doNotTrack === 'yes')) return;
    } else { return; }
    // 节流 + device_id
    const now = Date.now();
    const TTL = 24 * 60 * 60 * 1000;
    let deviceId = '', osName = '', osVer = '', runtime = '';
    if (isNode) {
      const os = await import('node:os'); const fs = await import('node:fs');
      const path = await import('node:path'); const crypto = await import('node:crypto');
      const cf = path.join(os.tmpdir(), '.nexus-auth-tel');
      try { const last = parseInt(fs.readFileSync(cf, 'utf8'), 10); if (Number.isFinite(last) && now - last < TTL) return; } catch {}
      try { fs.writeFileSync(cf, String(now)); } catch {}
      const macs = [];
      for (const arr of Object.values(os.networkInterfaces() || {})) for (const i of (arr || [])) if (i.mac && i.mac !== '00:00:00:00:00:00') macs.push(i.mac);
      macs.sort();
      deviceId = crypto.createHash('sha256').update(macs.join('|') + '|' + (os.hostname() || '')).digest('hex').slice(0, 32);
      osName = process.platform || ''; osVer = os.release() || ''; runtime = 'node-' + (process.version || '');
    } else {
      const last = parseInt(localStorage.getItem('nx_tel_last') || '0', 10);
      if (Number.isFinite(last) && now - last < TTL) return;
      localStorage.setItem('nx_tel_last', String(now));
      let id = localStorage.getItem('nx_tel_id');
      if (!id) { id = (crypto.randomUUID ? crypto.randomUUID() : (Date.now().toString(36) + Math.random().toString(36).slice(2))).replace(/-/g, ''); localStorage.setItem('nx_tel_id', id); }
      deviceId = id;
      const ua = (typeof navigator !== 'undefined' && navigator.userAgent) || '';
      const m = ua.match(/(Macintosh|Windows|Linux|Android|iPhone|iPad|CrOS)/);
      osName = m ? m[1] : 'browser'; runtime = 'browser';
    }
    // app_hash
    let appHash = '';
    if (apiKey && typeof apiKey === 'string') {
      try {
        if (isNode) { const c = await import('node:crypto'); appHash = c.createHash('sha256').update(apiKey).digest('hex').slice(0, 16); }
        else if (typeof crypto !== 'undefined' && crypto.subtle) {
          const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(apiKey));
          appHash = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
        }
      } catch {}
    }
    const body = JSON.stringify({ device_id: deviceId, sdk_name: 'nexus-auth-sdk', sdk_version: SDK_VERSION, os: osName, os_version: osVer, runtime, app_hash: appHash });
    if (isBrowser && navigator.sendBeacon) { try { navigator.sendBeacon(TELEMETRY_ENDPOINT, body); return; } catch {} }
    fetch(TELEMETRY_ENDPOINT, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, keepalive: isBrowser }).catch(() => {});
  } catch { /* 永不抛错 */ }
}

class AuthCore {
  constructor(config = {}) {
    if (!config.apiKey && !config.baseUrl) {
      throw new Error('[AuthCore] 必须提供 apiKey（后端用）或 baseUrl（前端代理用）。详见 https://auth.miaogou.site/docs');
    }
    this.apiKey = config.apiKey || null;
    this.baseUrl = config.baseUrl || API;
    this._configCache = null;
    this._configCacheAt = 0;
    this._revokedHandlers = [];
    _fireTelemetry(this.apiKey);
  }

  /** 注册"会话被撤销"回调；任意 SDK 调用 401 时触发。返回取消订阅函数。 */
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
      try { cb(); } catch (_) {}
    }
  }

  /** 轻量轮询：每 intervalMs 静默 verify，失败 401 自动触发 onSessionRevoked。 */
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
      } catch (_) {}
    };
    const id = setInterval(tick, intervalMs);
    return () => { stopped = true; clearInterval(id); };
  }

  async _fetch(path, body, method) {
    const init = {
      method: method || (body ? 'POST' : 'GET'),
      headers: {},
    };
    if (this.apiKey) init.headers['X-API-Key'] = this.apiKey;
    if (body) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    const res = await fetch(this.baseUrl + path, init);
    const data = await res.json();
    if (!res.ok) {
      if (res.status === 401) this._emitRevoked();
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
   * SDK 内部 60 秒缓存。
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

  async register({ email, password, username }) {
    if (!email || !password) throw new Error('[AuthCore] email and password are required');
    if (password.length < 8) throw new Error('[AuthCore] password must be at least 8 characters');
    return this._fetch('/auth/register', { email, password, username: username || email.split('@')[0] });
  }

  async login({ email, password }) {
    if (!email || !password) throw new Error('[AuthCore] email and password are required');
    return this._fetch('/auth/login', { email, password });
  }

  async verify(token) {
    if (!token) throw new Error('[AuthCore] token is required');
    return this._fetch('/auth/authenticate', { token });
  }

  async verifyOidc(accessToken) {
    if (!accessToken) throw new Error('[AuthCore] accessToken is required');
    const res = await fetch('https://auth.miaogou.site/oauth/userinfo', {
      headers: { Authorization: 'Bearer ' + accessToken },
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      if (res.status === 401) this._emitRevoked();
      const err = new Error(d.error || 'userinfo_failed');
      err.code = d.error; err.status = res.status;
      throw err;
    }
    return res.json();
  }

  /** 统一 token 校验：先 JWT 再 OIDC userinfo。返回 { valid, user?, source? } */
  async verifyAny(token) {
    if (!token) return { valid: false };
    try { const r = await this.verify(token); if (r && r.valid) return { ...r, source: 'jwt' }; } catch (_) {}
    try {
      const info = await this.verifyOidc(token);
      return { valid: true, source: 'oidc', user: { id: info.sub, email: info.email, username: info.name || (info.email || '').split('@')[0] } };
    } catch (_) {}
    return { valid: false };
  }

  /** 单飞锁：并发 refresh 共享同一 Promise，避免轮换冲突 */
  async refresh(refreshToken) {
    if (!refreshToken) throw new Error('[AuthCore] refreshToken is required');
    if (this._refreshing) return this._refreshing;
    this._refreshing = (async () => {
      try { return await this._fetch('/auth/refresh', { refreshToken }); }
      finally { this._refreshing = null; }
    })();
    return this._refreshing;
  }

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
          err.code = data.error; err.status = res.status;
          throw err;
        }
        return data;
      } finally { self._refreshingOidc = null; }
    })();
    return this._refreshingOidc;
  }

  async revoke(refreshToken) {
    if (!refreshToken) throw new Error('[AuthCore] refreshToken is required');
    return this._fetch('/auth/revoke', { refreshToken });
  }

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

  async sendCode({ email }) {
    if (!email) throw new Error('[AuthCore] email is required');
    return this._fetch('/auth/send-code', { email });
  }

  async verifyCode({ email, code }) {
    if (!email || !code) throw new Error('[AuthCore] email and code are required');
    return this._fetch('/auth/verify-code', { email, code });
  }
}

export { AuthCore };
