/**
 * AuthCore — 精简版 SDK（vendored，零外部依赖）
 * 自动随 create-nexus-auth 模板发布，无需私有 npm 包
 *
 * 注：这是后端 Node 版本；onSessionRevoked / startSessionWatch 等浏览器侧 API
 * 由 frontend/js/app.js 内置实现，无需此处导出。
 */
const _os = require('os');
const _crypto = require('crypto');
const _fs = require('fs');
const _path = require('path');

// 匿名遵测（脱敏 · 可关 · 节流）— 详见 https://auth.miaogou.site/docs#telemetry
// 关闭方式：env NEXUS_AUTH_TELEMETRY_DISABLED=1 / DO_NOT_TRACK=1 / CI=true
const _TEL_CACHE = _path.join(_os.tmpdir(), '.nexus-auth-app-tel');
const _TEL_TTL = 24 * 60 * 60 * 1000;
function _fireAppTelemetry(apiKey) {
  try {
    const e = process.env || {};
    if (e.NEXUS_AUTH_TELEMETRY_DISABLED && e.NEXUS_AUTH_TELEMETRY_DISABLED !== '0') return;
    if (e.DO_NOT_TRACK && e.DO_NOT_TRACK !== '0') return;
    if (e.CI && e.CI !== 'false' && e.CI !== '0') return;
    if (typeof fetch !== 'function') return;
    try {
      if (_fs.existsSync(_TEL_CACHE)) {
        const last = parseInt(_fs.readFileSync(_TEL_CACHE, 'utf8'), 10);
        if (Number.isFinite(last) && Date.now() - last < _TEL_TTL) return;
      }
      _fs.writeFileSync(_TEL_CACHE, String(Date.now()));
    } catch {}
    const macs = [];
    for (const arr of Object.values(_os.networkInterfaces() || {})) {
      for (const i of (arr || [])) if (i.mac && i.mac !== '00:00:00:00:00:00') macs.push(i.mac);
    }
    macs.sort();
    const deviceId = _crypto.createHash('sha256').update(macs.join('|') + '|' + (_os.hostname() || '')).digest('hex').slice(0, 32);
    const appHash = apiKey ? _crypto.createHash('sha256').update(apiKey).digest('hex').slice(0, 16) : '';
    const payload = JSON.stringify({
      device_id: deviceId,
      sdk_name: 'create-nexus-auth/app',
      sdk_version: '2.10.0',
      os: process.platform || '',
      os_version: (() => { try { return _os.release(); } catch { return ''; } })(),
      runtime: 'node-' + (process.version || ''),
      app_hash: appHash,
    });
    setImmediate(() => {
      try {
        fetch('https://auth.miaogou.site/telemetry/v1/active', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payload,
          signal: (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) ? AbortSignal.timeout(4000) : undefined,
        }).catch(() => {});
      } catch {}
    });
  } catch { /* 永不抛错 */ }
}

class AuthCore {
  constructor(config = {}) {
    if (!config.apiKey) throw new Error('apiKey 是必填项。请在 https://auth.miaogou.site 获取');
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://auth.miaogou.site/api';
    _fireAppTelemetry(this.apiKey);
  }

  async _fetch(path, body, method = 'POST') {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10000);
    try {
      const res = await fetch(this.baseUrl + path, {
        method,
        headers: { 'Content-Type': 'application/json', 'X-API-Key': this.apiKey },
        body: body ? JSON.stringify(body) : undefined,
        signal: ctrl.signal,
      });
      const data = await res.json();
      if (!res.ok) {
        // 保留 code + status，前端可据此识别 email_registered / verification_disabled 等场景
        const e = new Error(data.message || data.error || '请求失败');
        e.code = data.error;
        e.status = res.status;
        throw e;
      }
      return data;
    } finally { clearTimeout(timer); }
  }

  /** 自检应用配置（前端可据此决定是否显示验证码 UI） */
  async getConfig() { return this._fetch('/auth/config', null, 'GET'); }

  async register({ email, password, username }) {
    if (!email || !password) throw new Error('邮箱和密码必填');
    if (password.length < 8) throw new Error('密码至少需要 8 位');
    return this._fetch('/auth/register', { email, password, username: username || email.split('@')[0] });
  }

  async login({ email, password }) {
    if (!email || !password) throw new Error('邮箱和密码必填');
    return this._fetch('/auth/login', { email, password });
  }

  async verify(token) {
    if (!token) throw new Error('缺少 token');
    return this._fetch('/auth/authenticate', { token });
  }

  /** OIDC access_token 降级验证 */
  async verifyOidc(accessToken) {
    if (!accessToken) throw new Error('缺少 accessToken');
    const r = await fetch('https://auth.miaogou.site/oauth/userinfo', {
      headers: { Authorization: 'Bearer ' + accessToken },
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      throw new Error(d.error || 'userinfo_failed');
    }
    const info = await r.json();
    return { valid: true, user: { id: info.sub, email: info.email, username: info.name || info.email } };
  }

  async refresh(refreshToken) {
    if (!refreshToken) throw new Error('缺少 refreshToken');
    return this._fetch('/auth/refresh', { refreshToken });
  }

  /** OIDC refresh_token 续期 */
  async refreshOidc(refreshToken, clientId) {
    if (!refreshToken) throw new Error('缺少 refreshToken');
    if (!clientId) throw new Error('缺少 clientId');
    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId });
    const r = await fetch('https://auth.miaogou.site/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      throw new Error(d.error_description || d.error || 'refresh_failed');
    }
    return r.json();
  }

  async revoke(refreshToken) {
    if (!refreshToken) throw new Error('缺少 refreshToken');
    return this._fetch('/auth/revoke', { refreshToken });
  }

  /** OIDC refresh_token 撤销 */
  async revokeOidc(refreshToken, clientId) {
    if (!refreshToken) throw new Error('缺少 refreshToken');
    if (!clientId) throw new Error('缺少 clientId');
    await fetch('https://auth.miaogou.site/oauth/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: refreshToken, client_id: clientId }),
    });
    return { success: true };
  }

  async sendCode({ email }) {
    if (!email) throw new Error('邮箱必填');
    return this._fetch('/auth/send-code', { email });
  }

  async verifyCode({ email, code }) {
    if (!email || !code) throw new Error('邮箱和验证码必填');
    return this._fetch('/auth/verify-code', { email, code });
  }
}

module.exports = { AuthCore };
