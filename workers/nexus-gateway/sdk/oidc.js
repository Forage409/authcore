/**
 * nexus-auth-sdk/oidc — OpenID Connect 客户端（浏览器侧）
 *
 * 满血特性：
 *   - PKCE 公开客户端（无需 client_secret）
 *   - Callback 自动校验 state / nonce / iss / aud
 *   - Refresh 单飞锁（避免并发刷新轮换冲突）
 *   - 自动续期：根据 expires_in 在过期前 30s 主动 refresh
 *   - Visibility 回前台触发刷新
 *   - 撤销感知：可选 startSessionWatch 周期轮询 userinfo，401 触发 onSessionRevoked
 *   - authorizedFetch：自动加 Bearer + 401 触发 refresh 重试一次
 *   - Discovery 短路：连败 3 次冷却 60 秒不再重试
 *   - 所有出站 fetch 内置超时
 */

const DEFAULT_ISSUER = 'https://auth.miaogou.site';
const SDK_VERSION = '5.8.0';
const TELEMETRY_ENDPOINT = 'https://auth.miaogou.site/telemetry/v1/active';

// 匿名遵测（浏览器端） — 关闭：localStorage.setItem('NEXUS_AUTH_TELEMETRY_DISABLED','1') 或 navigator.doNotTrack=1
async function _fireOidcTelemetry(clientId) {
  try {
    if (typeof window === 'undefined' || typeof localStorage === 'undefined') return;
    if (localStorage.getItem('NEXUS_AUTH_TELEMETRY_DISABLED') === '1') return;
    if (typeof navigator !== 'undefined' && (navigator.doNotTrack === '1' || navigator.doNotTrack === 'yes')) return;
    const now = Date.now(); const TTL = 24 * 60 * 60 * 1000;
    const last = parseInt(localStorage.getItem('nx_tel_last_oidc') || '0', 10);
    if (Number.isFinite(last) && now - last < TTL) return;
    localStorage.setItem('nx_tel_last_oidc', String(now));
    let id = localStorage.getItem('nx_tel_id');
    if (!id) { id = (crypto.randomUUID ? crypto.randomUUID() : (Date.now().toString(36) + Math.random().toString(36).slice(2))).replace(/-/g, ''); localStorage.setItem('nx_tel_id', id); }
    const ua = (navigator && navigator.userAgent) || '';
    const m = ua.match(/(Macintosh|Windows|Linux|Android|iPhone|iPad|CrOS)/);
    let appHash = '';
    if (clientId && crypto.subtle) {
      try { const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(clientId));
        appHash = Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('').slice(0, 16); } catch {}
    }
    const body = JSON.stringify({ device_id: id, sdk_name: 'nexus-auth-sdk/oidc', sdk_version: SDK_VERSION, os: m ? m[1] : 'browser', runtime: 'browser', app_hash: appHash });
    if (navigator.sendBeacon) { try { navigator.sendBeacon(TELEMETRY_ENDPOINT, body); return; } catch {} }
    fetch(TELEMETRY_ENDPOINT, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, keepalive: true }).catch(() => {});
  } catch { /* silent */ }
}

function bytesToB64u(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64uToString(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return atob(s);
}
async function sha256(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return new Uint8Array(buf);
}
function randomString(len = 32) {
  return bytesToB64u(crypto.getRandomValues(new Uint8Array(len)));
}

async function fetchWithTimeout(url, init, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs || 8000);
  try { return await fetch(url, Object.assign({}, init || {}, { signal: (init && init.signal) || ctrl.signal })); }
  finally { clearTimeout(timer); }
}

class OidcClient {
  constructor(opts) {
    if (!opts || !opts.clientId) throw new Error('[OidcClient] clientId is required');
    if (!opts.redirectUri) throw new Error('[OidcClient] redirectUri is required');
    const inBrowser = typeof window !== 'undefined' && typeof window.document !== 'undefined';
    if (inBrowser && opts.clientSecret) {
      throw new Error('[OidcClient] clientSecret must NOT be set in browser code — use PKCE public client only');
    }
    this.issuer = (opts.issuer || DEFAULT_ISSUER).replace(/\/$/, '');
    this.clientId = opts.clientId;
    this.redirectUri = opts.redirectUri;
    this.scope = opts.scope || 'openid email profile';
    this.clientSecret = opts.clientSecret;
    this.storageKey = opts.storageKey || 'nx_oidc';
    this._discoveryCache = null;
    this._discFails = 0;
    this._discBlockedUntil = 0;
    this._refreshing = null;
    this._revokedHandlers = [];
    this._autoRefreshTimer = null;
    this._watcherTimer = null;
    this._visibilityBound = false;
    _fireOidcTelemetry(this.clientId);
  }

  /** 注册"会话被撤销"回调；userInfo / refresh 401 时触发 */
  onSessionRevoked(cb) {
    if (typeof cb !== 'function') return () => {};
    this._revokedHandlers.push(cb);
    return () => {
      const i = this._revokedHandlers.indexOf(cb);
      if (i >= 0) this._revokedHandlers.splice(i, 1);
    };
  }
  _emitRevoked() {
    for (const fn of this._revokedHandlers.slice()) { try { fn(); } catch (_) {} }
  }

  /** 后台轮询 userinfo；intervalMs 默认 60_000；返回 stop 函数 */
  startSessionWatch(intervalMs) {
    const ms = Math.max(10000, intervalMs || 60000);
    if (this._watcherTimer) clearInterval(this._watcherTimer);
    let stopped = false;
    this._watcherTimer = setInterval(async () => {
      if (stopped) return;
      if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
      const t = this.getAccessToken();
      if (!t) return;
      try { await this.userInfo(t); } catch (_) { /* userInfo 在 401 时已触发 _emitRevoked */ }
    }, ms);
    return () => { stopped = true; if (this._watcherTimer) { clearInterval(this._watcherTimer); this._watcherTimer = null; } };
  }

  async discovery() {
    if (this._discoveryCache) return this._discoveryCache;
    if (Date.now() < this._discBlockedUntil) throw new Error('discovery_temporarily_unavailable');
    try {
      const r = await fetchWithTimeout(this.issuer + '/.well-known/openid-configuration', {}, 8000);
      if (!r.ok) throw new Error('discovery_http_' + r.status);
      this._discoveryCache = await r.json();
      this._discFails = 0;
      return this._discoveryCache;
    } catch (e) {
      this._discFails++;
      if (this._discFails >= 3) this._discBlockedUntil = Date.now() + 60 * 1000;
      throw e;
    }
  }

  async signIn(extra = {}) {
    const cfg = await this.discovery();
    const verifier = randomString(48);
    const challenge = bytesToB64u(await sha256(verifier));
    const state = randomString(16);
    const nonce = randomString(16);
    sessionStorage.setItem(this.storageKey + ':state', state);
    sessionStorage.setItem(this.storageKey + ':nonce', nonce);
    sessionStorage.setItem(this.storageKey + ':verifier', verifier);
    sessionStorage.setItem(this.storageKey + ':redirect', this.redirectUri);
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: 'code',
      scope: this.scope,
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      ...extra,
    });
    window.location.assign(cfg.authorization_endpoint + '?' + params);
  }

  async handleCallback() {
    const url = new URL(window.location.href);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const error = url.searchParams.get('error');
    if (error) throw new Error('oidc_error:' + error);
    if (!code) throw new Error('missing_code');
    const expectedState = sessionStorage.getItem(this.storageKey + ':state');
    if (!expectedState || state !== expectedState) throw new Error('state_mismatch');
    const verifier = sessionStorage.getItem(this.storageKey + ':verifier');
    const nonce = sessionStorage.getItem(this.storageKey + ':nonce');
    const redirectUri = sessionStorage.getItem(this.storageKey + ':redirect') || this.redirectUri;

    const cfg = await this.discovery();
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: this.clientId,
      code_verifier: verifier || '',
    });
    if (this.clientSecret) body.set('client_secret', this.clientSecret);
    const r = await fetchWithTimeout(cfg.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    }, 10000);
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw Object.assign(new Error(data.error_description || data.error || 'token_failed'), { code: data.error, status: r.status });
    if (!data.id_token) throw new Error('no_id_token');

    const payload = this._decodeJwt(data.id_token);
    if (nonce && payload.nonce !== nonce) throw new Error('nonce_mismatch');
    if (payload.iss !== this.issuer) throw new Error('issuer_mismatch');
    if (payload.aud !== this.clientId) throw new Error('audience_mismatch');

    sessionStorage.removeItem(this.storageKey + ':state');
    sessionStorage.removeItem(this.storageKey + ':nonce');
    sessionStorage.removeItem(this.storageKey + ':verifier');
    this._storeTokens(data);
    this._scheduleAutoRefresh();
    this._bindVisibility();

    return {
      idToken: data.id_token,
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresIn: data.expires_in,
      scope: data.scope,
      user: { sub: payload.sub, email: payload.email, name: payload.name, picture: payload.picture, email_verified: payload.email_verified },
    };
  }

  async userInfo(accessToken) {
    const cfg = await this.discovery();
    const token = accessToken || this.getAccessToken();
    if (!token) throw new Error('no_access_token');
    const r = await fetchWithTimeout(cfg.userinfo_endpoint, { headers: { Authorization: 'Bearer ' + token } }, 8000);
    if (!r.ok) {
      if (r.status === 401) this._emitRevoked();
      throw new Error('userinfo_failed_' + r.status);
    }
    return r.json();
  }

  /** 单飞锁 refresh：并发调用共享一个 Promise，避免轮换冲突 */
  async refresh(refreshToken) {
    if (this._refreshing) return this._refreshing;
    const self = this;
    this._refreshing = (async () => {
      try {
        const cfg = await self.discovery();
        const rt = refreshToken || sessionStorage.getItem(self.storageKey + ':refresh');
        if (!rt) throw new Error('no_refresh_token');
        const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt, client_id: self.clientId });
        if (self.clientSecret) body.set('client_secret', self.clientSecret);
        const r = await fetchWithTimeout(cfg.token_endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body,
        }, 8000);
        const data = await r.json();
        if (!r.ok) {
          if (r.status === 400 || r.status === 401) self._emitRevoked();
          throw new Error(data.error_description || data.error || 'refresh_failed');
        }
        self._storeTokens(data);
        self._scheduleAutoRefresh();
        return data;
      } finally { self._refreshing = null; }
    })();
    return this._refreshing;
  }

  async signOut() {
    const cfg = await this.discovery().catch(() => null);
    const rt = sessionStorage.getItem(this.storageKey + ':refresh');
    if (cfg && rt) {
      try {
        await fetchWithTimeout(cfg.revocation_endpoint || (this.issuer + '/oauth/revoke'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ token: rt, client_id: this.clientId }),
        }, 5000);
      } catch (_) {}
    }
    if (this._autoRefreshTimer) { clearTimeout(this._autoRefreshTimer); this._autoRefreshTimer = null; }
    if (this._watcherTimer) { clearInterval(this._watcherTimer); this._watcherTimer = null; }
    sessionStorage.removeItem(this.storageKey + ':access');
    sessionStorage.removeItem(this.storageKey + ':id');
    sessionStorage.removeItem(this.storageKey + ':refresh');
    sessionStorage.removeItem(this.storageKey + ':expires_at');
  }

  /** 自带 Bearer + 401 自动 refresh 重试一次的 fetch */
  async authorizedFetch(url, init) {
    init = init || {};
    init.headers = Object.assign({}, init.headers || {});
    const t = this.getAccessToken();
    if (t) init.headers['Authorization'] = 'Bearer ' + t;
    let r = await fetch(url, init);
    if (r.status !== 401) return r;
    try { await this.refresh(); } catch (_) { return r; }
    const t2 = this.getAccessToken();
    if (t2) init.headers['Authorization'] = 'Bearer ' + t2;
    return await fetch(url, init);
  }

  getAccessToken() { return sessionStorage.getItem(this.storageKey + ':access') || null; }
  getIdToken() { return sessionStorage.getItem(this.storageKey + ':id') || null; }

  _storeTokens(data) {
    if (data.access_token) sessionStorage.setItem(this.storageKey + ':access', data.access_token);
    if (data.id_token) sessionStorage.setItem(this.storageKey + ':id', data.id_token);
    if (data.refresh_token) sessionStorage.setItem(this.storageKey + ':refresh', data.refresh_token);
    if (data.expires_in) {
      const expAt = Date.now() + (parseInt(data.expires_in, 10) - 30) * 1000;
      sessionStorage.setItem(this.storageKey + ':expires_at', String(expAt));
    }
  }

  _scheduleAutoRefresh() {
    if (this._autoRefreshTimer) { clearTimeout(this._autoRefreshTimer); this._autoRefreshTimer = null; }
    const exp = parseInt(sessionStorage.getItem(this.storageKey + ':expires_at') || '0', 10);
    if (!exp || !sessionStorage.getItem(this.storageKey + ':refresh')) return;
    let delay = exp - Date.now();
    if (delay < 0) delay = 0;
    if (delay > 24 * 60 * 60 * 1000) delay = 24 * 60 * 60 * 1000;
    this._autoRefreshTimer = setTimeout(() => { this.refresh().catch(() => {}); }, delay);
  }

  _bindVisibility() {
    if (this._visibilityBound || typeof document === 'undefined') return;
    this._visibilityBound = true;
    const self = this;
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState !== 'visible') return;
      const exp = parseInt(sessionStorage.getItem(self.storageKey + ':expires_at') || '0', 10);
      if (exp && Date.now() >= exp - 5000 && sessionStorage.getItem(self.storageKey + ':refresh')) {
        self.refresh().catch(() => {});
      }
    });
  }

  _decodeJwt(token) {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('invalid_jwt');
    return JSON.parse(b64uToString(parts[1]));
  }
}

module.exports = { OidcClient };
