/**
 * AuthCore OIDC client — vendored 浏览器版（无依赖，含 PKCE）
 * 与 nexus-auth-sdk/oidc 行为一致；构造方式: new OidcClient({...})
 *
 * 内置满血特性：
 *   - PKCE 公开客户端（state / nonce / iss / aud 校验）
 *   - 401 自动 refresh + 单飞锁（_refreshing）
 *   - 基于 expires_in 主动续期（_scheduleAutoRefresh，过期前 30s 自动刷）
 *   - visibilitychange 回前台触发续期（_bindVisibility）
 *   - authorizedFetch：自动加 Bearer + 401 重试一次
 *   - Discovery 连败 3 次冷却 60s（_discFails / _discBlockedUntil）
 *   - 撤销感知（onSessionRevoked + startSessionWatch）
 *   - 出站 fetch 内置超时（fetchWithTimeout）
 *   - 匿名遵测（脱敏 · 可关 · 24h 节流）
 */
(function (g) {
  function bytesToB64u(b) {
    let s = '';
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
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
  function rand(n) { return bytesToB64u(crypto.getRandomValues(new Uint8Array(n || 32))); }

  /** 出站 fetch 内置超时（默认 8 秒），与 npm SDK 行为一致 */
  async function fetchWithTimeout(url, init, timeoutMs) {
    const ctrl = new AbortController();
    const timer = setTimeout(function () { ctrl.abort(); }, timeoutMs || 8000);
    try { return await fetch(url, Object.assign({}, init || {}, { signal: (init && init.signal) || ctrl.signal })); }
    finally { clearTimeout(timer); }
  }

  // 匿名遵测（浏览器侧·脱敏·可关·24h 节流）— 详见 /docs#telemetry
  async function _fireTelemetry(clientId) {
    try {
      if (typeof window === 'undefined' || typeof localStorage === 'undefined') return;
      if (localStorage.getItem('NEXUS_AUTH_TELEMETRY_DISABLED') === '1') return;
      if (typeof navigator !== 'undefined' && (navigator.doNotTrack === '1' || navigator.doNotTrack === 'yes')) return;
      const now = Date.now(); const TTL = 24 * 60 * 60 * 1000;
      const last = parseInt(localStorage.getItem('nx_tel_last_oidc') || '0', 10);
      if (Number.isFinite(last) && now - last < TTL) return;
      localStorage.setItem('nx_tel_last_oidc', String(now));
      let id = localStorage.getItem('nx_tel_id');
      if (!id) { id = (crypto.randomUUID ? crypto.randomUUID() : (now.toString(36) + Math.random().toString(36).slice(2))).replace(/-/g, ''); localStorage.setItem('nx_tel_id', id); }
      const ua = (navigator && navigator.userAgent) || '';
      const m = ua.match(/(Macintosh|Windows|Linux|Android|iPhone|iPad|CrOS)/);
      let appHash = '';
      if (clientId && crypto.subtle) {
        try { const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(clientId));
          appHash = Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('').slice(0, 16); } catch {}
      }
      const body = JSON.stringify({ device_id: id, sdk_name: 'create-nexus-auth/oidc-template', sdk_version: '2.10.1', os: m ? m[1] : 'browser', runtime: 'browser', app_hash: appHash });
      if (navigator.sendBeacon) { try { navigator.sendBeacon('https://auth.miaogou.site/telemetry/v1/active', body); return; } catch {} }
      fetch('https://auth.miaogou.site/telemetry/v1/active', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, keepalive: true }).catch(function () {});
    } catch {}
  }

  function OidcClient(opts) {
    if (!opts || !opts.clientId) throw new Error('[OidcClient] clientId required');
    if (!opts.redirectUri) throw new Error('[OidcClient] redirectUri required');
    if (opts.clientSecret) throw new Error('[OidcClient] clientSecret must NOT be set in browser code — use PKCE public client only');
    this.issuer = (opts.issuer || 'https://auth.miaogou.site').replace(/\/$/, '');
    this.clientId = opts.clientId;
    this.redirectUri = opts.redirectUri;
    this.scope = opts.scope || 'openid email profile';
    this.storageKey = opts.storageKey || 'nx_oidc';
    this._cfg = null;
    this._discFails = 0;
    this._discBlockedUntil = 0;
    this._refreshing = null;
    this._revokedHandlers = [];
    this._autoRefreshTimer = null;
    this._watcherTimer = null;
    this._visibilityBound = false;
    _fireTelemetry(this.clientId);
  }

  /** 注册"会话被撤销"回调；userInfo / refresh 401 时触发 */
  OidcClient.prototype.onSessionRevoked = function (cb) {
    if (typeof cb !== 'function') return function () {};
    const self = this;
    this._revokedHandlers.push(cb);
    return function () {
      const i = self._revokedHandlers.indexOf(cb);
      if (i >= 0) self._revokedHandlers.splice(i, 1);
    };
  };
  OidcClient.prototype._emitRevoked = function () {
    const list = this._revokedHandlers.slice();
    for (let i = 0; i < list.length; i++) { try { list[i](); } catch (e) {} }
  };

  /** 轮询 userinfo；默认 60s；返回 stop 函数 */
  OidcClient.prototype.startSessionWatch = function (intervalMs) {
    const self = this;
    const ms = Math.max(10000, intervalMs || 60000);
    if (this._watcherTimer) clearInterval(this._watcherTimer);
    let stopped = false;
    this._watcherTimer = setInterval(async function () {
      if (stopped) return;
      if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
      const t = self.getAccessToken();
      if (!t) return;
      try { await self.userInfo(t); } catch (e) { /* userInfo 在 401 已触发 _emitRevoked */ }
    }, ms);
    return function () { stopped = true; if (self._watcherTimer) { clearInterval(self._watcherTimer); self._watcherTimer = null; } };
  };

  /** Discovery + 连败 3 次冷却 60s（防雪崩） */
  OidcClient.prototype.discovery = async function () {
    if (this._cfg) return this._cfg;
    if (Date.now() < this._discBlockedUntil) throw new Error('discovery_temporarily_unavailable');
    try {
      const r = await fetchWithTimeout(this.issuer + '/.well-known/openid-configuration', {}, 8000);
      if (!r.ok) throw new Error('discovery_http_' + r.status);
      this._cfg = await r.json();
      this._discFails = 0;
      return this._cfg;
    } catch (e) {
      this._discFails++;
      if (this._discFails >= 3) this._discBlockedUntil = Date.now() + 60 * 1000;
      throw e;
    }
  };

  OidcClient.prototype.signIn = async function (extra) {
    const cfg = await this.discovery();
    const verifier = rand(48);
    const challenge = bytesToB64u(await sha256(verifier));
    const state = rand(16);
    const nonce = rand(16);
    sessionStorage.setItem(this.storageKey + ':state', state);
    sessionStorage.setItem(this.storageKey + ':nonce', nonce);
    sessionStorage.setItem(this.storageKey + ':verifier', verifier);
    sessionStorage.setItem(this.storageKey + ':redirect', this.redirectUri);
    const params = new URLSearchParams(Object.assign({
      client_id: this.clientId, redirect_uri: this.redirectUri, response_type: 'code',
      scope: this.scope, state, nonce,
      code_challenge: challenge, code_challenge_method: 'S256',
    }, extra || {}));
    location.assign(cfg.authorization_endpoint + '?' + params);
  };

  OidcClient.prototype.handleCallback = async function () {
    const u = new URL(location.href);
    const code = u.searchParams.get('code');
    const state = u.searchParams.get('state');
    const error = u.searchParams.get('error');
    if (error) throw new Error('oidc_error:' + error);
    if (!code) throw new Error('missing_code');
    const expectedState = sessionStorage.getItem(this.storageKey + ':state');
    if (!expectedState || state !== expectedState) throw new Error('state_mismatch');
    const verifier = sessionStorage.getItem(this.storageKey + ':verifier');
    const nonce = sessionStorage.getItem(this.storageKey + ':nonce');
    const redirectUri = sessionStorage.getItem(this.storageKey + ':redirect') || this.redirectUri;
    const cfg = await this.discovery();
    const body = new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: redirectUri,
      client_id: this.clientId, code_verifier: verifier || '',
    });
    const r = await fetchWithTimeout(cfg.token_endpoint, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
    }, 10000);
    const data = await r.json().catch(function () { return {}; });
    if (!r.ok) {
      const e = new Error(data.error_description || data.error || 'token_failed');
      e.code = data.error; e.status = r.status; throw e;
    }
    if (!data.id_token) throw new Error('no_id_token');
    const payload = JSON.parse(b64uToString(data.id_token.split('.')[1]));
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
      idToken: data.id_token, accessToken: data.access_token, refreshToken: data.refresh_token,
      expiresIn: data.expires_in, scope: data.scope,
      user: { sub: payload.sub, email: payload.email, name: payload.name, picture: payload.picture, email_verified: payload.email_verified },
    };
  };

  OidcClient.prototype.userInfo = async function (token) {
    const cfg = await this.discovery();
    const t = token || this.getAccessToken();
    if (!t) throw new Error('no_access_token');
    const r = await fetchWithTimeout(cfg.userinfo_endpoint, { headers: { Authorization: 'Bearer ' + t } }, 8000);
    if (!r.ok) {
      if (r.status === 401) this._emitRevoked();
      throw new Error('userinfo_failed_' + r.status);
    }
    return r.json();
  };

  /** 用 refresh_token 续期（单飞锁防止并发轮换冲突） */
  OidcClient.prototype.refresh = async function (refreshToken) {
    if (this._refreshing) return this._refreshing;
    const self = this;
    this._refreshing = (async function () {
      try {
        const cfg = await self.discovery();
        const rt = refreshToken || sessionStorage.getItem(self.storageKey + ':refresh');
        if (!rt) throw new Error('no_refresh_token');
        const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt, client_id: self.clientId });
        const r = await fetchWithTimeout(cfg.token_endpoint, {
          method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
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
  };

  OidcClient.prototype.signOut = async function () {
    const cfg = await this.discovery().catch(function () { return null; });
    const rt = sessionStorage.getItem(this.storageKey + ':refresh');
    if (cfg && rt) {
      try {
        await fetchWithTimeout(cfg.revocation_endpoint || (this.issuer + '/oauth/revoke'), {
          method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ token: rt, client_id: this.clientId }),
        }, 5000);
      } catch (e) {}
    }
    if (this._autoRefreshTimer) { clearTimeout(this._autoRefreshTimer); this._autoRefreshTimer = null; }
    if (this._watcherTimer) { clearInterval(this._watcherTimer); this._watcherTimer = null; }
    sessionStorage.removeItem(this.storageKey + ':access');
    sessionStorage.removeItem(this.storageKey + ':id');
    sessionStorage.removeItem(this.storageKey + ':refresh');
    sessionStorage.removeItem(this.storageKey + ':expires_at');
  };

  /** 自带 Bearer + 401 自动 refresh 重试一次的 fetch */
  OidcClient.prototype.authorizedFetch = async function (url, init) {
    init = init || {};
    init.headers = Object.assign({}, init.headers || {});
    const t = this.getAccessToken();
    if (t) init.headers['Authorization'] = 'Bearer ' + t;
    let r = await fetch(url, init);
    if (r.status !== 401) return r;
    try { await this.refresh(); } catch (e) { return r; }
    const t2 = this.getAccessToken();
    if (t2) init.headers['Authorization'] = 'Bearer ' + t2;
    return await fetch(url, init);
  };

  OidcClient.prototype.getAccessToken = function () { return sessionStorage.getItem(this.storageKey + ':access') || null; };
  OidcClient.prototype.getIdToken = function () { return sessionStorage.getItem(this.storageKey + ':id') || null; };

  /** 内部：持久化 token + expires_at（用于自动续期定时器） */
  OidcClient.prototype._storeTokens = function (data) {
    if (data.access_token) sessionStorage.setItem(this.storageKey + ':access', data.access_token);
    if (data.id_token) sessionStorage.setItem(this.storageKey + ':id', data.id_token);
    if (data.refresh_token) sessionStorage.setItem(this.storageKey + ':refresh', data.refresh_token);
    if (data.expires_in) {
      const expAt = Date.now() + (parseInt(data.expires_in, 10) - 30) * 1000;
      sessionStorage.setItem(this.storageKey + ':expires_at', String(expAt));
    }
  };

  /** 内部：基于 expires_at 安排过期前 30s 主动续期 */
  OidcClient.prototype._scheduleAutoRefresh = function () {
    if (this._autoRefreshTimer) { clearTimeout(this._autoRefreshTimer); this._autoRefreshTimer = null; }
    const exp = parseInt(sessionStorage.getItem(this.storageKey + ':expires_at') || '0', 10);
    if (!exp || !sessionStorage.getItem(this.storageKey + ':refresh')) return;
    let delay = exp - Date.now();
    if (delay < 0) delay = 0;
    if (delay > 24 * 60 * 60 * 1000) delay = 24 * 60 * 60 * 1000;
    const self = this;
    this._autoRefreshTimer = setTimeout(function () { self.refresh().catch(function () {}); }, delay);
  };

  /** 内部：visibilitychange 回前台时若 token 即将过期/已过期则主动 refresh */
  OidcClient.prototype._bindVisibility = function () {
    if (this._visibilityBound || typeof document === 'undefined') return;
    this._visibilityBound = true;
    const self = this;
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState !== 'visible') return;
      const exp = parseInt(sessionStorage.getItem(self.storageKey + ':expires_at') || '0', 10);
      if (exp && Date.now() >= exp - 5000 && sessionStorage.getItem(self.storageKey + ':refresh')) {
        self.refresh().catch(function () {});
      }
    });
  };

  g.OidcClient = OidcClient;
})(window);
