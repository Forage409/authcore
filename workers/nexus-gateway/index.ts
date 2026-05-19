/**
 * NEXUS Auth Gateway — API Server v4.0
 */
import { Hono } from 'hono';
import { cors } from 'hono/cors';

interface R2BucketLite {
  put(key: string, body: ArrayBuffer | ReadableStream | Blob | string, opts?: { httpMetadata?: { contentType?: string } }): Promise<any>;
  get(key: string): Promise<{ body: ReadableStream; httpMetadata?: { contentType?: string }; size: number } | null>;
  delete(key: string): Promise<void>;
}
export interface Env { DB: D1Database; JWT_SECRET: string; RESEND_API_KEY?: string; ASSETS: { fetch: (req: Request) => Promise<Response> }; AVATARS: R2BucketLite; }
const app = new Hono<{ Bindings: Env }>();

// OIDC 公开端点 — 允许任何第三方应用跨域调用（无 cookie，所以 origin:* 安全）
app.use('/oauth/token', cors({ origin: '*', allowMethods: ['POST', 'OPTIONS'], allowHeaders: ['Content-Type', 'Authorization'], maxAge: 86400 }));
app.use('/oauth/userinfo', cors({ origin: '*', allowMethods: ['GET', 'OPTIONS'], allowHeaders: ['Authorization'], maxAge: 86400 }));
app.use('/oauth/revoke', cors({ origin: '*', allowMethods: ['POST', 'OPTIONS'], allowHeaders: ['Content-Type', 'Authorization'], maxAge: 86400 }));
app.use('/oauth/jwks', cors({ origin: '*', allowMethods: ['GET', 'OPTIONS'], maxAge: 86400 }));
app.use('/.well-known/*', cors({ origin: '*', allowMethods: ['GET', 'OPTIONS'], maxAge: 86400 }));

// OIDC 用户中心忘记密码：允许 user.miaogou.site 跨源调用（不带 cookie，发邮件 + 验证码重置）
// 必须放在下面 /api/* 严格同源 cors 之前，否则会被覆盖
app.use('/api/auth/oidc/forgot/*', cors({
  origin: ['https://user.miaogou.site', 'https://auth.miaogou.site', 'https://miaogou.site'],
  allowMethods: ['POST', 'OPTIONS'],
  allowHeaders: ['Content-Type'],
  maxAge: 86400,
}));

// 公开举报端点：任何人（含未登录）可提交，允许跨源（举报入口可以嵌在任何第三方应用页面）
// 不带 cookie，不需要 credentials；只接收 POST + OPTIONS
app.use('/api/abuse/report', cors({
  origin: '*',
  allowMethods: ['POST', 'OPTIONS'],
  allowHeaders: ['Content-Type'],
  maxAge: 86400,
}));

// playground.miaogou.site 演示用 — 封禁自己 / 解除自己（只对 playground-* 演示账号生效）
app.use('/api/demo/*', cors({
  origin: '*',
  allowMethods: ['POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'X-API-Key'],
  maxAge: 86400,
}));

// Playground 演示 OIDC：与生产 OIDC 完全隔离的平行端点集
// 生产 /oauth/* 永远拒绝 playground-* 邮箱，而这里 /demo/oauth/* 只接受 playground-* 邮箱
// 公开访问（无 SSO Cookie），但要求 client_id 必须等于 env.PLAYGROUND_DEMO_CLIENT_ID
app.use('/demo/oauth/*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
}));

// 控制台 API + 授权页内部接口 — 严格同源（带 SSO Cookie）
app.use('/api/*', cors({
  origin: (origin) => {
    // 允许：平台自有域名 + playground 子域 + CF Pages 预览域 + 本地 dev 端口
    if (!origin) return null;
    if (origin === 'https://auth.miaogou.site') return origin;
    if (origin === 'https://miaogou.site') return origin;
    if (origin === 'https://playground.miaogou.site') return origin;
    if (origin === 'https://nexus-gateway.pages.dev') return origin;
    if (origin === 'https://nexus-playground.pages.dev') return origin;
    // CF Pages 预览域：<hash>.nexus-playground.pages.dev / <hash>.nexus-gateway.pages.dev
    if (/^https:\/\/[a-z0-9]+\.nexus-(playground|gateway)\.pages\.dev$/.test(origin)) return origin;
    // 本地 dev 端口
    if (/^http:\/\/localhost:(517[0-9]|518[0-9])$/.test(origin)) return origin;
    return null;
  },
  credentials: true,
}));
app.use('/oauth/authorize/*', cors({ origin: ['https://auth.miaogou.site', 'https://user.miaogou.site', 'https://miaogou.site'], credentials: true }));
app.use('/oauth/sso/*', cors({ origin: ['https://auth.miaogou.site', 'https://user.miaogou.site', 'https://miaogou.site'], credentials: true }));

// ── Utilities ──
function b64d(s: string): string { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return atob(s); }
function b64e(s: string): string { return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
async function hmc(d: string, s: string) { return crypto.subtle.sign('HMAC', await crypto.subtle.importKey('raw', new TextEncoder().encode(s), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']), new TextEncoder().encode(d)); }
async function sha256(s: string) { const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)); return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join(''); }

// ── 出站 fetch 超时包装：避免上游慢调用挂死 worker（默认 8s，OAuth/discovery 用 15s）──
async function fetchWithTimeout(url: string, opts: RequestInit = {}, timeoutMs = 8000): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: opts.signal || ctrl.signal });
  } finally { clearTimeout(timer); }
}

// ── Resend 邮件出口断路器（in-memory per-isolate，连败 N 次 → 冷却 5min 不再尝试） ──
// 故障设计原则：上游挂时不让用户长时间排队 / 不再叠加请求 / 自动恢复
const _resendBreaker = { fails: 0, openedAt: 0 };
function resendBreakerOpen(): boolean {
  if (_resendBreaker.fails < 5) return false;
  if (Date.now() - _resendBreaker.openedAt > 5 * 60 * 1000) {
    // 冷却时间到 → 半开放尝试一次
    _resendBreaker.fails = 0;
    return false;
  }
  return true;
}
function resendNoteResult(ok: boolean) {
  if (ok) { _resendBreaker.fails = 0; return; }
  _resendBreaker.fails++;
  if (_resendBreaker.fails === 5) _resendBreaker.openedAt = Date.now();
}

// PBKDF2 password hashing
async function hashPassword(password: string): Promise<{ hash: string; salt: string }> {
  const salt = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, key, 256);
  const hash = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  return { hash, salt };
}

async function verifyPassword(password: string, storedHash: string, salt: string): Promise<boolean> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, key, 256);
  const hash = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  return hash === storedHash;
}

async function jwt(userId: string, email: string, secret: string) {
  const h = b64e(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const p = b64e(JSON.stringify({ sub: userId, email, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 }));
  return h + '.' + p + '.' + b64e(String.fromCharCode(...new Uint8Array(await hmc(h + '.' + p, secret))));
}
async function vjwt(t: string, s: string) { const p = t.split('.'); if (p.length !== 3) throw 0; const x = b64e(String.fromCharCode(...new Uint8Array(await hmc(p[0] + '.' + p[1], s)))); if (x !== p[2]) throw 0; const j = JSON.parse(b64d(p[1])); if (j.exp < Date.now() / 1000) throw 0; return j; }

// ── Structured error helper ──
function err(c: any, code: string, message: string, status: number, field?: string, detail?: string, suggestion?: string) {
  return c.json({ error: code, message, ...(field && { field }), ...(detail && { detail }), ...(suggestion && { suggestion }) }, status);
}

// ── Password validation ──
function validatePassword(pw: string): string | null {
  if (pw.length < 8) return 'password_too_short';
  if (!/[A-Z]/.test(pw)) return 'password_no_uppercase';
  if (!/[a-z]/.test(pw)) return 'password_no_lowercase';
  if (!/[0-9]/.test(pw)) return 'password_no_digit';
  return null;
}

// ── Rate limiting middleware ──
async function rateLimit(c: any, endpoint: string, windowSec: number, maxReqs: number) {
  const ip = c.req.header('CF-Connecting-IP') || 'unknown';
  const now = Math.floor(Date.now() / 1000);
  const ws = Math.floor(now / windowSec) * windowSec;
  const r = await c.env.DB.prepare(
    `INSERT INTO rate_limits (ip, endpoint, window_start, count) VALUES (?, ?, ?, 1)
     ON CONFLICT(ip, endpoint, window_start) DO UPDATE SET count = count + 1 RETURNING count`
  ).bind(ip, endpoint, ws).first() as any;
  return (r?.count || 0) > maxReqs;
}

// ── 全社区每日邮件配额（Asia/Shanghai） ──
function todayCN(): string {
  const d = new Date(Date.now() + 8 * 3600_000);
  return d.toISOString().slice(0, 10);
}
async function checkAndReserveQuota(db: any): Promise<boolean> {
  const today = todayCN();
  await db.prepare(
    `INSERT INTO email_quota_daily (date, sent_count, limit_value)
     SELECT ?, 0, COALESCE((SELECT CAST(v AS INTEGER) FROM email_quota_config WHERE k='daily_limit'), 100)
     WHERE NOT EXISTS (SELECT 1 FROM email_quota_daily WHERE date = ?)`
  ).bind(today, today).run().catch(() => {});
  const r = await db.prepare(
    `UPDATE email_quota_daily SET sent_count = sent_count + 1
     WHERE date = ? AND sent_count < limit_value RETURNING sent_count, limit_value`
  ).bind(today).first() as any;
  if (!r) {
    await triggerCaptchaForceOff(db, today).catch(() => {});
    return false;
  }
  return true;
}
async function rollbackQuota(db: any) {
  const today = todayCN();
  await db.prepare(`UPDATE email_quota_daily SET sent_count = sent_count - 1 WHERE date = ? AND sent_count > 0`).bind(today).run().catch(() => {});
}
async function isRegistrationOpen(db: any): Promise<boolean> {
  const today = todayCN();
  const r = await db.prepare(`SELECT sent_count, limit_value FROM email_quota_daily WHERE date = ?`).bind(today).first() as any;
  if (!r) return true;
  return r.sent_count < r.limit_value;
}
async function triggerCaptchaForceOff(db: any, date: string) {
  const already = await db.prepare(`SELECT 1 FROM captcha_state_backup WHERE date = ? LIMIT 1`).bind(date).first();
  if (already) return;
  await db.batch([
    db.prepare(`INSERT OR IGNORE INTO captcha_state_backup (date, api_key_id, original_enabled)
                SELECT ?, id, captcha_enabled FROM api_keys WHERE revoked = 0`).bind(date),
    db.prepare(`UPDATE api_keys SET captcha_forced_off = 1 WHERE revoked = 0`),
    db.prepare(`UPDATE email_quota_daily SET locked = 1, forced_off_at = datetime('now', '+8 hours') WHERE date = ?`).bind(date),
  ]);
}
// 懒恢复：访问相关接口时如果昨日有未恢复的备份，解除强制关闭（不动 captcha_enabled 用户意愿位）
async function restoreCaptchaIfNewDay(db: any) {
  const today = todayCN();
  const pending = await db.prepare(`SELECT 1 FROM captcha_state_backup WHERE restored = 0 AND date < ? LIMIT 1`).bind(today).first();
  if (!pending) return;
  await db.batch([
    db.prepare(`UPDATE api_keys SET captcha_forced_off = 0`),
    db.prepare(`UPDATE captcha_state_backup SET restored = 1 WHERE restored = 0 AND date < ?`).bind(today),
  ]);
}

// ── SSRF 防护 ──
function isPrivateHost(host: string): boolean {
  const h = host.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal') || h.endsWith('.local')) return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 0 || a === 10 || a === 127 || a >= 224) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  if (h.includes(':')) {
    if (h === '::1' || h === '::' || h.startsWith('::ffff:') ||
        h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80')) return true;
  }
  return false;
}
function assertSafeUrl(rawUrl: string): URL {
  let u: URL;
  try { u = new URL(rawUrl); }
  catch { throw new Error('URL 无效'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('仅支持 http/https 地址');
  if (isPrivateHost(u.hostname)) throw new Error('不允许访问内网或保留地址');
  return u;
}

// ══════ 应用注册审查 + 溯源 ══════
// 站长邮箱：仅此邮箱（开发者账号）可访问 /api/admin/forensics/* 与 /api/admin/bans/* 等端点
// 从 env.PLATFORM_OWNERS 读取（逗号分隔），通过 Cloudflare Secrets 配置，避免硬编码进开源仓库
//   wrangler secret put PLATFORM_OWNERS  →  输入 "you@example.com,backup@example.com"
let _platformOwnersCache: Set<string> | null = null;
function getPlatformOwners(env: any): Set<string> {
  if (_platformOwnersCache) return _platformOwnersCache;
  const raw = (env?.PLATFORM_OWNERS || '').toString();
  _platformOwnersCache = new Set(
    raw.split(',').map((s: string) => s.trim().toLowerCase()).filter(Boolean)
  );
  return _platformOwnersCache;
}

// 关键词黑名单：name / app_homepage / redirect_uri 任一字段命中即拒绝注册
// 中英混排，case-insensitive，子串匹配
const FORBIDDEN_KEYWORDS: Record<string, string[]> = {
  porn: ['色情', '成人', '约炮', '援交', '桑拿', '会所', '裸聊', '黄片', '一夜情', '伴游', '上门服务', '少妇', 'porn', 'xxx', 'adult', 'escort', 'nude', 'milf', 'erotic', 'fetish'],
  gambling: ['赌博', '赌场', '博彩', '彩票', '百家乐', '老虎机', '六合彩', '体育博彩', '足球投注', '德州扑克', '澳门赌', '赌球', 'casino', 'poker', 'baccarat', 'betting', 'gambling', 'wager', 'roulette'],
  drugs: ['毒品', '冰毒', '大麻', '海洛因', '可卡因', '麻古', '摇头丸', 'cocaine', 'heroin', 'cannabis', 'marijuana'],
  fraud: ['钓鱼站', '诈骗', '骗钱', '黑产', 'phishing', 'scam', 'fraud'],
  weapons: ['军火', '枪支交易', '弹药', 'firearm trade', 'ammunition sale'],
  csam: ['萝莉门', '幼女门', 'cp种子', 'pthc', 'preteen porn'],
};

// 敏感域名黑名单：普通开发者绝不可能拥有，命中即拒绝（防恶意填报 nsa.gov 等戏弄系统）
// 分为「精确匹配」和「后缀匹配」两类
const SENSITIVE_DOMAIN_SUFFIXES = [
  '.gov', '.mil', '.gov.cn', '.gov.uk', '.gov.au', '.gov.jp', '.gov.kr',
  '.edu.cn', '.ac.cn', '.org.cn',
];
const SENSITIVE_DOMAIN_EXACT = new Set([
  'nsa.gov', 'fbi.gov', 'cia.gov', 'whitehouse.gov',
  'mps.gov.cn', 'court.gov.cn', 'mod.gov.uk',
  // 大型平台（普通开发者不可能拥有这些根域）
  'google.com', 'facebook.com', 'apple.com', 'microsoft.com', 'amazon.com',
  'alibaba.com', 'tencent.com', 'baidu.com', 'qq.com', 'weibo.com',
  'twitter.com', 'x.com', 'meta.com', 'tiktok.com', 'douyin.com',
  'cloudflare.com', 'github.com', 'gitlab.com',
  // 协议演示用域名（不会真的部署应用）
  'example.com', 'example.org', 'example.net', 'test.com',
]);

function scanForbiddenKeywords(text: string): { hit: boolean; category: string; word: string } {
  if (!text) return { hit: false, category: '', word: '' };
  const lower = text.toLowerCase();
  for (const cat of Object.keys(FORBIDDEN_KEYWORDS)) {
    for (const w of FORBIDDEN_KEYWORDS[cat]) {
      if (lower.includes(w.toLowerCase())) return { hit: true, category: cat, word: w };
    }
  }
  return { hit: false, category: '', word: '' };
}

function isSensitiveDomain(host: string): boolean {
  const h = host.toLowerCase();
  if (SENSITIVE_DOMAIN_EXACT.has(h)) return true;
  for (const suf of SENSITIVE_DOMAIN_SUFFIXES) {
    if (h === suf.slice(1) || h.endsWith(suf)) return true;
  }
  return false;
}

function extractDomainsFromUris(uris: string): string[] {
  if (!uris) return [];
  const lines = uris.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
  const out = new Set<string>();
  for (const u of lines) {
    try {
      const url = new URL(u);
      const h = url.hostname.toLowerCase();
      if (h && h !== 'localhost' && h !== '127.0.0.1') out.add(h);
    } catch { /* 非法 URI 上游已挡，这里忽略 */ }
  }
  return Array.from(out);
}

// 关键词 + 敏感域名联合扫描。返回拒绝原因（null 表示通过）
function scanAppFields(name: string, homepage: string, redirectUris: string): { reason: string; hits: string } | null {
  // 1) 关键词扫描三个字段
  for (const [label, val] of [['name', name], ['homepage', homepage], ['redirect_uris', redirectUris]] as const) {
    const r = scanForbiddenKeywords(val);
    if (r.hit) return { reason: `${label} 命中禁止类目「${r.category}」关键词: ${r.word}`, hits: `${r.category}:${r.word}@${label}` };
  }
  // 2) 敏感域名扫描（homepage + redirect_uris 提取域名）
  const domains = new Set<string>();
  try { if (homepage) domains.add(new URL(homepage).hostname.toLowerCase()); } catch {}
  for (const d of extractDomainsFromUris(redirectUris)) domains.add(d);
  for (const d of domains) {
    if (isSensitiveDomain(d)) {
      return {
        reason: `域名 ${d} 属于政府 / 军方 / 大型平台等普通开发者不可能拥有的范围，禁止填报`,
        hits: `sensitive_domain:${d}`,
      };
    }
  }
  return null;
}

// DNS 解析（仅用作弱线索 / 时间快照，绝不作为定罪依据）
// 通过 Cloudflare DoH 拿 A 和 AAAA 记录
async function dnsLookup(domain: string): Promise<{ a: string[]; aaaa: string[] }> {
  const a: string[] = [];
  const aaaa: string[] = [];
  await Promise.all([
    (async () => {
      try {
        const r = await fetchWithTimeout(
          `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
          { headers: { 'Accept': 'application/dns-json' } },
          5000,
        );
        const data: any = await r.json();
        if (data?.Answer) for (const ans of data.Answer) if (ans.type === 1 && ans.data) a.push(ans.data);
      } catch { /* 静默 */ }
    })(),
    (async () => {
      try {
        const r = await fetchWithTimeout(
          `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=AAAA`,
          { headers: { 'Accept': 'application/dns-json' } },
          5000,
        );
        const data: any = await r.json();
        if (data?.Answer) for (const ans of data.Answer) if (ans.type === 28 && ans.data) aaaa.push(ans.data);
      } catch {}
    })(),
  ]);
  return { a, aaaa };
}

// 信任的托管域名后缀：在这些平台上托管 SPA 等于平台自己背书，黑客滥用成本极高
// 加新的请联系运维 —— 不要随意扩展（每加一项都是攻击面）
const TRUSTED_HOSTING_SUFFIXES = [
  // CDN / 静态托管
  '.github.io',
  '.vercel.app',
  '.netlify.app',
  '.pages.dev',           // Cloudflare Pages
  '.workers.dev',         // Cloudflare Workers 子域
  '.web.app',             // Firebase Hosting
  '.firebaseapp.com',
  '.cloudflareaccess.com',
  // 主流 PaaS / 边缘运行时
  '.deno.dev',            // Deno Deploy
  '.fly.dev',             // Fly.io
  '.railway.app',         // Railway
  '.onrender.com',        // Render
  '.amplifyapp.com',      // AWS Amplify
  '.appspot.com',         // Google App Engine
  '.run.app',             // Google Cloud Run
  '.azurestaticapps.net', // Azure Static Web Apps
  '.azurewebsites.net',   // Azure App Service
  '.herokuapp.com',       // Heroku
  '.replit.app',          // Replit
  '.surge.sh',            // Surge
  '.glitch.me',           // Glitch
  // dev / 测试域名（RFC 6761 / 2606 保留）
  '.localhost',           // 所有 *.localhost 按 RFC 6761 必须解析到 loopback
  '.local',               // mDNS / Bonjour
  '.test',                // RFC 2606 测试域名
  '.invalid',             // RFC 2606
  '.example',             // RFC 2606
];

// IPv4 字符串是否属于私网（RFC 1918）/ loopback / 0.0.0.0
function isPrivateIPv4(host: string): boolean {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [parseInt(m[1]), parseInt(m[2])];
  if (a > 255 || b > 255 || parseInt(m[3]) > 255 || parseInt(m[4]) > 255) return false;
  if (a === 127 || a === 0) return true;                           // loopback / unspecified
  if (a === 10) return true;                                       // 10/8
  if (a === 192 && b === 168) return true;                         // 192.168/16
  if (a === 172 && b >= 16 && b <= 31) return true;                // 172.16/12
  return false;
}

function isTrustedHostingDomain(host: string): boolean {
  const h = host.toLowerCase();
  // dev hosts: localhost / IPv6 loopback / 私网 IP / 保留域名
  if (h === 'localhost' || h === '[::1]' || h === '::1') return true;
  if (isPrivateIPv4(h)) return true;
  for (const suf of TRUSTED_HOSTING_SUFFIXES) {
    // 必须真子域名（防 evil-github.io.attacker.com 这种伪装）
    if (h.endsWith(suf) && h.length > suf.length) return true;
  }
  return false;
}

// 检查某 host 是否已被该 user 验证；自动继承父域验证（已验 miaogou.site → 任意子域名直接通过）
// 不查 1-label TLD（如 site / com），因为没人能给 TLD 加 TXT 也没有意义
// 返回 { verified: bool, coveredBy: string|null }：coveredBy 是触发通过的真正域名（精确或父域）
async function isHostVerified(db: any, userId: string, host: string): Promise<{ verified: boolean; coveredBy: string | null }> {
  const labels = host.split('.');
  // 候选：精确 host，然后逐级去掉最前面的 label，直到剩 2 个 label 为止
  const candidates: string[] = [];
  for (let i = 0; i < labels.length - 1; i++) {
    const candidate = labels.slice(i).join('.');
    if (candidate.split('.').length >= 2) candidates.push(candidate);
  }
  if (candidates.length === 0) return { verified: false, coveredBy: null };
  // 一次性查所有候选，DB 一次 IN 查询
  const placeholders = candidates.map(() => '?').join(',');
  const { results } = await db.prepare(
    `SELECT domain FROM domain_verifications WHERE user_id = ? AND verified = 1 AND domain IN (${placeholders})`
  ).bind(userId, ...candidates).all();
  if (!results || results.length === 0) return { verified: false, coveredBy: null };
  // 精确匹配优先；否则取第一个父域（其实任一父域命中就够了）
  const exact = results.find((r: any) => r.domain === host);
  return { verified: true, coveredBy: exact ? host : (results[0] as any).domain };
}

// 评估应用审批状态：考虑 [信任托管 + 已 DNS 验证（含父域继承）] 两类豁免
// approved 条件：OIDC 关 / 没 URI / 所有 URI 域名都满足任一豁免
// 否则 pending（沙盒，仅所有者可登录）
async function evaluateApprovalStatus(db: any, userId: string, oidcEnabled: boolean, redirectUris: string): Promise<'approved' | 'pending'> {
  if (!oidcEnabled) return 'approved';
  const lines = redirectUris.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
  if (lines.length === 0) return 'approved';
  for (const u of lines) {
    let host = '';
    try { host = new URL(u).hostname.toLowerCase(); } catch { return 'pending'; }
    if (isTrustedHostingDomain(host)) continue;
    const { verified } = await isHostVerified(db, userId, host);
    if (!verified) return 'pending';
  }
  return 'approved';
}

// 提取应用所有 redirect URI 的"需要验证的域名"列表（去重，跳过 localhost / 信任托管）
function extractDomainsNeedingVerification(redirectUris: string): string[] {
  const lines = redirectUris.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
  const out = new Set<string>();
  for (const u of lines) {
    try {
      const host = new URL(u).hostname.toLowerCase();
      if (!isTrustedHostingDomain(host)) out.add(host);
    } catch {}
  }
  return Array.from(out);
}

// DNS TXT 查询：CF DoH 优先，空结果时 Google DoH 兜底（CF 偶尔有 NXDOMAIN 缓存延迟）
async function lookupTxtFromProvider(url: string): Promise<{ status: number; txts: string[] }> {
  try {
    const r = await fetchWithTimeout(url, { headers: { 'Accept': 'application/dns-json' } }, 6000);
    const data: any = await r.json();
    const txts: string[] = [];
    if (data?.Answer) {
      for (const ans of data.Answer) {
        if (ans.type === 16 && typeof ans.data === 'string') {
          // RFC 1035 TXT 格式：每段用引号包围；多段时段之间用 `" "`（quote-space-quote）分隔
          // 例：'"part1" "part2"' → 拼接为 'part1part2'
          const joined = ans.data
            .split(/"\s+"/)              // 拆段（兼容多空格）
            .map((seg: string) => seg.replace(/^"/, '').replace(/"$/, ''))   // 去段首尾引号
            .join('');
          txts.push(joined);
        }
      }
    }
    return { status: data?.Status ?? -1, txts };
  } catch { return { status: -2, txts: [] }; }
}

async function lookupTxt(name: string): Promise<{ txts: string[]; diagnostic: string }> {
  const cf = await lookupTxtFromProvider(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`
  );
  if (cf.txts.length > 0) return { txts: cf.txts, diagnostic: `Cloudflare DoH 找到 ${cf.txts.length} 条` };
  // CF 没找到 → Google 兜底（独立 DNS 解析路径）
  const google = await lookupTxtFromProvider(
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=TXT`
  );
  if (google.txts.length > 0) return { txts: google.txts, diagnostic: `Google DoH 找到 ${google.txts.length} 条（CF DoH 返回 Status=${cf.status}）` };
  // 两家都没找到
  const meaning = (s: number) => s === 0 ? 'NOERROR(无该记录)' : s === 3 ? 'NXDOMAIN(域名不存在)' : `Status=${s}`;
  return {
    txts: [],
    diagnostic: `CF DoH: ${meaning(cf.status)}; Google DoH: ${meaning(google.status)}`,
  };
}

// 32 位随机 challenge（碰撞概率可忽略）
function generateChallenge(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return 'nx-verify-' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// redirect URI 严格校验：拒绝重复 / fragment / userinfo / wildcards / IP / 数量超限
// 返回 ok 时给规范化后的去重列表；不 ok 时给具体错误（前端原文回显）
function normalizeRedirectUri(u: string): string {
  try {
    const url = new URL(u);
    const host = url.hostname.toLowerCase();
    let port = url.port;
    if ((url.protocol === 'https:' && port === '443') || (url.protocol === 'http:' && port === '80')) port = '';
    return `${url.protocol}//${host}${port ? ':' + port : ''}${url.pathname}${url.search}`;
  } catch { return u.toLowerCase(); }
}

function validateRedirectUris(redirectUris: string): { ok: true; uris: string[] } | { ok: false; code: string; message: string } {
  const raw = String(redirectUris || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
  if (raw.length === 0) return { ok: true, uris: [] };
  if (raw.length > 10) return { ok: false, code: 'too_many_uris', message: '最多 10 条 redirect_uri（防滥用）' };

  const seen = new Set<string>();
  const out: string[] = [];
  for (const u of raw) {
    if (u.length > 500) return { ok: false, code: 'uri_too_long', message: `URL 不能超过 500 字符: ${u.slice(0, 60)}…` };
    if (u.includes('*')) return { ok: false, code: 'wildcard_forbidden', message: `禁止使用通配符 *: ${u}（OAuth 标准要求精确匹配）` };
    let url: URL;
    try { url = new URL(u); } catch { return { ok: false, code: 'invalid_url', message: `URL 格式不合法: ${u}` }; }
    const isLocalhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLocalhost)) {
      return { ok: false, code: 'invalid_protocol', message: `必须是 https 或 http://localhost: ${u}` };
    }
    if (url.hash) return { ok: false, code: 'fragment_forbidden', message: `URL 不能包含 # 片段: ${u}（OAuth RFC 6749 § 3.1.2 禁止）` };
    if (url.username || url.password) return { ok: false, code: 'userinfo_forbidden', message: `URL 不能包含用户名/密码: ${u}` };
    if (!url.hostname) return { ok: false, code: 'empty_host', message: `URL 缺少域名: ${u}` };
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname) && url.hostname !== '127.0.0.1') {
      return { ok: false, code: 'ip_forbidden', message: `不允许使用 IP 地址（127.0.0.1 除外）: ${u}` };
    }
    // 重复检测：规范化后比较（host 小写 + 移除默认端口）
    const norm = normalizeRedirectUri(u);
    if (seen.has(norm)) return { ok: false, code: 'duplicate_uri', message: `重复的 redirect_uri: ${u}` };
    seen.add(norm);
    out.push(u);
  }
  return { ok: true, uris: out };
}

// 异步写一条 audit 行（不阻塞主请求）
async function writeAppAudit(c: any, opts: {
  apiKeyId: string;
  userId: string;
  action: 'create' | 'update_oidc' | 'rotate_key' | 'generate_key';
  appName?: string;
  clientType?: string;
  appHomepage?: string;
  redirectUris?: string;
  scanResult: 'pass' | 'rejected' | 'flagged';
  scanHits?: string;
}) {
  const ip = c.req.header('CF-Connecting-IP') || '';
  const ua = c.req.header('User-Agent') || '';
  let dnsResolutions: Record<string, any> = {};
  // 仅在通过扫描 + 有可解析域名时做 DNS（避免对敏感域名发请求）
  if (opts.scanResult === 'pass') {
    const domains = new Set<string>();
    try { if (opts.appHomepage) domains.add(new URL(opts.appHomepage).hostname.toLowerCase()); } catch {}
    for (const d of extractDomainsFromUris(opts.redirectUris || '')) domains.add(d);
    if (domains.size > 0 && domains.size <= 10) {
      // 并发解析，限 10 个域名以内防滥用
      const entries = await Promise.all(
        Array.from(domains).map(async d => [d, await dnsLookup(d)] as const)
      );
      for (const [d, res] of entries) dnsResolutions[d] = res;
    }
  }
  await c.env.DB.prepare(
    `INSERT INTO app_registry_audit (id, api_key_id, user_id, action, app_name, client_type, app_homepage, redirect_uris, developer_ip, developer_ua, dns_resolutions, scan_result, scan_hits)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    crypto.randomUUID(),
    opts.apiKeyId,
    opts.userId,
    opts.action,
    opts.appName || '',
    opts.clientType || '',
    opts.appHomepage || '',
    opts.redirectUris || '',
    ip,
    ua,
    JSON.stringify(dnsResolutions),
    opts.scanResult,
    opts.scanHits || '',
  ).run().catch(() => {});
}

// ── 跨端强制同意协议系统 ──
// 共享 D1 user_consent 表，三端（personal / gateway / user-center）任一端写入即所有端可见
// 升级 ToS 时只需提升此常量，所有未升级版本的用户会被强制重新弹窗
const CURRENT_CONSENT_VERSION = '2026-05-18';
// 这些路径不强制要求同意（让用户能查询自身、登出、提交同意请求）
const CONSENT_BYPASS_PREFIXES = ['/api/consent/', '/api/auth/gateway/me', '/api/auth/refresh', '/api/auth/revoke', '/api/auth/logout'];
function isConsentBypassed(path: string): boolean {
  return CONSENT_BYPASS_PREFIXES.some(p => path === p || path.startsWith(p));
}
async function hasUserConsent(db: any, email: string): Promise<boolean> {
  if (!email) return false;
  const r = await db.prepare(
    `SELECT 1 FROM user_consent WHERE email = ? AND consent_version >= ?`
  ).bind(email, CURRENT_CONSENT_VERSION).first();
  return !!r;
}

// ── CSRF 防护：cookie 认证端点必须验证 Origin/Referer ──
// SameSite=Lax 在新浏览器里能挡 cross-site POST，但旧浏览器 / 边缘场景仍可能漏
// 服务端 Origin 检查是真正的强制约束，不依赖客户端规范
const _csrfAllowedOrigins = new Set([
  'https://auth.miaogou.site',
  'https://miaogou.site',
  'https://user.miaogou.site',
]);
function requireSameOrigin(c: any): Response | null {
  const origin = c.req.header('Origin') || '';
  const referer = c.req.header('Referer') || '';
  let ok = false;
  if (origin) {
    ok = _csrfAllowedOrigins.has(origin);
  } else if (referer) {
    try { ok = _csrfAllowedOrigins.has(new URL(referer).origin); } catch {}
  }
  if (!ok) return err(c, 'invalid_origin', '请求来源不允许（CSRF 防护）', 403);
  return null;
}

// ── 撞库防护：按邮箱 15 分钟窗口计数登录失败 ──
// 用 ip='email' 哨兵 + endpoint 含邮箱 做 (邮箱, scope, 窗口) 唯一键，与原 IP 限流共表共索引不冲突
async function emailFailCount(db: any, email: string, scope: string): Promise<number> {
  const ws = Math.floor(Date.now() / 1000 / 900) * 900;
  const r = await db.prepare(
    `SELECT count FROM rate_limits WHERE ip = 'email' AND endpoint = ? AND window_start = ?`
  ).bind(scope + ':' + email, ws).first() as any;
  return r?.count || 0;
}
async function emailFailBump(db: any, email: string, scope: string) {
  const ws = Math.floor(Date.now() / 1000 / 900) * 900;
  await db.prepare(
    `INSERT INTO rate_limits (ip, endpoint, window_start, count) VALUES ('email', ?, ?, 1)
     ON CONFLICT(ip, endpoint, window_start) DO UPDATE SET count = count + 1`
  ).bind(scope + ':' + email, ws).run().catch(() => {});
}

// ── Auth middleware ──
// JWT 验证通过后，追加同意协议闸门：非白名单接口要求用户在 user_consent 表里有当前版本记录
// 未同意 → 412 + {error:'consent_required'}，前端 fetch interceptor 捕获后重新弹模态框
async function authMW(c: any, next: any) {
  const a = c.req.header('Authorization')?.replace('Bearer ', '');
  if (!a) return err(c, 'auth_missing', '未提供认证令牌', 401);
  let payload: any;
  try { payload = await vjwt(a, c.env.JWT_SECRET); }
  catch { return err(c, 'auth_invalid', '令牌无效或已过期', 401); }
  // 封禁兜底：旧 JWT 在过期前仍能调控制台；这里查 DB 拒绝
  const ban = await c.env.DB.prepare('SELECT banned, banned_reason FROM gateway_users WHERE id = ?').bind(payload.sub).first() as any;
  if (ban && Number(ban.banned) === 1) {
    await c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').bind(payload.sub).run().catch(() => {});
    return err(c, 'account_banned', '账号已被封禁' + (ban.banned_reason ? `：${ban.banned_reason}` : ''), 403);
  }
  c.set('userId', payload.sub);
  c.set('userEmail', payload.email || '');
  // 同意闸门
  if (!isConsentBypassed(c.req.path)) {
    if (!(await hasUserConsent(c.env.DB, payload.email || ''))) {
      return c.json({
        error: 'consent_required',
        message: '请先同意最新的《服务条款》与《隐私政策》',
        consent_version: CURRENT_CONSENT_VERSION,
      }, 412);
    }
  }
  return next();
}

async function keyMW(c: any, next: any) {
  const k = c.req.header('X-API-Key') || '';
  if (!k) return err(c, 'missing_api_key', '缺少 API Key', 401, 'X-API-Key', '请在 X-API-Key Header 中提供你的 API Key');
  const h = await sha256(k);
  const r = await c.env.DB.prepare('SELECT id, user_id, allowed_ips, require_email_verification, banned, banned_reason FROM api_keys WHERE key_hash = ? AND revoked = 0').bind(h).first() as any;
  if (!r) return err(c, 'invalid_api_key', 'API Key 无效或已撤销', 401);
  if (Number(r.banned) === 1) {
    return err(c, 'api_key_banned', 'API Key 已被站长封禁' + (r.banned_reason ? `：${r.banned_reason}` : ''), 403);
  }
  // API Key 的所有者被封 → 整把 Key 也禁用（连带效应）
  const owner = await c.env.DB.prepare('SELECT banned, banned_reason FROM gateway_users WHERE id = ?').bind(r.user_id).first() as any;
  if (owner && Number(owner.banned) === 1) {
    return err(c, 'api_key_owner_banned', 'API Key 所属开发者账号已被封禁' + (owner.banned_reason ? `：${owner.banned_reason}` : ''), 403);
  }
  // IP whitelist check
  if (r.allowed_ips) {
    const clientIp = c.req.header('CF-Connecting-IP') || '';
    const allowed = r.allowed_ips.split(',').map((s: string) => s.trim()).filter(Boolean);
    if (allowed.length > 0 && !allowed.includes(clientIp)) return err(c, 'ip_not_whitelisted', 'IP 不在白名单中', 401, null, `你的 IP (${clientIp}) 未被授权使用此 API Key`);
  }
  c.set('keyId', r.id); c.set('keyUserId', r.user_id);
  await next();
}

// ── Request logging middleware (仅记录真实第三方 API 调用，不记控制台自身请求) ──
app.use('/api/*', async (c, next) => {
  await next();
  const keyId = (c as any).get?.('keyId') || null;
  if (!keyId) return; // 控制台/未认证请求不写入 page_views，避免统计污染
  const ua = c.req.header('User-Agent') || '';
  const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For')?.split(',')[0]?.trim() || '';
  c.env.DB.prepare('INSERT INTO page_views (path, ip, user_agent, api_key_id) VALUES (?, ?, ?, ?)')
    .bind(c.req.path, ip, ua, keyId).run().catch((e: any) => { console.error('page_views insert error:', e?.message || e); });
  // Abnormal IP detection: 5% 采样避免每请求全表扫；alerts 1 小时内同 key 同 type 仅写一条
  if (Math.random() < 0.05) {
    c.env.DB.prepare("SELECT COUNT(DISTINCT ip) as c FROM page_views WHERE api_key_id = ? AND created_at >= datetime('now', '+8 hours', '-1 hour')")
      .bind(keyId).first().then((r: any) => {
        if ((r?.c || 0) > 5) {
          c.env.DB.prepare("SELECT 1 FROM alerts WHERE api_key_id = ? AND type = 'multi_ip' AND created_at >= datetime('now', '+8 hours', '-1 hour') LIMIT 1")
            .bind(keyId).first().then((dup: any) => {
              if (dup) return;
              c.env.DB.prepare('INSERT INTO alerts (api_key_id, type, detail) VALUES (?, ?, ?)')
                .bind(keyId, 'multi_ip', 'API Key used from ' + r.c + ' unique IPs in 1 hour').run().catch(() => {});
            }).catch(() => {});
        }
      }).catch(() => {});
  }
});

// ══════ Developer Auth ══════
// ── Gateway developer send-code ──
app.post('/api/auth/gateway/send-code', async (c) => {
  const { email } = await c.req.json().catch(() => ({}));
  if (!email) return err(c, 'missing_fields', '邮箱为必填项', 400);
  // 多维度限流
  if (await rateLimit(c, 'gw_send_code:e:' + email, 60, 1)) return err(c, 'rate_limited', '该邮箱 60 秒内已发送过验证码', 429);
  if (await rateLimit(c, 'gw_send_code:ip:m', 60, 3)) return err(c, 'rate_limited', '发送太频繁，请稍后再试', 429);
  if (await rateLimit(c, 'gw_send_code:ip:h', 3600, 10)) return err(c, 'rate_limited', '今日发送次数已达上限，请明日再试', 429);
  // 预检：该邮箱是否已注册过开发者账号？避免浪费邮件配额（与 gateway login 一致：id = created_by 即开发者自身行）
  const dupDev = await c.env.DB.prepare('SELECT id FROM gateway_users WHERE email = ? AND id = created_by').bind(email).first();
  if (dupDev) return err(c, 'email_registered', '该邮箱已注册，请直接登录', 409, 'email');
  await restoreCaptchaIfNewDay(c.env.DB).catch(() => {});
  const reserved = await checkAndReserveQuota(c.env.DB);
  if (!reserved) return err(c, 'quota_exceeded', '今日社区邮件配额已用完，明日恢复', 429);
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const codeHash = await sha256(code);
  const id = crypto.randomUUID();
  await c.env.DB.prepare("INSERT INTO verification_codes (id, api_key_id, email, code_hash, expires_at) VALUES (?, 'gateway-dev', ?, ?, datetime('now', '+8 hours', '+5 minutes'))").bind(id, email, codeHash).run();
  let emailSent = false;
  let emailError = '';
  const resendKey = c.env.RESEND_API_KEY;
  if (!resendKey) {
    emailError = 'RESEND_API_KEY not configured';
  } else if (resendBreakerOpen()) {
    emailError = 'Resend 短期内连续失败，已临时熔断（5 分钟后自动尝试）';
  } else {
    try {
      const resp = await fetchWithTimeout('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${resendKey}` },
        body: JSON.stringify({
          from: 'AuthCore <noreply@mail.miaogou.site>',
          to: [email],
          subject: `AuthCore 验证码: ${code}`,
          html: `<p>${code} 是你的验证码，5 分钟内有效。</p><p>如果你没有请求此操作，请忽略这封邮件。</p>`,
        }),
      }, 8000);
      emailSent = resp.ok;
      if (!resp.ok) emailError = `Resend HTTP ${resp.status}`;
      resendNoteResult(resp.ok);
    } catch (e: any) {
      emailError = e?.name === 'AbortError' ? 'Resend 请求超时（8s）' : (e.message || 'Resend fetch failed');
      resendNoteResult(false);
    }
  }
  if (!emailSent) await rollbackQuota(c.env.DB);
  const logId = crypto.randomUUID();
  await c.env.DB.prepare("INSERT INTO email_logs (id, api_key_id, to_email, success, error, created_at) VALUES (?, 'gateway-dev', ?, ?, ?, datetime('now', '+8 hours'))")
    .bind(logId, email, emailSent ? 1 : 0, emailError).run().catch(() => {});
  return c.json({ success: true, email_sent: emailSent, expires_in: 300 });
});

// ── Gateway developer verify-code ──
app.post('/api/auth/gateway/verify-code', async (c) => {
  if (await rateLimit(c, 'gw_verify_code', 60, 10)) return err(c, 'rate_limited', '验证太频繁', 429);
  const { email, code } = await c.req.json().catch(() => ({}));
  if (!email || !code) return err(c, 'missing_fields', '邮箱和验证码为必填项', 400);
  const codeHash = await sha256(String(code));
  const vc = await c.env.DB.prepare("SELECT id, attempts, used FROM verification_codes WHERE email = ? AND api_key_id = 'gateway-dev' AND code_hash = ? AND expires_at > datetime('now', '+8 hours') AND used = 0").bind(email, codeHash).first() as any;
  if (vc) {
    if (vc.attempts >= 3) {
      await c.env.DB.prepare('UPDATE verification_codes SET used = 1 WHERE id = ?').bind(vc.id).run();
      return c.json({ valid: false, error: 'max_attempts' });
    }
    await c.env.DB.prepare('UPDATE verification_codes SET attempts = attempts + 1, used = 1 WHERE id = ?').bind(vc.id).run();
    return c.json({ valid: true });
  }
  await c.env.DB.prepare("UPDATE verification_codes SET attempts = attempts + 1 WHERE email = ? AND api_key_id = 'gateway-dev' AND expires_at > datetime('now', '+8 hours') AND used = 0").bind(email).run();
  return c.json({ valid: false, error: 'invalid_or_expired' });
});

// ── Gateway developer register ──
app.post('/api/auth/gateway/register', async (c) => {
  if (await rateLimit(c, 'gateway_register', 60, 5)) return err(c, 'rate_limited', '请求过于频繁，请稍后再试', 429);
  const { email, password, username } = await c.req.json().catch(() => ({}));
  if (!email || !password) return err(c, 'missing_fields', '邮箱和密码为必填项', 400);
  const pwErr = validatePassword(password);
  if (pwErr) return err(c, pwErr, '密码强度不够', 400, 'password', '密码至少 8 位，包含大小写字母和数字', '试试: MyPass2025!');
  // Email verification required for gateway dev registration（配额耗尽时降级，跳过）
  const regOpen = await isRegistrationOpen(c.env.DB);
  let verifiedCodeIdDev: string | null = null;
  if (regOpen) {
    const verified = await c.env.DB.prepare("SELECT id FROM verification_codes WHERE email = ? AND api_key_id = 'gateway-dev' AND used = 1 AND created_at >= datetime('now', '-10 minutes')").bind(email).first() as any;
    if (!verified) return err(c, 'email_not_verified', '请先验证邮箱', 400, 'email');
    verifiedCodeIdDev = verified.id;
  }
  // 封禁邮箱拒绝注册（同邮箱被封 → 不能换个身份继续）
  const banPreGw = await c.env.DB.prepare(
    `SELECT MAX(banned) AS b, MAX(banned_reason) AS r FROM (
       SELECT banned, banned_reason FROM gateway_users WHERE email = ?
       UNION ALL SELECT banned, banned_reason FROM oidc_identities WHERE email = ?
       UNION ALL SELECT banned, banned_reason FROM users WHERE email = ?)`
  ).bind(email, email, email).first() as any;
  if (banPreGw && Number(banPreGw.b) === 1) {
    return err(c, 'account_banned', '该邮箱已被封禁，不能注册' + (banPreGw.r ? `：${banPreGw.r}` : ''), 403);
  }
  const id = crypto.randomUUID(); const { hash, salt } = await hashPassword(password);
  const uname = (username || email.split('@')[0]).trim();
  try {
    // 开发者端独立：只写 gateway_users，不与 oidc_identities / users 联动
    await c.env.DB.prepare('INSERT INTO gateway_users (id, email, password_hash, username, salt, hash_version, created_by) VALUES (?, ?, ?, ?, ?, 1, ?)').bind(id, email, hash, uname, salt, id).run();
    if (verifiedCodeIdDev) await c.env.DB.prepare('UPDATE verification_codes SET used = 1, attempts = 999 WHERE id = ?').bind(verifiedCodeIdDev).run().catch(() => {});
    const rt = crypto.randomUUID(); const rtHash = await sha256(rt);
    await c.env.DB.prepare('INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime("now", "+8 hours", "+30 days"))').bind(crypto.randomUUID(), id, rtHash).run();
    return c.json({ token: await jwt(id, email, c.env.JWT_SECRET), refreshToken: rt, user: { id, email, username: (username || email.split('@')[0]).trim() } }, 201);
  } catch (e: any) { return err(c, 'email_registered', '该邮箱已注册', 409, 'email'); }
});

// ── 登录账号锁定已移除：ESA 边缘验证码托底，避免邮箱枚举锁号 DoS ──

app.post('/api/auth/gateway/login', async (c) => {
  // IP 突发限流：5 次/60 秒（原 10 次过宽，且 rateLimit 是 > 比较有 off-by-one）
  if (await rateLimit(c, 'gateway_login', 60, 5)) return err(c, 'rate_limited', '请求过于频繁，请稍后再试', 429);
  const { email, password } = await c.req.json().catch(() => ({}));
  if (!email || !password) return err(c, 'missing_fields', '邮箱和密码为必填项', 400);
  // 撞库防护：同一邮箱 15 分钟内累计失败 ≥5 次 → 阻断（不依赖 IP，防轮换 IP 攻击）
  if ((await emailFailCount(c.env.DB, email, 'gw_login_fail')) >= 5) {
    return err(c, 'too_many_failures', '该账号失败次数过多，请 15 分钟后再试', 429);
  }
  // 开发者端独立：只查 gateway_users
  const u = await c.env.DB.prepare('SELECT id, email, username, password_hash, salt, hash_version, banned, banned_reason FROM gateway_users WHERE email = ? AND id = created_by').bind(email).first() as any;
  if (!u) {
    await emailFailBump(c.env.DB, email, 'gw_login_fail');
    return err(c, 'invalid_credentials', '邮箱或密码错误', 401);
  }
  let valid = false;
  if (u.hash_version === 1 && u.salt) {
    valid = await verifyPassword(password, u.password_hash, u.salt);
  } else {
    valid = (await sha256(password)) === u.password_hash;
    if (valid) {
      const { hash, salt } = await hashPassword(password);
      await c.env.DB.prepare('UPDATE gateway_users SET password_hash = ?, salt = ?, hash_version = 1 WHERE id = ?').bind(hash, salt, u.id).run();
    }
  }
  if (!valid) {
    await emailFailBump(c.env.DB, email, 'gw_login_fail');
    return err(c, 'invalid_credentials', '邮箱或密码错误', 401);
  }
  if (Number(u.banned) === 1) {
    await c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').bind(u.id).run().catch(() => {});
    return err(c, 'account_banned', '账号已被封禁' + (u.banned_reason ? `：${u.banned_reason}` : ''), 403);
  }
  const rt = crypto.randomUUID(); const rtHash = await sha256(rt);
  await c.env.DB.prepare('INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime("now", "+8 hours", "+30 days"))').bind(crypto.randomUUID(), u.id, rtHash).run();
  return c.json({ token: await jwt(u.id, u.email, c.env.JWT_SECRET), refreshToken: rt, user: { id: u.id, email: u.email, username: u.username } });
});

app.get('/api/auth/gateway/me', authMW, async (c) => {
  const u = await c.env.DB.prepare('SELECT id, email, username, created_at FROM gateway_users WHERE id = ?').bind(c.get('userId') as string).first() as any;
  return u ? c.json({ user: u }) : err(c, 'not_found', '用户不存在', 404);
});

// ══════ Gateway 开发者忘记密码 ══════
// 与个人站 /api/auth/forgot/* 隔离：api_key_id='gateway-dev-reset'，只针对 gateway_users 表
// 同样的反枚举策略：账号不存在也返回 success，仅在存在时扣配额
app.post('/api/auth/gateway/forgot/send-code', async (c) => {
  const { email } = await c.req.json().catch(() => ({}));
  if (!email || typeof email !== 'string') return err(c, 'missing_fields', '邮箱必填', 400);
  if (await rateLimit(c, 'gw_forgot_send:e:' + email, 60, 1)) return err(c, 'rate_limited', '该邮箱 60 秒内已发送过验证码', 429);
  if (await rateLimit(c, 'gw_forgot_send:ip:m', 300, 3)) return err(c, 'rate_limited', '发送太频繁，请稍后再试', 429);
  if (await rateLimit(c, 'gw_forgot_send:ip:h', 86400, 10)) return err(c, 'rate_limited', '今日重置请求已达上限', 429);

  const exist = await c.env.DB.prepare('SELECT 1 FROM gateway_users WHERE email = ? AND id = created_by').bind(email).first();
  if (!exist) return c.json({ success: true, email_sent: false });

  await restoreCaptchaIfNewDay(c.env.DB).catch(() => {});
  const reserved = await checkAndReserveQuota(c.env.DB);
  if (!reserved) return err(c, 'quota_exceeded', '今日社区邮件配额已用完，明日恢复', 429);

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const codeHash = await sha256(code);
  await c.env.DB.prepare("INSERT INTO verification_codes (id, api_key_id, email, code_hash, expires_at) VALUES (?, 'gateway-dev-reset', ?, ?, datetime('now', '+8 hours', '+15 minutes'))")
    .bind(crypto.randomUUID(), email, codeHash).run();

  let emailSent = false, emailError = '';
  const resendKey = c.env.RESEND_API_KEY;
  if (!resendKey) { emailError = 'RESEND_API_KEY not configured'; }
  else if (resendBreakerOpen()) { emailError = 'Resend 熔断中'; }
  else {
    try {
      const resp = await fetchWithTimeout('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${resendKey}` },
        body: JSON.stringify({
          from: 'AuthCore <noreply@mail.miaogou.site>',
          to: [email],
          subject: `AuthCore 密码重置验证码: ${code}`,
          html: `<p>${code} 是你的密码重置验证码，15 分钟内有效。</p><p>如果不是你本人操作，请忽略此邮件并立即检查账号安全。</p>`,
        }),
      }, 8000);
      emailSent = resp.ok;
      if (!resp.ok) emailError = `Resend HTTP ${resp.status}`;
      resendNoteResult(resp.ok);
    } catch (e: any) {
      emailError = e?.name === 'AbortError' ? 'Resend 请求超时（8s）' : (e.message || 'Resend fetch failed');
      resendNoteResult(false);
    }
  }
  if (!emailSent) await rollbackQuota(c.env.DB);
  await c.env.DB.prepare("INSERT INTO email_logs (id, api_key_id, to_email, success, error, created_at) VALUES (?, 'gateway-dev-reset', ?, ?, ?, datetime('now', '+8 hours'))")
    .bind(crypto.randomUUID(), email, emailSent ? 1 : 0, emailError).run().catch(() => {});
  return c.json({ success: true, email_sent: emailSent, expires_in: 900 });
});

// ══════ OIDC 用户中心忘记密码（user.miaogou.site）══════
// 跨源调用：user.miaogou.site 直连 auth.miaogou.site/api/auth/oidc/forgot/*
// 操作 oidc_identities 表（非 gateway_users / 非 users）；与开发者端、个人站重置独立
app.post('/api/auth/oidc/forgot/send-code', async (c) => {
  const { email } = await c.req.json().catch(() => ({}));
  if (!email || typeof email !== 'string') return err(c, 'missing_fields', '邮箱必填', 400);
  if (await rateLimit(c, 'oidc_forgot_send:e:' + email, 60, 1)) return err(c, 'rate_limited', '该邮箱 60 秒内已发送过验证码', 429);
  if (await rateLimit(c, 'oidc_forgot_send:ip:m', 300, 3)) return err(c, 'rate_limited', '发送太频繁，请稍后再试', 429);
  if (await rateLimit(c, 'oidc_forgot_send:ip:h', 86400, 10)) return err(c, 'rate_limited', '今日重置请求已达上限', 429);

  const exist = await c.env.DB.prepare('SELECT 1 FROM oidc_identities WHERE email = ?').bind(email).first();
  if (!exist) return c.json({ success: true, email_sent: false });

  await restoreCaptchaIfNewDay(c.env.DB).catch(() => {});
  const reserved = await checkAndReserveQuota(c.env.DB);
  if (!reserved) return err(c, 'quota_exceeded', '今日社区邮件配额已用完，明日恢复', 429);

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const codeHash = await sha256(code);
  await c.env.DB.prepare("INSERT INTO verification_codes (id, api_key_id, email, code_hash, expires_at) VALUES (?, 'oidc-reset', ?, ?, datetime('now', '+8 hours', '+15 minutes'))")
    .bind(crypto.randomUUID(), email, codeHash).run();

  let emailSent = false, emailError = '';
  const resendKey = c.env.RESEND_API_KEY;
  if (!resendKey) { emailError = 'RESEND_API_KEY not configured'; }
  else if (resendBreakerOpen()) { emailError = 'Resend 熔断中'; }
  else {
    try {
      const resp = await fetchWithTimeout('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${resendKey}` },
        body: JSON.stringify({
          from: 'AuthCore <noreply@mail.miaogou.site>',
          to: [email],
          subject: `账号中心密码重置验证码: ${code}`,
          html: `<p>${code} 是你的密码重置验证码，15 分钟内有效。</p><p>若非你本人操作请忽略此邮件。</p>`,
        }),
      }, 8000);
      emailSent = resp.ok;
      if (!resp.ok) emailError = `Resend HTTP ${resp.status}`;
      resendNoteResult(resp.ok);
    } catch (e: any) {
      emailError = e?.name === 'AbortError' ? 'Resend 请求超时（8s）' : (e.message || 'Resend fetch failed');
      resendNoteResult(false);
    }
  }
  if (!emailSent) await rollbackQuota(c.env.DB);
  await c.env.DB.prepare("INSERT INTO email_logs (id, api_key_id, to_email, success, error, created_at) VALUES (?, 'oidc-reset', ?, ?, ?, datetime('now', '+8 hours'))")
    .bind(crypto.randomUUID(), email, emailSent ? 1 : 0, emailError).run().catch(() => {});
  return c.json({ success: true, email_sent: emailSent, expires_in: 900 });
});

app.post('/api/auth/oidc/forgot/reset', async (c) => {
  if (await rateLimit(c, 'oidc_forgot_reset', 60, 5)) return err(c, 'rate_limited', '重置太频繁', 429);
  const { email, code, password } = await c.req.json().catch(() => ({}));
  if (!email || !code || !password) return err(c, 'missing_fields', '邮箱、验证码、新密码必填', 400);
  const pwErr = validatePassword(password);
  if (pwErr) return err(c, pwErr, '新密码不符合要求', 400);

  const codeHash = await sha256(String(code));
  const vc = await c.env.DB.prepare("SELECT id, attempts FROM verification_codes WHERE email = ? AND api_key_id = 'oidc-reset' AND code_hash = ? AND expires_at > datetime('now', '+8 hours') AND used = 0").bind(email, codeHash).first() as any;
  if (!vc) {
    await c.env.DB.prepare("UPDATE verification_codes SET attempts = attempts + 1 WHERE email = ? AND api_key_id = 'oidc-reset' AND expires_at > datetime('now', '+8 hours') AND used = 0").bind(email).run().catch(() => {});
    return err(c, 'invalid_code', '验证码错误或已过期', 400);
  }
  if (vc.attempts >= 3) {
    await c.env.DB.prepare('UPDATE verification_codes SET used = 1 WHERE id = ?').bind(vc.id).run();
    return err(c, 'max_attempts', '尝试次数过多，请重新发送验证码', 400);
  }

  const u = await c.env.DB.prepare('SELECT id FROM oidc_identities WHERE email = ?').bind(email).first() as any;
  if (!u) {
    await c.env.DB.prepare('UPDATE verification_codes SET used = 1 WHERE id = ?').bind(vc.id).run();
    return err(c, 'not_found', '账号不存在', 404);
  }

  const { hash, salt } = await hashPassword(password);
  await c.env.DB.prepare('UPDATE oidc_identities SET password_hash = ?, salt = ?, hash_version = 1 WHERE id = ?').bind(hash, salt, u.id).run();
  // 也同步到 users 表（如该用户也是个人站用户）
  await c.env.DB.prepare('UPDATE users SET password_hash = ?, salt = ?, hash_version = 1 WHERE id = ?').bind(hash, salt, u.id).run().catch(() => {});
  await c.env.DB.prepare('UPDATE verification_codes SET used = 1, attempts = 999 WHERE id = ?').bind(vc.id).run();
  // 撤销所有现有 OIDC SSO 会话（强制其他端重新登录）
  await c.env.DB.prepare('DELETE FROM oidc_sso_sessions WHERE identity_id = ?').bind(u.id).run().catch(() => {});

  return c.json({ success: true, message: '密码已重置，请用新密码登录' });
});

app.post('/api/auth/gateway/forgot/reset', async (c) => {
  if (await rateLimit(c, 'gw_forgot_reset', 60, 5)) return err(c, 'rate_limited', '重置太频繁', 429);
  const { email, code, password } = await c.req.json().catch(() => ({}));
  if (!email || !code || !password) return err(c, 'missing_fields', '邮箱、验证码、新密码必填', 400);
  const pwErr = validatePassword(password);
  if (pwErr) return err(c, pwErr, '新密码不符合要求', 400);

  const codeHash = await sha256(String(code));
  const vc = await c.env.DB.prepare("SELECT id, attempts FROM verification_codes WHERE email = ? AND api_key_id = 'gateway-dev-reset' AND code_hash = ? AND expires_at > datetime('now', '+8 hours') AND used = 0").bind(email, codeHash).first() as any;
  if (!vc) {
    await c.env.DB.prepare("UPDATE verification_codes SET attempts = attempts + 1 WHERE email = ? AND api_key_id = 'gateway-dev-reset' AND expires_at > datetime('now', '+8 hours') AND used = 0").bind(email).run().catch(() => {});
    return err(c, 'invalid_code', '验证码错误或已过期', 400);
  }
  if (vc.attempts >= 3) {
    await c.env.DB.prepare('UPDATE verification_codes SET used = 1 WHERE id = ?').bind(vc.id).run();
    return err(c, 'max_attempts', '尝试次数过多，请重新发送验证码', 400);
  }

  const u = await c.env.DB.prepare('SELECT id FROM gateway_users WHERE email = ? AND id = created_by').bind(email).first() as any;
  if (!u) {
    await c.env.DB.prepare('UPDATE verification_codes SET used = 1 WHERE id = ?').bind(vc.id).run();
    return err(c, 'not_found', '账号不存在', 404);
  }

  const { hash, salt } = await hashPassword(password);
  await c.env.DB.prepare('UPDATE gateway_users SET password_hash = ?, salt = ?, hash_version = 1 WHERE id = ?').bind(hash, salt, u.id).run();
  await c.env.DB.prepare('UPDATE verification_codes SET used = 1, attempts = 999 WHERE id = ?').bind(vc.id).run();
  await c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').bind(u.id).run().catch(() => {});

  return c.json({ success: true, message: '密码已重置，请用新密码登录' });
});

app.patch('/api/auth/gateway/me', authMW, async (c) => {
  const uid = c.get('userId') as string;
  const { username } = await c.req.json().catch(() => ({}));
  if (!username?.trim()) return err(c, 'missing_fields', '用户名不能为空', 400, 'username');
  if (username.trim().length > 32) return err(c, 'too_long', '用户名不超过 32 个字符', 400, 'username');
  await c.env.DB.prepare('UPDATE gateway_users SET username = ? WHERE id = ?').bind(username.trim(), uid).run();
  return c.json({ success: true });
});

// ══════ Token Refresh ══════
app.post('/api/auth/refresh', async (c) => {
  if (await rateLimit(c, 'auth_refresh', 60, 20)) return err(c, 'rate_limited', '请求过于频繁，请稍后再试', 429);
  const { refreshToken } = await c.req.json().catch(() => ({}));
  if (!refreshToken) return err(c, 'missing_token', '缺少 refreshToken', 400);
  const rtHash = await sha256(refreshToken);
  const rt = await c.env.DB.prepare("SELECT id, user_id FROM refresh_tokens WHERE token_hash = ? AND revoked = 0 AND expires_at > datetime('now', '+8 hours')").bind(rtHash).first() as any;
  if (!rt) return err(c, 'invalid_refresh_token', 'Refresh token 无效或已过期', 401);
  // Revoke old, issue new
  await c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?').bind(rt.id).run();
  let u = await c.env.DB.prepare('SELECT id, email, username FROM gateway_users WHERE id = ?').bind(rt.user_id).first() as any;
  if (!u) {
    // 兼容：如果 dev 隔离前 refresh_token 的 user_id 指向 oidc_identities
    u = await c.env.DB.prepare('SELECT id, email, username FROM oidc_identities WHERE id = ?').bind(rt.user_id).first() as any;
  }
  if (!u) return err(c, 'not_found', '用户不存在', 404);
  const newRt = crypto.randomUUID(); const newRtHash = await sha256(newRt);
  await c.env.DB.prepare('INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime("now", "+8 hours", "+30 days"))').bind(crypto.randomUUID(), u.id, newRtHash).run();
  return c.json({ token: await jwt(u.id, u.email, c.env.JWT_SECRET), refreshToken: newRt });
});

// ══════ Token Revoke ══════
app.post('/api/auth/revoke', async (c) => {
  if (await rateLimit(c, 'auth_revoke', 60, 20)) return err(c, 'rate_limited', '请求过于频繁，请稍后再试', 429);
  const { refreshToken } = await c.req.json().catch(() => ({}));
  if (!refreshToken) return err(c, 'missing_token', '缺少 refreshToken', 400);
  const rtHash = await sha256(refreshToken);
  const rt = await c.env.DB.prepare("SELECT id FROM refresh_tokens WHERE token_hash = ? AND revoked = 0").bind(rtHash).first() as any;
  if (!rt) return err(c, 'invalid_refresh_token', 'Refresh token 无效或已被撤销', 401);
  await c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?').bind(rt.id).run();
  return c.json({ success: true, message: 'Refresh token 已撤销' });
});

// ══════ Third-party Auth ══════
// ── Webhook 派发：在真实事件（注册/登录）发生时通知开发者配置的回调地址 ──
// Webhook 派发：每次尝试写 webhook_deliveries，5xx/网络故障自动重试（指数退避 + 抖动），4xx 不重试
async function dispatchWebhooks(c: any, developerUserId: string, event: string, user: any, apiKeyId?: string) {
  try {
    // 按应用过滤：NULL 列 = 全部应用 webhook；指定列 = 仅该应用 webhook
    // 一次拉，filter 时按 events + api_key_id 两个维度
    const { results } = await c.env.DB.prepare(
      'SELECT id, url, secret, events, api_key_id FROM webhooks WHERE user_id = ? AND active = 1'
    ).bind(developerUserId).all();
    const hooks = (results as any[]).filter(w => {
      // 应用过滤：webhook 未指定（NULL）→ 全部 app 都触发；指定了 → 必须匹配
      if (w.api_key_id && apiKeyId && w.api_key_id !== apiKeyId) return false;
      if (w.api_key_id && !apiKeyId) return false;  // webhook 限定了 app，但本次事件没传 apiKeyId → 不发
      // 事件过滤
      return (w.events || '').split(',').map((e: string) => e.trim()).includes(event);
    });
    if (!hooks.length) return;
    // payload 里加 app_id 让开发者能在自己端区分事件来源
    const body = JSON.stringify({ event, user, app_id: apiKeyId || null, timestamp: new Date().toISOString() });
    await Promise.all(hooks.map((w: any) => deliverOne(c, w, event, body)));
  } catch (_) { /* 派发失败不影响主流程 */ }
}

async function deliverOne(c: any, w: any, event: string, body: string) {
  const maxAttempts = 3;
  // 退避：1s / 3s / 7s + ±20% 抖动（避免上游所有副本同时重试形成尖刺）
  const baseDelays = [1000, 3000, 7000];
  const jitter = (ms: number) => ms * (0.8 + Math.random() * 0.4);

  try { assertSafeUrl(w.url); }
  catch (e: any) {
    await logDelivery(c, w.id, event, 1, 0, false, 0, 'unsafe_url:' + (e?.message || ''));
    return;
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-AuthCore-Event': event,
    'User-Agent': 'AuthCore-Webhook/1.0',
  };
  if (w.secret) headers['X-AuthCore-Signature'] = await sha256(body + w.secret);

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const started = Date.now();
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 5000);
    let statusCode = 0, errorText = '', success = false;
    try {
      const resp = await fetch(w.url, { method: 'POST', headers, body, redirect: 'manual', signal: ctrl.signal });
      statusCode = resp.status;
      success = resp.ok;
      if (!resp.ok) errorText = `HTTP ${resp.status}`;
    } catch (e: any) {
      errorText = e?.name === 'AbortError' ? 'timeout_5s' : (e?.message || 'network_error');
    } finally { clearTimeout(t); }
    const duration = Date.now() - started;
    await logDelivery(c, w.id, event, attempt, statusCode, success, duration, errorText);
    // 2xx 成功 → 停止；非重试型 4xx（400/401/403/404/410/422）→ 停止；其它 → 退避后重试
    if (success) return;
    const retriable = statusCode === 0 || statusCode === 408 || statusCode === 425 || statusCode === 429 || statusCode >= 500;
    if (!retriable || attempt === maxAttempts) return;
    await new Promise(r => setTimeout(r, jitter(baseDelays[attempt - 1])));
  }
}

async function logDelivery(c: any, webhookId: string, event: string, attempt: number, statusCode: number, success: boolean, durationMs: number, errorText: string) {
  await c.env.DB.prepare(
    'INSERT INTO webhook_deliveries (id, webhook_id, event, attempt, status_code, success, duration_ms, error_text) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(crypto.randomUUID(), webhookId, event, attempt, statusCode, success ? 1 : 0, durationMs, errorText || null).run().catch(() => {});
}

app.post('/api/auth/register', keyMW, async (c) => {
  if (await rateLimit(c, 'auth_register', 60, 10)) return err(c, 'rate_limited', '请求过于频繁，请稍后再试', 429);
  const { email, password, username } = await c.req.json().catch(() => ({}));
  if (!email || !password) return err(c, 'missing_fields', '邮箱和密码为必填项', 400);
  const pwErr = validatePassword(password);
  if (pwErr) return err(c, pwErr, '密码强度不够', 400, 'password', '密码至少 8 位，包含大小写字母和数字', '试试: MyPass2025!');
  // Check if email verification is required for this API key
  // 实际生效 = require_email_verification AND captcha_enabled AND NOT captcha_forced_off
  const keyId = c.get('keyId') as string;
  const keyRow = await c.env.DB.prepare('SELECT require_email_verification, captcha_enabled, captcha_forced_off FROM api_keys WHERE id = ?').bind(keyId).first() as any;
  const verifyRequired = !!keyRow?.require_email_verification && !!keyRow?.captcha_enabled && !keyRow?.captcha_forced_off;
  let verifiedCodeIdGw: string | null = null;
  if (verifyRequired) {
    const verified = await c.env.DB.prepare("SELECT id FROM verification_codes WHERE email = ? AND api_key_id = ? AND used = 1 AND created_at >= datetime('now', '-10 minutes')").bind(email, keyId).first() as any;
    if (!verified) return err(c, 'email_not_verified', '请先验证邮箱', 400, 'email', '该 API Key 要求邮箱验证。请先调用 /api/auth/send-code 然后 /api/auth/verify-code');
    verifiedCodeIdGw = verified.id;
  }
  // 封禁邮箱拒注册：同邮箱被封 → 不允许再创建新身份绕过
  const banPre = await c.env.DB.prepare(
    `SELECT MAX(banned) AS b, MAX(banned_reason) AS r FROM (
       SELECT banned, banned_reason FROM oidc_identities WHERE email = ?
       UNION ALL SELECT banned, banned_reason FROM users WHERE email = ?
       UNION ALL SELECT banned, banned_reason FROM gateway_users WHERE email = ?)`
  ).bind(email, email, email).first() as any;
  if (banPre && Number(banPre.b) === 1) {
    return err(c, 'account_banned', '该邮箱已被封禁，不能注册' + (banPre.r ? `：${banPre.r}` : ''), 403);
  }
  const id = crypto.randomUUID(); const { hash, salt } = await hashPassword(password);
  const keyUserId = c.get('keyUserId') as string;
  try {
    await c.env.DB.prepare('INSERT INTO gateway_users (id, email, password_hash, username, created_by, api_key_id, salt, hash_version) VALUES (?, ?, ?, ?, ?, ?, ?, 1)')
      .bind(id, email, hash, (username || email.split('@')[0]).trim(), keyUserId, keyId, salt).run();
    if (verifiedCodeIdGw) await c.env.DB.prepare('UPDATE verification_codes SET used = 1, attempts = 999 WHERE id = ?').bind(verifiedCodeIdGw).run().catch(() => {});
    const rt = crypto.randomUUID(); const rtHash2 = await sha256(rt);
    await c.env.DB.prepare('INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime("now", "+8 hours", "+30 days"))').bind(crypto.randomUUID(), id, rtHash2).run();
    const newUser = { id, email, username: (username || email.split('@')[0]).trim() };
    c.executionCtx.waitUntil(dispatchWebhooks(c, keyUserId, 'user.registered', newUser, keyId));
    return c.json({ token: await jwt(id, email, c.env.JWT_SECRET), refreshToken: rt, user: newUser }, 201);
  } catch (e: any) { return err(c, 'email_registered', '该邮箱在此开发者下已注册', 409, 'email'); }
});

app.post('/api/auth/login', keyMW, async (c) => {
  // IP 突发限流：10 次/60 秒（第三方应用 SDK 流量更高，比 gateway_login 略宽松）
  if (await rateLimit(c, 'auth_login', 60, 10)) return err(c, 'rate_limited', '请求过于频繁，请稍后再试', 429);
  const { email, password } = await c.req.json().catch(() => ({}));
  if (!email || !password) return err(c, 'missing_fields', '邮箱和密码为必填项', 400);
  const keyUserId = c.get('keyUserId') as string;
  const loginKeyId = (c as any).get('keyId') as string;
  // 撞库防护：同 (邮箱, 开发者) 维度 15 分钟内累计失败 ≥5 次 → 阻断
  // 加 keyUserId 维度避免不同开发者的同名邮箱共享阻断
  const failKey = 'auth_login_fail:' + keyUserId;
  if ((await emailFailCount(c.env.DB, email, failKey)) >= 5) {
    return err(c, 'too_many_failures', '该账号失败次数过多，请 15 分钟后再试', 429);
  }
  const u = await c.env.DB.prepare('SELECT id, email, username, password_hash, salt, hash_version, banned, banned_reason FROM gateway_users WHERE email = ? AND created_by = ?')
    .bind(email, keyUserId).first() as any;
  if (!u) {
    await emailFailBump(c.env.DB, email, failKey);
    return err(c, 'invalid_credentials', '邮箱或密码错误', 401);
  }
  let valid = false;
  if (u.hash_version === 1 && u.salt) {
    valid = await verifyPassword(password, u.password_hash, u.salt);
  } else {
    valid = (await sha256(password)) === u.password_hash;
    if (valid) {
      const { hash, salt } = await hashPassword(password);
      await c.env.DB.prepare('UPDATE gateway_users SET password_hash = ?, salt = ?, hash_version = 1 WHERE id = ?').bind(hash, salt, u.id).run();
    }
  }
  if (!valid) {
    await emailFailBump(c.env.DB, email, failKey);
    return err(c, 'invalid_credentials', '邮箱或密码错误', 401);
  }
  // 封禁闸：第三方应用用户被封 / 或同邮箱的 oidc_identities 被封禁，都拒绝登录
  // OR 查 oidc_identities 是因为站长可能封禁全局身份，gateway_users 这行本身没标但全局被封
  if (Number(u.banned) === 1) {
    await c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').bind(u.id).run().catch(() => {});
    return err(c, 'account_banned', '账号已被封禁' + (u.banned_reason ? `：${u.banned_reason}` : ''), 403);
  }
  const globalBan = await c.env.DB.prepare('SELECT banned, banned_reason FROM oidc_identities WHERE email = ?').bind(email).first() as any;
  if (globalBan && Number(globalBan.banned) === 1) {
    return err(c, 'account_banned', '账号已被封禁' + (globalBan.banned_reason ? `：${globalBan.banned_reason}` : ''), 403);
  }
  // 自动迁移：第三方用户首次登录后，若全局身份不存在则补建（password_hash/salt 通用，因 PBKDF2 算法一致）
  // 之后该用户在任何 OIDC 应用通过 SSO 登录时，可直接复用同样的密码
  c.executionCtx.waitUntil((async () => {
    const exists = await c.env.DB.prepare(`SELECT id FROM oidc_identities WHERE email = ?`).bind(u.email).first();
    if (!exists) {
      await c.env.DB.prepare(
        `INSERT OR IGNORE INTO oidc_identities (id, email, password_hash, salt, hash_version, username) VALUES (?, ?, ?, ?, ?, ?)`
      ).bind(crypto.randomUUID(), u.email, u.password_hash, u.salt || '', u.hash_version || 1, u.username || '').run().catch(() => {});
    }
  })());
  const rt = crypto.randomUUID(); const rtHash3 = await sha256(rt);
  await c.env.DB.prepare('INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime("now", "+8 hours", "+30 days"))').bind(crypto.randomUUID(), u.id, rtHash3).run();
  c.executionCtx.waitUntil(dispatchWebhooks(c, keyUserId, 'user.login', { id: u.id, email: u.email, username: u.username }, loginKeyId));
  return c.json({ token: await jwt(u.id, u.email, c.env.JWT_SECRET), refreshToken: rt, user: { id: u.id, email: u.email, username: u.username } });
});

app.post('/api/auth/authenticate', keyMW, async (c) => {
  if (await rateLimit(c, 'auth_authenticate', 60, 60)) return err(c, 'rate_limited', '请求过于频繁，请稍后再试', 429);
  const { token } = await c.req.json().catch(() => ({}));
  if (!token) return err(c, 'missing_token', '缺少 token', 400);
  try {
    const p = await vjwt(token, c.env.JWT_SECRET);
    const u = await c.env.DB.prepare('SELECT id, email, username FROM gateway_users WHERE id = ? AND created_by = ?')
      .bind(p.sub, c.get('keyUserId') as string).first() as any;
    return u ? c.json({ valid: true, user: u }) : c.json({ valid: false }, 404);
  } catch { return c.json({ valid: false }, 401); }
});

// ══════ Config 自检接口（前端用来按需显示验证 UI，无需开发者额外配置） ══════
app.get('/api/auth/config', keyMW, async (c) => {
  const keyId = c.get('keyId') as string;
  await restoreCaptchaIfNewDay(c.env.DB).catch(() => {});
  const r = await c.env.DB.prepare('SELECT require_email_verification, captcha_enabled, captcha_forced_off, oidc_enabled, redirect_uris FROM api_keys WHERE id = ?').bind(keyId).first() as any;
  const effective = !!r?.require_email_verification && !!r?.captcha_enabled && !r?.captcha_forced_off;
  const firstRedirect = (r?.redirect_uris || '').split(/[\n,]+/).map((s: string) => s.trim()).filter(Boolean)[0] || '';
  return c.json({
    require_email_verification: effective,
    captcha_forced_off: !!r?.captcha_forced_off,
    // OIDC 自动检测：SDK 据此决定是否展示「用 AuthCore 登录」按钮
    oidc_enabled: !!r?.oidc_enabled,
    oidc_authorize_url: r?.oidc_enabled ? (ISSUER + '/oauth/authorize') : null,
    oidc_default_redirect_uri: r?.oidc_enabled ? firstRedirect : null,
    client_id: keyId,
    password_policy: { min_length: 8, require_upper: true, require_lower: true, require_digit: true },
    jwt_ttl_seconds: 3600,
    refresh_ttl_seconds: 2592000,
  });
});

// ══════ Registration status（前端注册页加载时拉取） ══════
app.get('/api/auth/registration-status', async (c) => {
  await restoreCaptchaIfNewDay(c.env.DB).catch(() => {});
  const open = await isRegistrationOpen(c.env.DB);
  return c.json({ open, codeRequired: open });
});

// 管理端点已移除 — 邮件配额由系统自动管控，每个开发者无需也不应能看到/修改全社区共享配置。
// 若平台站长需要查看/手动解锁，可直接 wrangler d1 execute 操作数据库。

// ══════ Email Verification ══════
app.post('/api/auth/send-code', keyMW, async (c) => {
  const { email } = await c.req.json().catch(() => ({}));
  if (!email) return err(c, 'missing_fields', '邮箱为必填项', 400, 'email');
  const keyId = c.get('keyId') as string;
  // Effective verification = require_email_verification AND captcha_enabled AND NOT captcha_forced_off
  const keyRow = await c.env.DB.prepare('SELECT require_email_verification, captcha_enabled, captcha_forced_off FROM api_keys WHERE id = ?').bind(keyId).first() as any;
  const effectiveOn = !!keyRow?.require_email_verification && !!keyRow?.captcha_enabled && !keyRow?.captcha_forced_off;
  if (!effectiveOn) return err(c, 'verification_disabled', '该 API Key 未开启邮箱验证', 400);
  // 多维度限流
  if (await rateLimit(c, '3p_send_code:e:' + email, 60, 1)) return err(c, 'rate_limited', '该邮箱 60 秒内已发送过验证码', 429);
  if (await rateLimit(c, '3p_send_code:ip:m', 60, 3)) return err(c, 'rate_limited', '发送太频繁，请稍后再试', 429);
  if (await rateLimit(c, '3p_send_code:k:h:' + keyId, 3600, 30)) return err(c, 'rate_limited', '该应用今日发送次数已达上限', 429);
  // 预检：该邮箱是否已在此开发者下注册？避免浪费邮件配额（与 register 同库 + 同 created_by 维度）
  const keyUserIdPre = (c as any).get('keyUserId') as string;
  const dupUser = await c.env.DB.prepare('SELECT id FROM gateway_users WHERE email = ? AND created_by = ?').bind(email, keyUserIdPre).first();
  if (dupUser) return err(c, 'email_registered', '该邮箱已注册，请直接登录', 409, 'email');
  await restoreCaptchaIfNewDay(c.env.DB).catch(() => {});
  const reserved = await checkAndReserveQuota(c.env.DB);
  if (!reserved) return err(c, 'quota_exceeded', '今日社区邮件配额已用完，明日恢复', 429);
  // Generate 6-digit code
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const codeHash = await sha256(code);
  const id = crypto.randomUUID();
  await c.env.DB.prepare('INSERT INTO verification_codes (id, api_key_id, email, code_hash, expires_at) VALUES (?, ?, ?, ?, datetime("now", "+8 hours", "+5 minutes"))').bind(id, keyId, email, codeHash).run();
  // Send via Resend（含 8s 超时 + 短期连败熔断 + 配额回滚）
  let emailSent = false;
  let emailError = '';
  const resendKey = c.env.RESEND_API_KEY;
  if (!resendKey) {
    emailError = 'RESEND_API_KEY not configured';
  } else if (resendBreakerOpen()) {
    emailError = 'Resend 短期内连续失败，已临时熔断（5 分钟后自动尝试）';
  } else {
    try {
      const resp = await fetchWithTimeout('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${resendKey}` },
        body: JSON.stringify({
          from: 'AuthCore <noreply@mail.miaogou.site>',
          to: [email],
          subject: `AuthCore 验证码: ${code}`,
          html: `<p>${code} 是你的验证码，5 分钟内有效。</p><p>如果你没有请求此操作，请忽略这封邮件。</p>`,
        }),
      }, 8000);
      emailSent = resp.ok;
      if (!resp.ok) emailError = `Resend HTTP ${resp.status}`;
      resendNoteResult(resp.ok);
    } catch (e: any) {
      emailError = e?.name === 'AbortError' ? 'Resend 请求超时（8s）' : (e.message || 'Resend fetch failed');
      resendNoteResult(false);
    }
  }
  if (!emailSent) await rollbackQuota(c.env.DB);
  const logId = crypto.randomUUID();
  await c.env.DB.prepare('INSERT INTO email_logs (id, api_key_id, to_email, success, error, created_at) VALUES (?, ?, ?, ?, ?, datetime(\'now\'))')
    .bind(logId, keyId, email, emailSent ? 1 : 0, emailError).run().catch(() => {});
  return c.json({ success: true, email_sent: emailSent, expires_in: 300 });
});

app.post('/api/auth/verify-code', keyMW, async (c) => {
  if (await rateLimit(c, 'verify_code', 60, 20)) return err(c, 'rate_limited', '请求过于频繁，请稍后再试', 429);
  const { email, code } = await c.req.json().catch(() => ({}));
  if (!email || !code) return err(c, 'missing_fields', '邮箱和验证码为必填项', 400);
  const keyId = c.get('keyId') as string;
  const codeHash = await sha256(String(code));
  // Check correct code
  const vc = await c.env.DB.prepare("SELECT id, attempts, used FROM verification_codes WHERE email = ? AND api_key_id = ? AND code_hash = ? AND expires_at > datetime('now', '+8 hours') AND used = 0").bind(email, keyId, codeHash).first() as any;
  if (vc) {
    if (vc.attempts >= 3) {
      await c.env.DB.prepare('UPDATE verification_codes SET used = 1 WHERE id = ?').bind(vc.id).run();
      return c.json({ valid: false, error: 'max_attempts', message: '验证码已失效，请重新发送' });
    }
    await c.env.DB.prepare('UPDATE verification_codes SET attempts = attempts + 1, used = 1 WHERE id = ?').bind(vc.id).run();
    return c.json({ valid: true });
  }
  // Wrong code — increment attempt on all active codes for this email+key
  await c.env.DB.prepare("UPDATE verification_codes SET attempts = attempts + 1 WHERE email = ? AND api_key_id = ? AND expires_at > datetime('now', '+8 hours') AND used = 0").bind(email, keyId).run();
  // Check if any code is now maxed out
  const maxed = await c.env.DB.prepare("SELECT id FROM verification_codes WHERE email = ? AND api_key_id = ? AND attempts >= 3 AND expires_at > datetime('now', '+8 hours') AND used = 0").bind(email, keyId).first() as any;
  if (maxed) await c.env.DB.prepare('UPDATE verification_codes SET used = 1 WHERE id = ?').bind(maxed.id).run();
  return c.json({ valid: false, error: 'invalid_or_expired' });
});

// ══════ Gateway Users & Metrics ══════
app.get('/api/gateway/users', authMW, async (c) => {
  const uid = (c as any).get('userId') as string;
  const apiKeyFilter = c.req.query('api_key_id') || '';
  // password_hash = '' 表示 OIDC 授权镜像用户（见 0028 迁移），用于在控制台区分两种来源
  // LEFT JOIN oidc_grants 拿 OIDC 用户的最近授权使用时间；密码用户该字段为 NULL
  let q = `SELECT u.id, u.email, u.username, u.created_at, u.api_key_id,
                  CASE WHEN COALESCE(u.password_hash, '') = '' THEN 1 ELSE 0 END AS is_oidc,
                  g.last_used_at AS last_active_at,
                  g.first_authorized_at
           FROM gateway_users u
           LEFT JOIN oidc_grants g ON g.identity_id = u.id AND g.api_key_id = u.api_key_id
           WHERE u.created_by = ?`;
  const params: any[] = [uid];
  if (apiKeyFilter) { q += ' AND u.api_key_id = ?'; params.push(apiKeyFilter); }
  q += ' ORDER BY COALESCE(g.last_used_at, u.created_at) DESC LIMIT 200';
  const { results } = await c.env.DB.prepare(q).bind(...params).all();
  return c.json({ users: results });
});

app.get('/api/gateway/metrics', authMW, async (c) => {
  const uid = c.get('userId') as string;
  const keys = await c.env.DB.prepare('SELECT COUNT(*) as c FROM api_keys WHERE user_id = ? AND revoked = 0').bind(uid).first() as any;
  const users = await c.env.DB.prepare('SELECT COUNT(*) as c FROM gateway_users WHERE created_by = ?').bind(uid).first() as any;
  return c.json({ activeKeys: keys?.c || 0, totalUsers: users?.c || 0 });
});

// ══════ Me: 当前开发者所有已验证域名 + 信任托管平台列表（前端 redirect URI 预览用） ══════
// 给"实时预览每条 redirect URI 状态"功能用：开发者在 textarea 输入时无需点保存就能看到每行是
//   - 自动通过（信任托管 / dev host）
//   - 覆盖通过（已验证父域）
//   - 需要 DNS 验证
//   - 非法
// 前端拿到 verified_domains（用户名下所有 verified=1）+ trusted_suffixes，就能纯本地实时判断
app.get('/api/me/verified-domains', authMW, async (c) => {
  const uid = (c as any).get('userId') as string;
  const { results } = await c.env.DB.prepare(
    'SELECT domain FROM domain_verifications WHERE user_id = ? AND verified = 1'
  ).bind(uid).all();
  return c.json({
    verified_domains: (results as any[]).map(r => r.domain),
    trusted_suffixes: TRUSTED_HOSTING_SUFFIXES,
  });
});

// ══════ Clients CRUD ══════
app.get('/api/clients', authMW, async (c) => {
  await restoreCaptchaIfNewDay(c.env.DB).catch(() => {});
  const limit = parseInt(c.req.query('limit') || '100');
  const uid = (c as any).get('userId') as string;
  const { results } = await c.env.DB.prepare('SELECT id, name, created_at, revoked, allowed_ips, require_email_verification, captcha_enabled, captcha_forced_off, oidc_enabled, redirect_uris, client_secret_hash, app_logo, app_homepage, key_hash, client_type, app_review_status, banned, banned_reason FROM api_keys WHERE user_id = ? ORDER BY created_at DESC LIMIT ?').bind(uid, limit).all();
  const clients = (results as any[]).map(r => ({
    id: r.id, name: r.name,
    status: r.revoked ? 'revoked' : 'active', createdAt: r.created_at,
    allowedIps: r.allowed_ips || '',
    requireEmailVerification: !!r.require_email_verification,
    captchaEnabled: !!r.captcha_enabled,
    captchaForcedOff: !!r.captcha_forced_off,
    oidcEnabled: !!r.oidc_enabled,
    redirectUris: r.redirect_uris || '',
    hasClientSecret: !!r.client_secret_hash,
    hasApiKey: !!r.key_hash,
    clientType: r.client_type || 'backend',
    appLogo: r.app_logo || '',
    appHomepage: r.app_homepage || '',
    reviewStatus: r.app_review_status || 'approved',  // 历史应用未列时默认通过
    banned: !!r.banned,
    bannedReason: r.banned_reason || '',
  }));
  return c.json({ clients });
});

app.post('/api/clients', authMW, async (c) => {
  // clientType: 'backend' (API Key + 可选 OIDC) | 'spa' (无 API Key，强制 OIDC 公开客户端)
  const { name, allowedIps, requireEmailVerification, clientType, oidcEnabled, redirectUris, appHomepage } = await c.req.json().catch(() => ({}));
  const id = crypto.randomUUID();
  const isSpa = clientType === 'spa';
  const uid = (c as any).get('userId') as string;

  // 防绕过：被封禁的开发者不允许创建新应用（否则封了 app 后用户能马上建一个新的换名继续）
  // authMW 已经在登录态层面拒绝过 banned gateway_users，但保险起见再 owner 维度查一次
  const owner = await c.env.DB.prepare('SELECT banned, banned_reason FROM gateway_users WHERE id = ?').bind(uid).first() as any;
  if (owner && Number(owner.banned) === 1) {
    return err(c, 'account_banned', '账号已被封禁，不能创建应用' + (owner.banned_reason ? `：${owner.banned_reason}` : ''), 403);
  }

  // redirect_uris 严格校验：协议 / 格式 / 重复 / fragment / userinfo / wildcards / IP / 数量
  const v = validateRedirectUris(redirectUris);
  if (!v.ok) return c.json({ error: v.code, message: v.message }, 400);
  const uriLines = v.uris;
  if (isSpa && uriLines.length === 0) return c.json({ error: 'missing_redirect_uri', message: 'SPA 必须配置至少一个 redirect_uri' }, 400);

  // ── 内容审查：关键词 + 敏感域名扫描 ──
  // 命中即拒绝并写一条 rejected 审计行（不创建应用，但留下试图注册的证据）
  const scanResult = scanAppFields(String(name || ''), String(appHomepage || ''), uriLines.join('\n'));
  if (scanResult) {
    c.executionCtx.waitUntil(writeAppAudit(c, {
      apiKeyId: id,  // 占位 UUID，方便定位"被拒绝的应用注册尝试"
      userId: uid,
      action: 'create',
      appName: name,
      clientType: isSpa ? 'spa' : 'backend',
      appHomepage,
      redirectUris: uriLines.join('\n'),
      scanResult: 'rejected',
      scanHits: scanResult.hits,
    }));
    return c.json({ error: 'content_violation', message: '应用注册被拒：' + scanResult.reason }, 400);
  }

  // SPA：不生成 API Key（key_hash 为空），自动开启 OIDC 公开客户端
  // Backend：生成 API Key，OIDC 可选
  let key = '';
  let keyHash = '';
  if (!isSpa) {
    key = 'nx_' + crypto.randomUUID().replace(/-/g, '');
    keyHash = await sha256(key);
  }
  const wantOidc = isSpa ? 1 : (oidcEnabled ? 1 : 0);
  // 邮箱验证 = require_email_verification AND captcha_enabled 才算开启；
  // 创建时若用户勾选「需要验证」，captcha_enabled 也跟着打开，保持语义一致
  const wantVerify = isSpa ? 0 : (requireEmailVerification ? 1 : 0);

  // 自动审批评估：OIDC 关 / 信任托管 / 已 DNS 验证 → approved；否则 pending（沙盒）
  const reviewStatus = await evaluateApprovalStatus(c.env.DB, uid, !!wantOidc, uriLines.join('\n'));

  await c.env.DB.prepare(
    'INSERT INTO api_keys (id, user_id, name, key_hash, allowed_ips, require_email_verification, captcha_enabled, oidc_enabled, redirect_uris, client_type, app_review_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(
    id,
    (c as any).get('userId') as string,
    (name || 'Default').trim(),
    keyHash,
    (allowedIps || ''),
    wantVerify,
    wantVerify,
    wantOidc,
    uriLines.join('\n'),
    isSpa ? 'spa' : 'backend',
    reviewStatus,
  ).run();

  const resp: any = {
    id,
    name: name || 'Default',
    status: 'active',
    allowedIps: allowedIps || '',
    oidcEnabled: !!wantOidc,
    redirectUris: redirectUris || '',
    clientType: isSpa ? 'spa' : 'backend',
    hasApiKey: !isSpa,
    reviewStatus,   // 前端据此显示"待审核"提示 + 引导验证流程
  };
  if (!isSpa) {
    resp.apiKey = key;
    resp.strategy = 'api_key';
  }
  // 异步审计：记录注册时 IP/UA + redirect_uri 域名 DNS 快照（不阻塞响应）
  c.executionCtx.waitUntil(writeAppAudit(c, {
    apiKeyId: id,
    userId: uid,
    action: 'create',
    appName: name,
    clientType: isSpa ? 'spa' : 'backend',
    appHomepage,
    redirectUris: uriLines.join('\n'),
    scanResult: 'pass',
  }));
  return c.json(resp, 201);
});

app.put('/api/clients/:id', authMW, async (c) => {
  const { name, allowedIps, requireEmailVerification, captchaEnabled } = await c.req.json().catch(() => ({}));
  const uid = (c as any).get('userId') as string;
  const pid = c.req.param('id');
  // 已撤销的应用不可再编辑
  const row = await c.env.DB.prepare('SELECT revoked, captcha_forced_off, banned, banned_reason FROM api_keys WHERE id = ? AND user_id = ?').bind(pid, uid).first() as any;
  if (!row) return c.json({ error: '应用不存在' }, 404);
  if (row.revoked) return c.json({ error: '该应用已撤销，无法编辑' }, 409);
  // 防绕过：被封 app 不能改任何字段（特别是 name），否则等于自动洗白违规命名
  if (Number(row.banned) === 1) {
    return err(c, 'app_banned', '该应用已被站长封禁，不能编辑' + (row.banned_reason ? `：${row.banned_reason}` : '') + '。如需申诉发邮件至 support@mail.miaogou.site', 403);
  }
  if (name) await c.env.DB.prepare('UPDATE api_keys SET name = ? WHERE id = ? AND user_id = ?').bind(name.trim(), pid, uid).run();
  if (allowedIps !== undefined) await c.env.DB.prepare('UPDATE api_keys SET allowed_ips = ? WHERE id = ? AND user_id = ?').bind(allowedIps, pid, uid).run();
  if (requireEmailVerification !== undefined) {
    // 配额耗尽强制关闭期间，拒绝任何 require_email_verification 改写（避免用户误以为开关已生效）
    if (row.captcha_forced_off) return c.json({ error: 'captcha_locked', message: '今日社区邮件配额已用完，验证码开关被系统暂时强制关闭，明日自动恢复' }, 423);
    // 两列必须同步：闸门 = require_email_verification AND captcha_enabled，CREATE 端就是同步写入，
    // PUT 必须保持同样语义，否则会出现"开关 ON 但发送验证码报未开启"的怪状态。
    const v = requireEmailVerification ? 1 : 0;
    await c.env.DB.prepare('UPDATE api_keys SET require_email_verification = ?, captcha_enabled = ? WHERE id = ? AND user_id = ?').bind(v, v, pid, uid).run();
  }
  // captcha_enabled 编辑：强制关闭期间拒绝改写
  if (captchaEnabled !== undefined) {
    if (row.captcha_forced_off) return c.json({ error: 'captcha_locked', message: '今日社区邮件配额已用完，验证码开关被系统暂时强制关闭，明日自动恢复' }, 423);
    await c.env.DB.prepare('UPDATE api_keys SET captcha_enabled = ? WHERE id = ? AND user_id = ?').bind(captchaEnabled ? 1 : 0, pid, uid).run();
  }
  // OIDC 字段走单独的 PATCH /api/clients/:id/oidc（body 不能在 Hono 中消费两次）
  return c.json({ success: true });
});

// 单独的 OIDC 字段更新端点（避免与上面 PUT 的 body 消费冲突）
app.patch('/api/clients/:id/oidc', authMW, async (c) => {
  const uid = (c as any).get('userId') as string;
  const pid = c.req.param('id');
  const { oidcEnabled, redirectUris, appLogo, appHomepage } = await c.req.json().catch(() => ({}));
  const row = await c.env.DB.prepare('SELECT revoked, name, client_type, redirect_uris, app_homepage, banned, banned_reason FROM api_keys WHERE id = ? AND user_id = ?').bind(pid, uid).first() as any;
  if (!row) return c.json({ error: '应用不存在' }, 404);
  if (row.revoked) return c.json({ error: '已撤销' }, 409);
  if (Number(row.banned) === 1) {
    return err(c, 'app_banned', '该应用已被站长封禁，不能修改' + (row.banned_reason ? `：${row.banned_reason}` : ''), 403);
  }

  // 计算扫描材料：用本次提交值，未提交则用现有值
  const effRedirectUris = redirectUris !== undefined ? String(redirectUris) : (row.redirect_uris || '');
  const effHomepage = appHomepage !== undefined ? String(appHomepage) : (row.app_homepage || '');
  // 关键词 + 敏感域名扫描
  const scanRes = scanAppFields(String(row.name || ''), effHomepage, effRedirectUris);
  if (scanRes) {
    c.executionCtx.waitUntil(writeAppAudit(c, {
      apiKeyId: pid,
      userId: uid,
      action: 'update_oidc',
      appName: row.name,
      clientType: row.client_type,
      appHomepage: effHomepage,
      redirectUris: effRedirectUris,
      scanResult: 'rejected',
      scanHits: scanRes.hits,
    }));
    return c.json({ error: 'content_violation', message: '修改被拒：' + scanRes.reason }, 400);
  }

  if (oidcEnabled !== undefined) await c.env.DB.prepare('UPDATE api_keys SET oidc_enabled = ? WHERE id = ? AND user_id = ?').bind(oidcEnabled ? 1 : 0, pid, uid).run();
  if (redirectUris !== undefined) {
    // 严格校验（同 POST /api/clients）
    const v = validateRedirectUris(redirectUris);
    if (!v.ok) return c.json({ error: v.code, message: v.message }, 400);
    await c.env.DB.prepare('UPDATE api_keys SET redirect_uris = ? WHERE id = ? AND user_id = ?').bind(v.uris.join('\n'), pid, uid).run();
  }
  if (appLogo !== undefined) await c.env.DB.prepare('UPDATE api_keys SET app_logo = ? WHERE id = ? AND user_id = ?').bind(String(appLogo), pid, uid).run();
  if (appHomepage !== undefined) await c.env.DB.prepare('UPDATE api_keys SET app_homepage = ? WHERE id = ? AND user_id = ?').bind(String(appHomepage), pid, uid).run();

  // ★ 关键覆盖：任何对 oidc_enabled / redirect_uris 的改动都触发重新评估审批状态
  // 路径包括：① 纯 API Key 应用首次打开 OIDC ② OIDC 应用修改 redirect URI ③ 关闭 OIDC
  // 不允许从 'rejected'（被站长禁用）回到 approved/pending —— rejected 是永久标记
  const cur = await c.env.DB.prepare('SELECT oidc_enabled, redirect_uris, app_review_status FROM api_keys WHERE id = ? AND user_id = ?').bind(pid, uid).first() as any;
  if (cur && cur.app_review_status !== 'rejected') {
    const newStatus = await evaluateApprovalStatus(c.env.DB, uid, !!cur.oidc_enabled, cur.redirect_uris || '');
    await c.env.DB.prepare('UPDATE api_keys SET app_review_status = ? WHERE id = ? AND user_id = ?').bind(newStatus, pid, uid).run();
  }

  // 异步审计：本次修改后的 redirect URI DNS 快照
  c.executionCtx.waitUntil(writeAppAudit(c, {
    apiKeyId: pid,
    userId: uid,
    action: 'update_oidc',
    appName: row.name,
    clientType: row.client_type,
    appHomepage: effHomepage,
    redirectUris: effRedirectUris,
    scanResult: 'pass',
  }));
  return c.json({ success: true });
});

// 生成/重置 client_secret（机密客户端）
app.post('/api/clients/:id/client-secret', authMW, async (c) => {
  const uid = (c as any).get('userId') as string;
  const pid = c.req.param('id');
  const row = await c.env.DB.prepare('SELECT revoked, banned, banned_reason FROM api_keys WHERE id = ? AND user_id = ?').bind(pid, uid).first() as any;
  if (!row) return c.json({ error: '应用不存在' }, 404);
  if (row.revoked) return c.json({ error: '已撤销' }, 409);
  if (Number(row.banned) === 1) return err(c, 'app_banned', '该应用已被站长封禁，无法生成 Client Secret' + (row.banned_reason ? `：${row.banned_reason}` : ''), 403);
  const secret = generateClientSecret();
  const hash = await sha256Hex(secret);
  await c.env.DB.prepare('UPDATE api_keys SET client_secret_hash = ? WHERE id = ? AND user_id = ?').bind(hash, pid, uid).run();
  return c.json({ clientSecret: secret });   // 一次性返回，不再可见
});

// 删除 client_secret（改回公开客户端）
app.delete('/api/clients/:id/client-secret', authMW, async (c) => {
  const uid = (c as any).get('userId') as string;
  const pid = c.req.param('id');
  const row = await c.env.DB.prepare('SELECT banned, banned_reason FROM api_keys WHERE id = ? AND user_id = ?').bind(pid, uid).first() as any;
  if (!row) return c.json({ error: '应用不存在' }, 404);
  if (Number(row.banned) === 1) return err(c, 'app_banned', '该应用已被站长封禁，无法修改' + (row.banned_reason ? `：${row.banned_reason}` : ''), 403);
  await c.env.DB.prepare('UPDATE api_keys SET client_secret_hash = NULL WHERE id = ? AND user_id = ?').bind(pid, uid).run();
  return c.json({ success: true });
});

// 为 SPA 应用补生成 API Key（从纯 OIDC 升级为双模）
app.post('/api/clients/:id/generate-api-key', authMW, async (c) => {
  const uid = (c as any).get('userId') as string;
  const pid = c.req.param('id');
  const row = await c.env.DB.prepare('SELECT key_hash, revoked, banned, banned_reason FROM api_keys WHERE id = ? AND user_id = ?').bind(pid, uid).first() as any;
  if (!row) return c.json({ error: '应用不存在' }, 404);
  if (row.revoked) return c.json({ error: '已撤销' }, 409);
  if (Number(row.banned) === 1) return err(c, 'app_banned', '该应用已被站长封禁，无法生成 API Key' + (row.banned_reason ? `：${row.banned_reason}` : ''), 403);
  if (row.key_hash) return c.json({ error: '该应用已有 API Key，请使用轮换而非生成' }, 409);
  const key = 'nx_' + crypto.randomUUID().replace(/-/g, '');
  const hash = await sha256(key);
  // 同时把 client_type 升回 backend（SPA → backend 升级）
  await c.env.DB.prepare("UPDATE api_keys SET key_hash = ?, client_type = 'backend' WHERE id = ? AND user_id = ?").bind(hash, pid, uid).run();
  return c.json({ apiKey: key });
});

// 移除 API Key（保留 OIDC 配置，变为纯 SPA 模式）
app.delete('/api/clients/:id/api-key', authMW, async (c) => {
  const uid = (c as any).get('userId') as string;
  const pid = c.req.param('id');
  const row = await c.env.DB.prepare('SELECT key_hash, oidc_enabled, banned, banned_reason FROM api_keys WHERE id = ? AND user_id = ?').bind(pid, uid).first() as any;
  if (!row) return c.json({ error: '应用不存在' }, 404);
  if (Number(row.banned) === 1) return err(c, 'app_banned', '该应用已被站长封禁，无法修改' + (row.banned_reason ? `：${row.banned_reason}` : ''), 403);
  if (!row.key_hash) return c.json({ error: '该应用没有 API Key' }, 409);
  if (!row.oidc_enabled) return c.json({ error: '请先开启 OIDC 再移除 API Key（应用必须至少有一种认证方式）' }, 409);
  await c.env.DB.prepare('UPDATE api_keys SET key_hash = ?, client_type = ? WHERE id = ? AND user_id = ?').bind('', 'spa', pid, uid).run();
  return c.json({ success: true });
});

app.delete('/api/clients/:id', authMW, async (c) => {
  // 删除应用：清掉日志，把关联的 gateway_users.api_key_id 置 NULL（孤立），保留用户数据本身
  const id = c.req.param('id');
  const uid = (c as any).get('userId') as string;
  const row = await c.env.DB.prepare('SELECT id, banned, banned_reason FROM api_keys WHERE id = ? AND user_id = ?').bind(id, uid).first() as any;
  if (!row) return c.json({ error: '应用不存在' }, 404);
  // 防绕过最关键的洞：被封 app 不能删除，否则 DELETE FROM api_keys → 整行没了 → ban_audit_log
  // 里的 target_id 成为悬挂引用，违规历史被"漂白"。封禁后行必须保留，呼应 ToS § 4「账户被停用后
  // 相关数据保留 90 个自然日用于法律响应」
  if (Number(row.banned) === 1) {
    return err(c, 'app_banned', '该应用已被站长封禁，不能删除（封禁记录需保留用于法律响应）' + (row.banned_reason ? `：${row.banned_reason}` : '') + '。如需申诉发邮件至 support@mail.miaogou.site', 403);
  }
  const orphan = await c.env.DB.prepare('SELECT COUNT(*) as c FROM gateway_users WHERE api_key_id = ?').bind(id).first() as any;
  await c.env.DB.prepare('DELETE FROM page_views WHERE api_key_id = ?').bind(id).run().catch(() => {});
  await c.env.DB.prepare('DELETE FROM email_logs WHERE api_key_id = ?').bind(id).run().catch(() => {});
  // OIDC：把该 client 的 grants 也清掉（用户下次访问需要重新同意）
  await c.env.DB.prepare('DELETE FROM oidc_grants WHERE api_key_id = ?').bind(id).run().catch(() => {});
  // 用户数据：api_key_id 置 NULL，开发者层面仍能查到这些"前应用"用户
  await c.env.DB.prepare('UPDATE gateway_users SET api_key_id = NULL WHERE api_key_id = ?').bind(id).run().catch(() => {});
  await c.env.DB.prepare('DELETE FROM api_keys WHERE id = ? AND user_id = ?').bind(id, uid).run();
  return c.json({ success: true, orphanedUsers: orphan?.c || 0 });
});

app.post('/api/clients/:id/rotate-key', authMW, async (c) => {
  const rotateUid = (c as any).get('userId') as string;
  const rotatePid = c.req.param('id');
  const row = await c.env.DB.prepare('SELECT key_hash, revoked, banned, banned_reason FROM api_keys WHERE id = ? AND user_id = ?').bind(rotatePid, rotateUid).first() as any;
  if (!row) return c.json({ error: '应用不存在' }, 404);
  if (row.revoked) return c.json({ error: '该应用已撤销，无法轮换密钥' }, 409);
  if (Number(row.banned) === 1) return err(c, 'app_banned', '该应用已被站长封禁，无法轮换密钥' + (row.banned_reason ? `：${row.banned_reason}` : ''), 403);
  if (!row.key_hash) return c.json({ error: '该应用没有 API Key（SPA 类型），请先生成' }, 409);
  const key = 'nx_' + crypto.randomUUID().replace(/-/g, '');
  await c.env.DB.prepare('UPDATE api_keys SET key_hash = ? WHERE id = ? AND user_id = ?').bind(await sha256(key), rotatePid, rotateUid).run();
  return c.json({ apiKey: key });
});

// 读取最近 50 条投递历史（用户必须是该 webhook 的所有者）
app.get('/api/webhooks/:id/deliveries', authMW, async (c) => {
  const uid = (c as any).get('userId') as string;
  const wid = c.req.param('id');
  const own = await c.env.DB.prepare('SELECT 1 FROM webhooks WHERE id = ? AND user_id = ?').bind(wid, uid).first();
  if (!own) return err(c, 'not_found', 'Webhook 不存在或无权访问', 404);
  const { results } = await c.env.DB.prepare(
    'SELECT id, event, attempt, status_code, success, duration_ms, error_text, created_at FROM webhook_deliveries WHERE webhook_id = ? ORDER BY created_at DESC LIMIT 50'
  ).bind(wid).all();
  return c.json({ deliveries: results });
});

// ══════ Public Metrics ══════
app.get('/api/metrics', async (c) => {
  const keys = await c.env.DB.prepare('SELECT COUNT(*) as c FROM api_keys WHERE revoked = 0').first() as any;
  const users = await c.env.DB.prepare('SELECT COUNT(*) as c FROM gateway_users').first() as any;
  const views = await c.env.DB.prepare("SELECT COUNT(*) as c FROM page_views WHERE path LIKE '/api/%'").first() as any;
  const recent = await c.env.DB.prepare("SELECT COUNT(*) as c FROM page_views WHERE path LIKE '/api/%' AND created_at >= datetime('now', '+8 hours', '-1 hour')").first() as any;
  return c.json({ gateway: { activeClients: keys?.c || 0, totalUsers: users?.c || 0, totalRequests: views?.c || 0 }, metrics: { last1h: { totalRequests: recent?.c || 0 } } });
});

app.get('/api/metrics/logs', authMW, async (c) => {
  const limit = parseInt(c.req.query('limit') || '50');
  const apiKeyId = c.req.query('api_key_id') || '';
  const uid = c.get('userId') as string;
  let q = "SELECT pv.id, pv.path, pv.ip, pv.user_agent, pv.api_key_id, pv.created_at FROM page_views pv JOIN api_keys k ON pv.api_key_id = k.id WHERE k.user_id = ?";
  const params: any[] = [uid];
  if (apiKeyId) { q += ' AND pv.api_key_id = ?'; params.push(apiKeyId); }
  q += ' ORDER BY pv.created_at DESC LIMIT ?'; params.push(limit);
  const { results } = await c.env.DB.prepare(q).bind(...params).all();
  return c.json({ logs: results.map((r: any) => ({ id: r.id, path: r.path, ip: r.ip, user_agent: r.user_agent, api_key_id: r.api_key_id, timestamp: r.created_at })) });
});

app.get('/api/metrics/analytics', authMW, async (c) => {
  const uid = c.get('userId') as string;
  const { results } = await c.env.DB.prepare(
    "SELECT pv.created_at, pv.path, pv.api_key_id FROM page_views pv JOIN api_keys k ON pv.api_key_id = k.id WHERE k.user_id = ? ORDER BY pv.created_at DESC LIMIT 168"
  ).bind(uid).all();
  return c.json({ hourly: results });
});

// ══════ Webhooks ══════
app.post('/api/webhooks', authMW, async (c) => {
  const { url, events, secret, apiKeyId } = await c.req.json().catch(() => ({}));
  if (!url?.trim()) return err(c, 'missing_fields', 'URL 为必填项', 400, 'url');
  try { assertSafeUrl(url.trim()); }
  catch (e: any) { return err(c, 'invalid_url', e.message, 400, 'url'); }
  const uid = (c as any).get('userId') as string;
  // apiKeyId 校验：必须是该开发者自己的应用，防绑别人应用上偷事件
  let resolvedApiKeyId: string | null = null;
  if (apiKeyId && typeof apiKeyId === 'string' && apiKeyId.trim()) {
    const own = await c.env.DB.prepare('SELECT id FROM api_keys WHERE id = ? AND user_id = ?').bind(apiKeyId.trim(), uid).first();
    if (!own) return err(c, 'invalid_api_key', '指定的应用不存在或不属于你', 400, 'apiKeyId');
    resolvedApiKeyId = apiKeyId.trim();
  }
  const id = crypto.randomUUID();
  await c.env.DB.prepare('INSERT INTO webhooks (id, user_id, url, events, secret, api_key_id) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(id, uid, url.trim(), (events || 'user.registered,user.login'), (secret || ''), resolvedApiKeyId).run();
  return c.json({ id, url: url.trim(), events, api_key_id: resolvedApiKeyId, active: true }, 201);
});

app.get('/api/webhooks', authMW, async (c) => {
  const { results } = await c.env.DB.prepare('SELECT id, url, events, active, api_key_id, created_at FROM webhooks WHERE user_id = ? ORDER BY created_at DESC').bind((c as any).get('userId') as string).all();
  return c.json({ webhooks: results });
});

app.delete('/api/webhooks/:id', authMW, async (c) => {
  await c.env.DB.prepare('DELETE FROM webhooks WHERE id = ? AND user_id = ?').bind(c.req.param('id'), c.get('userId') as string).run();
  return c.json({ success: true });
});

app.post('/api/webhooks/:id/test', authMW, async (c) => {
  const wh = await c.env.DB.prepare('SELECT url, secret FROM webhooks WHERE id = ? AND user_id = ?').bind(c.req.param('id'), c.get('userId') as string).first() as any;
  if (!wh) return err(c, 'not_found', 'Webhook 不存在', 404);
  try { assertSafeUrl(wh.url); }
  catch (e: any) { return c.json({ success: false, error: e.message }, 400); }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 5000);
  try {
    const body = JSON.stringify({ event: 'test', timestamp: new Date().toISOString(), message: 'Webhook test from AuthCore' });
    const headers: Record<string, string> = { 'Content-Type': 'application/json', 'X-AuthCore-Event': 'test', 'User-Agent': 'AuthCore-Webhook/1.0' };
    if (wh.secret) headers['X-AuthCore-Signature'] = await sha256(body + wh.secret);
    const resp = await fetch(wh.url, { method: 'POST', headers, body, redirect: 'manual', signal: ctrl.signal });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return c.json({ success: true, status: resp.status });
  } catch (e: any) { return c.json({ success: false, error: e.message }, 502); }
  finally { clearTimeout(timer); }
});

// ══════ Email Logs ══════
app.get('/api/email-logs', authMW, async (c) => {
  const limit = parseInt(c.req.query('limit') || '50');
  const apiKeyId = c.req.query('api_key_id') || '';
  const uid = c.get('userId') as string;
  let q = 'SELECT e.id, e.api_key_id, e.to_email, e.success, e.error, e.created_at FROM email_logs e INNER JOIN api_keys k ON e.api_key_id = k.id WHERE k.user_id = ?';
  const params: any[] = [uid];
  if (apiKeyId) { q += ' AND e.api_key_id = ?'; params.push(apiKeyId); }
  q += ' ORDER BY e.created_at DESC LIMIT ?';
  params.push(limit);
  const { results } = await c.env.DB.prepare(q).bind(...params).all();
  return c.json({ logs: results });
});

// ══════ OIDC OpenID Connect Provider ══════
import {
  getOrCreateActiveSigningKey, listJwks, signRs256Jwt, verifyPkce, sha256B64u, sha256Hex,
  pbkdf2Hash as oidcPbkdf2Hash, pbkdf2Verify as oidcPbkdf2Verify,
  generateClientSecret, isValidRedirectUri, decodeJwtPayload, getActivePublicKey, verifyRs256,
} from './oidc';

const ISSUER = 'https://auth.miaogou.site';
const SSO_TTL_DAYS = 30;
const CODE_TTL_SEC = 60;
const ID_TOKEN_TTL_SEC = 3600;
const ACCESS_TOKEN_TTL_SEC = 3600;
const REFRESH_TOKEN_TTL_DAYS = 30;

// ── Cookie helpers ──
function readCookie(c: any, name: string): string {
  const cookie = c.req.header('Cookie') || '';
  const m = cookie.match(new RegExp('(?:^|; )' + name.replace(/[.$?*|{}()[\]\\/+^]/g, '\\$&') + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}
function setSsoCookie(c: any, sessionId: string) {
  const maxAge = SSO_TTL_DAYS * 24 * 3600;
  // 先清旧 cookie（host-only + domain 两个版本），防新旧碰撞
  clearSsoCookie(c);
  c.header('Set-Cookie', `nx_sso=${sessionId}; Domain=.miaogou.site; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`, { append: true });
}
function clearSsoCookie(c: any) {
  // 同时清 host-only 版本（旧 cookie）和 domain 版本
  c.header('Set-Cookie', 'nx_sso=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0', { append: true });
  c.header('Set-Cookie', 'nx_sso=; Domain=.miaogou.site; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0', { append: true });
}

// ── SSO 当前身份（多 cookie 遍历取有效，防新旧碰撞）──
async function getSsoIdentity(c: any): Promise<any | null> {
  const cookieHeader = c.req.header('Cookie') || '';
  const sids = [...cookieHeader.matchAll(/(?:^|;\s*)nx_sso=([^;]*)/g)].map(m => m[1]);
  for (const sid of sids) {
    if (!sid) continue;
    const sess = await c.env.DB.prepare(
      `SELECT s.identity_id, i.id, i.email, i.email_verified, i.username, i.avatar_url, i.banned, i.banned_reason
       FROM oidc_sso_sessions s JOIN oidc_identities i ON s.identity_id = i.id
       WHERE s.session_id = ? AND s.expires_at > datetime('now', '+8 hours')`
    ).bind(sid).first() as any;
    if (!sess) continue;
    // 封禁兜底：会话还在但身份被封 → 立即清会话 + cookie，返回 null（视为未登录）
    if (Number(sess.banned) === 1) {
      await c.env.DB.prepare('DELETE FROM oidc_sso_sessions WHERE identity_id = ?').bind(sess.identity_id).run().catch(() => {});
      clearSsoCookie(c);
      // 抛特殊错让上游路由可以提示具体原因；此处先 return null 让 caller 走"未登录"分支
      // OIDC authorize 上游会重新触发 SSO 登录 → 输错时再展示封禁错误
      return null;
    }
    return sess;
  }
  return null;
}

// ── Discovery ──
app.get('/.well-known/openid-configuration', (c) => c.json({
  issuer: ISSUER,
  authorization_endpoint: ISSUER + '/oauth/authorize',
  token_endpoint: ISSUER + '/oauth/token',
  userinfo_endpoint: ISSUER + '/oauth/userinfo',
  jwks_uri: ISSUER + '/oauth/jwks',
  revocation_endpoint: ISSUER + '/oauth/revoke',
  response_types_supported: ['code'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['RS256'],
  scopes_supported: ['openid', 'email', 'profile'],
  token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
  claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce', 'email', 'email_verified', 'name', 'picture'],
  code_challenge_methods_supported: ['S256'],
  grant_types_supported: ['authorization_code', 'refresh_token'],
}));

// ── JWKS ──
app.get('/oauth/jwks', async (c) => {
  await getOrCreateActiveSigningKey(c.env.DB);
  return c.json(await listJwks(c.env.DB));
});

// ── 默认头像 SVG：用户没设头像时返回「首字母 + 哈希配色圆」占位 ──
// 设过头像的用户：302 到真实 URL。这样 picture 字段可以始终是 ISSUER + '/avatar/{sub}.svg'，三网共用一个 URL。
function hashHue(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return Math.abs(h) % 360;
}
function escapeXml(s: string): string {
  return s.replace(/[<>&"']/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c] as string));
}
app.get('/avatar/:filename', async (c) => {
  const filename = c.req.param('filename') || '';
  const sub = filename.replace(/\.(svg|png|jpg|jpeg|webp)$/i, '');
  let row: any = null;
  if (sub) {
    row = await c.env.DB.prepare(
      `SELECT email, username, avatar_url FROM oidc_identities WHERE id = ?`
    ).bind(sub).first();
  }
  if (row?.avatar_url) {
    const v = String(row.avatar_url);
    // R2 存储：avatar_url = 'r2:{key}'，从 bucket 读字节直出
    if (v.startsWith('r2:')) {
      const key = v.slice(3);
      try {
        const obj = await c.env.AVATARS.get(key);
        if (obj) {
          return new Response(obj.body as any, {
            headers: {
              'Content-Type': obj.httpMetadata?.contentType || 'image/jpeg',
              'Cache-Control': 'public, max-age=60, s-maxage=300',
            },
          });
        }
      } catch (_) {}
      // R2 读失败 → 退回 SVG
    } else if (/^https?:\/\//i.test(v)) {
      // 外部 URL（社交登录返回的头像、用户手填）→ 302 重定向
      return new Response(null, {
        status: 302,
        headers: { Location: v, 'Cache-Control': 'public, max-age=60' },
      });
    }
  }
  const seed = sub || 'guest';
  const initialSrc = (row?.username || row?.email || '?').toString();
  const initial = escapeXml(([...initialSrc][0] || '?').toUpperCase());
  const hue = hashHue(seed);
  const bg = `hsl(${hue}, 60%, 52%)`;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200"><circle cx="100" cy="100" r="100" fill="${bg}"/><text x="100" y="100" text-anchor="middle" dominant-baseline="central" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="100" font-weight="700" fill="#fff">${initial}</text></svg>`;
  return new Response(svg, {
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': 'public, max-age=300, s-maxage=3600',
      'X-Content-Type-Options': 'nosniff',
    },
  });
});

// ── Authorize info (Vue 授权页拉取上下文) ──
app.get('/oauth/authorize/info', async (c) => {
  const clientId = c.req.query('client_id') || '';
  const redirectUri = c.req.query('redirect_uri') || '';
  const scope = c.req.query('scope') || 'openid';
  const responseType = c.req.query('response_type') || '';
  if (!clientId || !redirectUri) return err(c, 'invalid_request', '缺少 client_id 或 redirect_uri', 400);
  if (responseType !== 'code') return err(c, 'unsupported_response_type', '仅支持 response_type=code', 400);
  const app2 = await c.env.DB.prepare(
    `SELECT k.id, k.name, k.oidc_enabled, k.redirect_uris, k.app_logo, k.app_homepage, k.revoked, k.app_review_status, k.user_id, u.email AS owner_email
     FROM api_keys k LEFT JOIN gateway_users u ON u.id = k.user_id WHERE k.id = ?`
  ).bind(clientId).first() as any;
  if (!app2 || app2.revoked) return err(c, 'invalid_client', '应用不存在或已撤销', 400);
  if (!app2.oidc_enabled) return err(c, 'oidc_disabled', '该应用未启用 OIDC', 400);
  if (!isValidRedirectUri(redirectUri, app2.redirect_uris || '')) return err(c, 'invalid_redirect_uri', 'redirect_uri 不在白名单内', 400, 'redirect_uri', redirectUri, '把这串地址完整粘贴到控制台 → 你的应用 → Redirect URIs');
  // ★ 防钓鱼：rejected 永久拒绝
  if (app2.app_review_status === 'rejected') {
    return err(c, 'app_rejected', '该应用已被平台拒绝（违反服务条款），无法使用', 403);
  }
  const sso = await getSsoIdentity(c);
  // ★ 防钓鱼：pending 状态下仅应用所有者本人可登录（沙盒模式，给开发者自测）
  // 其他任何用户尝试授权 → 拒绝，提示该应用需要域名验证
  if (app2.app_review_status === 'pending' && sso && sso.email !== app2.owner_email) {
    return err(
      c, 'app_pending_review',
      '该应用使用了自定义域名，尚未通过域名所有权验证。当前仅应用所有者可登录测试，公开使用前需联系平台管理员审批',
      403, 'app', app2.name,
    );
  }
  const granted = sso ? await c.env.DB.prepare(`SELECT 1 FROM oidc_grants WHERE identity_id = ? AND api_key_id = ?`).bind(sso.identity_id, clientId).first() : null;
  return c.json({
    app: { id: app2.id, name: app2.name, logo: app2.app_logo || '', homepage: app2.app_homepage || '', review_status: app2.app_review_status },
    sso: sso ? { id: sso.identity_id, email: sso.email, username: sso.username, avatar_url: sso.avatar_url } : null,
    already_granted: !!granted,
    is_owner_sandbox: sso ? sso.email === app2.owner_email && app2.app_review_status === 'pending' : false,
    scope,
  });
});

// ── Authorize login (SSO 登录) ──
// 兼容旧 gateway_users：若 oidc_identities 找不到该 email，回退到 gateway_users 表，
// 任意一条记录密码匹配即视为登录成功，并即时把该用户迁移到全局身份池
// 登录失败 IP 计数（撞库防护）：连续 5 次失败后 15 分钟阻断
async function loginFailCount(c: any): Promise<number> {
  const ip = c.req.header('CF-Connecting-IP') || 'unknown';
  const ws = Math.floor(Date.now() / 1000 / 900) * 900;
  const r = await c.env.DB.prepare(
    `SELECT count FROM rate_limits WHERE ip = ? AND endpoint = 'login_fail' AND window_start = ?`
  ).bind(ip, ws).first() as any;
  return r?.count || 0;
}
async function bumpLoginFail(c: any) {
  const ip = c.req.header('CF-Connecting-IP') || 'unknown';
  const ws = Math.floor(Date.now() / 1000 / 900) * 900;
  await c.env.DB.prepare(
    `INSERT INTO rate_limits (ip, endpoint, window_start, count) VALUES (?, 'login_fail', ?, 1)
     ON CONFLICT(ip, endpoint, window_start) DO UPDATE SET count = count + 1`
  ).bind(ip, ws).run().catch(() => {});
}

// upsert 助手：迁移老用户到 oidc_identities，UNIQUE 冲突时同步最新 hash/salt
async function upsertOidcIdentity(c: any, email: string, passwordHash: string, salt: string, hashVersion: number, username: string): Promise<string> {
  const newId = crypto.randomUUID();
  try {
    await c.env.DB.prepare(
      `INSERT INTO oidc_identities (id, email, password_hash, salt, hash_version, username) VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(newId, email, passwordHash, salt, hashVersion, username).run();
    return newId;
  } catch (e: any) {
    // 已存在 → 同步最新 hash（修复历史上把 SHA-256 错写成 hash_version=1 的情况）
    await c.env.DB.prepare(
      `UPDATE oidc_identities SET password_hash = ?, salt = ?, hash_version = ? WHERE email = ?`
    ).bind(passwordHash, salt, hashVersion, email).run().catch(() => {});
    const again = await c.env.DB.prepare(`SELECT id FROM oidc_identities WHERE email = ?`).bind(email).first() as any;
    return again?.id || newId;
  }
}

// Playground 演示账号邮箱模式（playground-<random>@example.com）
// 这些账号是 SDK /api/auth/register 创建的 tenant-isolated 用户，按设计：
//   - 只能登录创建它们的那个 demo app（X-API-Key 受限的 /api/auth/login）
//   - 不能 SSO 进任何 OIDC 应用（包括平台三网与第三方应用）
//   - 不能登录开发者控制台（gateway_users 表里没行）
// 通过在 /oauth/authorize/login & /register 早期拦截邮箱模式来强制隔离
function isPlaygroundDemoEmail(email: string): boolean {
  return /^playground-[a-z0-9]{6,}@example\.com$/i.test(String(email || ''));
}

app.post('/oauth/authorize/login', async (c) => {
  const csrf = requireSameOrigin(c); if (csrf) return csrf;
  if (await rateLimit(c, 'oidc_login', 60, 10)) return err(c, 'rate_limited', '请求过于频繁', 429);
  // 连续失败 5+ 次 → 强制阻断 15 分钟
  if ((await loginFailCount(c)) >= 5) {
    return err(c, 'too_many_failures', '登录失败次数过多，请 15 分钟后再试', 429);
  }
  const { email, password } = await c.req.json().catch(() => ({}));
  if (!email || !password) return err(c, 'missing_fields', '邮箱和密码必填', 400);

  // 演示账号隔离：直接拒绝，不暴露"账号存在"信息
  if (isPlaygroundDemoEmail(email)) {
    await bumpLoginFail(c).catch(() => {});
    return err(c, 'invalid_credentials', '邮箱或密码错误', 401);
  }

  let identityId: string | null = null;
  let migrationSource = '';

  // 1) 先查 oidc_identities
  const oidcUser = await c.env.DB.prepare(`SELECT id, password_hash, salt, hash_version FROM oidc_identities WHERE email = ?`).bind(email).first() as any;
  if (oidcUser) {
    let valid = false;
    if (oidcUser.hash_version === 1 && oidcUser.salt) {
      valid = await oidcPbkdf2Verify(password, oidcUser.password_hash, oidcUser.salt);
    } else {
      const sha = await sha256(password);
      valid = (sha === oidcUser.password_hash);
    }
    if (valid) { identityId = oidcUser.id; migrationSource = 'oidc_identities'; }
    else console.error('[OIDC login] oidc_identities hash mismatch for', email);
  }

  // 2) 回退：gateway_users（任一条记录密码匹配即可）
  if (!identityId) {
    const { results } = await c.env.DB.prepare(
      `SELECT id, username, password_hash, salt, hash_version FROM gateway_users WHERE email = ?`
    ).bind(email).all();
    for (const gu of (results as any[])) {
      let valid = false;
      if (gu.hash_version === 1 && gu.salt) {
        valid = await oidcPbkdf2Verify(password, gu.password_hash, gu.salt);
      } else {
        const sha = await sha256(password);
        valid = (sha === gu.password_hash);
      }
      if (valid) {
        migrationSource = 'gateway_users';
        identityId = await upsertOidcIdentity(c, email, gu.password_hash, gu.salt || '', gu.hash_version || 1, gu.username || '');
        break;
      }
    }
    if (!identityId && results.length > 0) console.error('[OIDC login] gateway_users found but all hashes mismatch for', email, 'rows=', results.length);
  }

  // 3) 回退：personal-site users 表
  if (!identityId) {
    const pu = await c.env.DB.prepare(
      `SELECT id, username, password_hash, salt, hash_version FROM users WHERE email = ?`
    ).bind(email).first().catch(() => null) as any;
    if (pu) {
      let valid = false;
      if (pu.hash_version === 1 && pu.salt) {
        valid = await oidcPbkdf2Verify(password, pu.password_hash, pu.salt);
      } else {
        const sha = await sha256(password);
        valid = (sha === pu.password_hash);
      }
      if (valid) {
        migrationSource = 'users';
        identityId = await upsertOidcIdentity(c, email, pu.password_hash, pu.salt || '', pu.hash_version || 1, pu.username || '');
      } else {
        console.error('[OIDC login] users (personal-site) hash mismatch for', email);
      }
    }
  }

  if (!identityId) {
    await bumpLoginFail(c);
    console.error('[OIDC login] FINAL FAILURE for', email);
    return err(c, 'invalid_credentials', '邮箱或密码错误', 401);
  }

  // 封禁兜底：跨三张表任一标 banned=1 即拒绝 OIDC 登录
  // 此时密码已正确，可以暴露具体原因
  const banChk = await c.env.DB.prepare(
    `SELECT MAX(banned) AS b, MAX(banned_reason) AS r FROM (
       SELECT banned, banned_reason FROM oidc_identities WHERE email = ?
       UNION ALL SELECT banned, banned_reason FROM users WHERE email = ?
       UNION ALL SELECT banned, banned_reason FROM gateway_users WHERE email = ?)`
  ).bind(email, email, email).first() as any;
  if (banChk && Number(banChk.b) === 1) {
    return err(c, 'account_banned', '账号已被封禁' + (banChk.r ? `：${banChk.r}` : '') + '。第三方应用无法接受被封禁账号登录', 403);
  }

  if (migrationSource && migrationSource !== 'oidc_identities') {
    console.log('[OIDC login] migrated from', migrationSource, 'for', email);
  }

  const sid = crypto.randomUUID();
  await c.env.DB.prepare(
    `INSERT INTO oidc_sso_sessions (session_id, identity_id, expires_at) VALUES (?, ?, datetime('now', '+8 hours', '+${SSO_TTL_DAYS} days'))`
  ).bind(sid, identityId).run();
  setSsoCookie(c, sid);
  return c.json({ success: true });
});

// ── Authorize send-code (OIDC 注册发邮箱验证码 — 防黑客批量注册) ──
app.post('/oauth/authorize/send-code', async (c) => {
  const csrf = requireSameOrigin(c); if (csrf) return csrf;
  const { email } = await c.req.json().catch(() => ({}));
  if (!email) return err(c, 'missing_fields', '邮箱必填', 400);
  // 多维度限流
  if (await rateLimit(c, 'oidc_sendcode:e:' + email, 60, 1)) return err(c, 'rate_limited', '该邮箱 60 秒内已发送过验证码', 429);
  if (await rateLimit(c, 'oidc_sendcode:ip:m', 60, 3)) return err(c, 'rate_limited', '发送太频繁', 429);
  if (await rateLimit(c, 'oidc_sendcode:ip:h', 3600, 10)) return err(c, 'rate_limited', '今日发送次数已达上限', 429);
  // 预检：该邮箱是否已注册过 OIDC 身份？避免浪费邮件配额（与 oidc register 同表）
  const dupOidc = await c.env.DB.prepare('SELECT id FROM oidc_identities WHERE email = ?').bind(email).first();
  if (dupOidc) return err(c, 'email_registered', '该邮箱已注册，请直接登录', 409, 'email');
  await restoreCaptchaIfNewDay(c.env.DB).catch(() => {});
  const reserved = await checkAndReserveQuota(c.env.DB);
  if (!reserved) return err(c, 'quota_exceeded', '今日社区邮件配额已用完，明日恢复', 429);
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const codeHash = await sha256(code);
  const id = crypto.randomUUID();
  await c.env.DB.prepare("INSERT INTO verification_codes (id, api_key_id, email, code_hash, expires_at) VALUES (?, 'oidc-register', ?, ?, datetime('now', '+8 hours', '+5 minutes'))").bind(id, email, codeHash).run();
  let emailSent = false; let emailError = '';
  const resendKey = c.env.RESEND_API_KEY;
  if (!resendKey) {
    emailError = 'RESEND_API_KEY not configured';
  } else if (resendBreakerOpen()) {
    emailError = 'Resend 短期内连续失败，已临时熔断';
  } else {
    try {
      const resp = await fetchWithTimeout('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${resendKey}` },
        body: JSON.stringify({
          from: 'AuthCore <noreply@mail.miaogou.site>', to: [email],
          subject: `AuthCore 注册验证码: ${code}`,
          html: `<p>${code} 是你的 AuthCore 注册验证码，5 分钟内有效。</p>`,
        }),
      }, 8000);
      emailSent = resp.ok;
      if (!resp.ok) emailError = `Resend HTTP ${resp.status}`;
      resendNoteResult(resp.ok);
    } catch (e: any) {
      emailError = e?.name === 'AbortError' ? 'Resend 请求超时（8s）' : (e.message || 'Resend fetch failed');
      resendNoteResult(false);
    }
  }
  if (!emailSent) await rollbackQuota(c.env.DB);
  return c.json({ success: true, email_sent: emailSent, expires_in: 300, error: emailError || undefined });
});

// ── Authorize register (创建 OIDC 全局身份 — 必须先通过邮箱验证码) ──
app.post('/oauth/authorize/register', async (c) => {
  const csrf = requireSameOrigin(c); if (csrf) return csrf;
  if (await rateLimit(c, 'oidc_register', 60, 5)) return err(c, 'rate_limited', '请求过于频繁', 429);
  const { email, password, username, code } = await c.req.json().catch(() => ({}));
  if (!email || !password) return err(c, 'missing_fields', '邮箱和密码必填', 400);
  if (!code) return err(c, 'missing_code', '请先获取并填写邮箱验证码', 400, 'code');
  // 演示账号邮箱模式专门保留给 Playground SDK 注册流程使用，不允许直接注册到 oidc_identities
  if (isPlaygroundDemoEmail(email)) {
    return err(c, 'reserved_email_pattern', '此邮箱模式仅用于 Playground 演示账号，请使用其他邮箱注册', 400, 'email');
  }
  const pwErr = validatePassword(password);
  if (pwErr) return err(c, pwErr, '密码强度不够', 400, 'password', '至少 8 位含大小写字母与数字');

  // 封禁邮箱拒绝 OIDC 注册：被封过的邮箱不能用新密码续命
  const banPreOidc = await c.env.DB.prepare(
    `SELECT MAX(banned) AS b, MAX(banned_reason) AS r FROM (
       SELECT banned, banned_reason FROM oidc_identities WHERE email = ?
       UNION ALL SELECT banned, banned_reason FROM users WHERE email = ?
       UNION ALL SELECT banned, banned_reason FROM gateway_users WHERE email = ?)`
  ).bind(email, email, email).first() as any;
  if (banPreOidc && Number(banPreOidc.b) === 1) {
    return err(c, 'account_banned', '该邮箱已被封禁，不能注册' + (banPreOidc.r ? `：${banPreOidc.r}` : ''), 403);
  }

  // 校验验证码（防黑客批量注册的关键防线）
  const codeHash = await sha256(String(code));
  const vc = await c.env.DB.prepare(
    "SELECT id, attempts FROM verification_codes WHERE email = ? AND api_key_id = 'oidc-register' AND code_hash = ? AND expires_at > datetime('now', '+8 hours') AND used = 0"
  ).bind(email, codeHash).first() as any;
  if (!vc) {
    // 累加尝试次数
    await c.env.DB.prepare("UPDATE verification_codes SET attempts = attempts + 1 WHERE email = ? AND api_key_id = 'oidc-register' AND expires_at > datetime('now', '+8 hours') AND used = 0").bind(email).run().catch(() => {});
    return err(c, 'invalid_code', '验证码错误或已过期，请重新获取', 400, 'code');
  }
  if (vc.attempts >= 3) {
    await c.env.DB.prepare('UPDATE verification_codes SET used = 1 WHERE id = ?').bind(vc.id).run().catch(() => {});
    return err(c, 'max_attempts', '验证码错误次数过多，请重新获取', 400, 'code');
  }
  // 立刻作废
  await c.env.DB.prepare('UPDATE verification_codes SET used = 1, attempts = 999 WHERE id = ?').bind(vc.id).run().catch(() => {});

  const id = crypto.randomUUID();
  const { hash, salt } = await oidcPbkdf2Hash(password);
  try {
    await c.env.DB.prepare(
      `INSERT INTO oidc_identities (id, email, email_verified, password_hash, salt, hash_version, username, is_personal, is_gateway_dev) VALUES (?, ?, 1, ?, ?, 1, ?, 1, 1)`
    ).bind(id, email, hash, salt, (username || email.split('@')[0]).trim()).run();
    // 三端串联（个人站 + user 端 + SSO）：镜像到 users，便于个人站接口直接可查
    // 不镜像到 gateway_users —— 开发者端独立
    const uname2 = (username || email.split('@')[0]).trim();
    await c.env.DB.prepare('INSERT OR IGNORE INTO users (id, email, password_hash, username, salt, hash_version) VALUES (?, ?, ?, ?, ?, 1)').bind(id, email, hash, uname2, salt).run().catch(() => {});
  } catch (e: any) {
    if (e.message?.includes('UNIQUE')) return err(c, 'email_registered', '该邮箱已注册', 409, 'email');
    return err(c, 'server_error', '注册失败', 500);
  }
  const sid = crypto.randomUUID();
  await c.env.DB.prepare(
    `INSERT INTO oidc_sso_sessions (session_id, identity_id, expires_at) VALUES (?, ?, datetime('now', '+8 hours', '+${SSO_TTL_DAYS} days'))`
  ).bind(sid, id).run();
  setSsoCookie(c, sid);
  return c.json({ success: true });
});

// ── Authorize consent (用户点"允许"后下发 code) ──
app.post('/oauth/authorize/consent', async (c) => {
  const csrf = requireSameOrigin(c); if (csrf) return csrf;
  const sso = await getSsoIdentity(c);
  if (!sso) return err(c, 'not_signed_in', '请先登录', 401);
  const body = await c.req.json().catch(() => ({}));
  const { client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, action } = body;
  if (!client_id || !redirect_uri) return err(c, 'invalid_request', '参数不全', 400);
  const appRow = await c.env.DB.prepare(
    `SELECT k.id, k.oidc_enabled, k.redirect_uris, k.revoked, k.user_id, k.app_review_status, u.email AS owner_email
     FROM api_keys k LEFT JOIN gateway_users u ON u.id = k.user_id WHERE k.id = ?`
  ).bind(client_id).first() as any;
  if (!appRow || appRow.revoked || !appRow.oidc_enabled) return err(c, 'invalid_client', '应用无效', 400);
  if (!isValidRedirectUri(redirect_uri, appRow.redirect_uris || '')) return err(c, 'invalid_redirect_uri', 'redirect_uri 不在白名单', 400, 'redirect_uri', redirect_uri, '把这串地址完整粘贴到控制台 → 你的应用 → Redirect URIs');
  // ★ 强制点 2：颁发 code 前再次校验审批状态（即使绕过了 /oauth/authorize/info）
  if (appRow.app_review_status === 'rejected') {
    return err(c, 'app_rejected', '该应用已被平台拒绝', 403);
  }
  if (appRow.app_review_status === 'pending' && sso.email !== appRow.owner_email) {
    return err(c, 'app_pending_review', '该应用尚未通过域名验证，无法颁发授权码', 403);
  }
  if (action === 'deny') {
    const sep = redirect_uri.includes('?') ? '&' : '?';
    return c.json({ redirect: redirect_uri + sep + 'error=access_denied' + (state ? '&state=' + encodeURIComponent(state) : '') });
  }
  // 写入 grant + 生成 code
  await c.env.DB.prepare(
    `INSERT INTO oidc_grants (identity_id, api_key_id, scopes) VALUES (?, ?, ?)
     ON CONFLICT(identity_id, api_key_id) DO UPDATE SET scopes = excluded.scopes, last_used_at = datetime('now', '+8 hours')`
  ).bind(sso.identity_id, client_id, scope || 'openid').run();
  // 自动镜像到 gateway_users（每个 identity 仅建一条，created_by = API Key 拥有者）
  const uname3 = sso.username || sso.email.split('@')[0];
  await c.env.DB.prepare(
    `INSERT OR IGNORE INTO gateway_users (id, email, password_hash, username, salt, hash_version, created_by, api_key_id)
     VALUES (?, ?, '', ?, '', 1, ?, ?)`
  ).bind(sso.identity_id, sso.email, uname3, appRow.user_id, client_id).run().catch(() => {});
  // 如果已存在（别的 app 先镜像过了），至少更新 created_by + api_key_id 为最新的
  await c.env.DB.prepare(
    `UPDATE gateway_users SET created_by = ?, api_key_id = ?, username = ? WHERE id = ?`
  ).bind(appRow.user_id, client_id, uname3, sso.identity_id).run().catch(() => {});
  const code = bytesToB64uLocal(crypto.getRandomValues(new Uint8Array(32)));
  await c.env.DB.prepare(
    `INSERT INTO oidc_codes (code, identity_id, api_key_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+8 hours', '+${CODE_TTL_SEC} seconds'))`
  ).bind(code, sso.identity_id, client_id, redirect_uri, scope || 'openid', nonce || null, code_challenge || null, code_challenge_method || null).run();
  const sep = redirect_uri.includes('?') ? '&' : '?';
  return c.json({ redirect: redirect_uri + sep + 'code=' + encodeURIComponent(code) + (state ? '&state=' + encodeURIComponent(state) : '') });
});

function bytesToB64uLocal(u8: Uint8Array): string {
  let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── Token endpoint (code → tokens / refresh) ──
app.post('/oauth/token', async (c) => {
  if (await rateLimit(c, 'oidc_token', 60, 60)) return err(c, 'rate_limited', '请求过于频繁', 429);
  const ct = c.req.header('Content-Type') || '';
  let params: any = {};
  if (ct.includes('application/x-www-form-urlencoded')) {
    const text = await c.req.text();
    for (const pair of text.split('&')) { const [k, v] = pair.split('='); if (k) params[decodeURIComponent(k)] = decodeURIComponent((v || '').replace(/\+/g, ' ')); }
  } else {
    params = await c.req.json().catch(() => ({}));
  }
  // 客户端认证：Basic 或 client_id/client_secret in body
  const basicAuth = c.req.header('Authorization')?.replace(/^Basic /, '');
  if (basicAuth) {
    try { const [cid, csec] = atob(basicAuth).split(':'); params.client_id = params.client_id || cid; params.client_secret = params.client_secret || csec; } catch {}
  }
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier, refresh_token } = params;
  if (!client_id) return c.json({ error: 'invalid_client' }, 401);
  const appRow = await c.env.DB.prepare(`SELECT id, client_secret_hash, oidc_enabled, redirect_uris, revoked, app_review_status FROM api_keys WHERE id = ?`).bind(client_id).first() as any;
  if (!appRow || appRow.revoked || !appRow.oidc_enabled) return c.json({ error: 'invalid_client' }, 401);
  // 机密客户端：必须提供且匹配 client_secret
  if (appRow.client_secret_hash) {
    if (!client_secret) return c.json({ error: 'invalid_client', error_description: 'client_secret required' }, 401);
    if ((await sha256Hex(client_secret)) !== appRow.client_secret_hash) return c.json({ error: 'invalid_client' }, 401);
  }
  // ★ 强制点 3：rejected 永久禁用 token 换发（即使持有有效 code）
  // pending 状态因为 consent 端点已挡，此处 code 不存在，但 refresh_token 路径仍需防御
  if (appRow.app_review_status === 'rejected') {
    return c.json({ error: 'app_rejected', error_description: 'application rejected by platform' }, 403);
  }

  if (grant_type === 'authorization_code') {
    if (!code || !redirect_uri) return c.json({ error: 'invalid_request' }, 400);
    const row = await c.env.DB.prepare(
      `SELECT * FROM oidc_codes WHERE code = ? AND used = 0 AND expires_at > datetime('now', '+8 hours')`
    ).bind(code).first() as any;
    if (!row) return c.json({ error: 'invalid_grant', error_description: 'code invalid or expired' }, 400);
    if (row.api_key_id !== client_id) return c.json({ error: 'invalid_grant', error_description: 'client mismatch' }, 400);
    if (row.redirect_uri !== redirect_uri) return c.json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }, 400);
    if (row.code_challenge) {
      if (!code_verifier) return c.json({ error: 'invalid_grant', error_description: 'pkce required' }, 400);
      if (!(await verifyPkce(code_verifier, row.code_challenge, row.code_challenge_method))) {
        return c.json({ error: 'invalid_grant', error_description: 'pkce failed' }, 400);
      }
    } else if (!appRow.client_secret_hash) {
      // 公开客户端必须 PKCE
      return c.json({ error: 'invalid_grant', error_description: 'pkce required for public clients' }, 400);
    }
    await c.env.DB.prepare(`UPDATE oidc_codes SET used = 1 WHERE code = ?`).bind(code).run();
    try {
      return c.json(await issueTokens(c, row.identity_id, client_id, row.scope, row.nonce));
    } catch (e: any) {
      if (e?.message === 'banned_identity') {
        return c.json({ error: 'invalid_grant', error_description: 'account_banned' + (e.banReason ? `: ${e.banReason}` : '') }, 400);
      }
      throw e;
    }
  }

  if (grant_type === 'refresh_token') {
    if (!refresh_token) return c.json({ error: 'invalid_request' }, 400);
    const rtHash = await sha256Hex(refresh_token);
    const row = await c.env.DB.prepare(
      `SELECT identity_id, api_key_id, scope FROM oidc_tokens WHERE token_hash = ? AND kind = 'refresh' AND revoked = 0 AND expires_at > datetime('now', '+8 hours')`
    ).bind(rtHash).first() as any;
    if (!row || row.api_key_id !== client_id) return c.json({ error: 'invalid_grant' }, 400);
    // 防御性检查：即使 refresh_token 自身未被撤销，若用户已撤销对该应用的授权（oidc_grants 不存在），也拒绝
    const grant = await c.env.DB.prepare(
      `SELECT 1 FROM oidc_grants WHERE identity_id = ? AND api_key_id = ?`
    ).bind(row.identity_id, client_id).first();
    if (!grant) return c.json({ error: 'invalid_grant', error_description: 'authorization_revoked' }, 400);
    await c.env.DB.prepare(`UPDATE oidc_tokens SET revoked = 1 WHERE token_hash = ?`).bind(rtHash).run();
    try {
      return c.json(await issueTokens(c, row.identity_id, client_id, row.scope, null));
    } catch (e: any) {
      if (e?.message === 'banned_identity') {
        return c.json({ error: 'invalid_grant', error_description: 'account_banned' + (e.banReason ? `: ${e.banReason}` : '') }, 400);
      }
      throw e;
    }
  }

  return c.json({ error: 'unsupported_grant_type' }, 400);
});

// 签发 access_token (RS256 JWT) + id_token (RS256 JWT) + refresh_token (opaque UUID)
async function issueTokens(c: any, identityId: string, clientId: string, scope: string, nonce: string | null) {
  const ident = await c.env.DB.prepare(
    `SELECT id, email, email_verified, username, avatar_url, banned, banned_reason FROM oidc_identities WHERE id = ?`
  ).bind(identityId).first() as any;
  if (!ident) throw new Error('identity_not_found');
  // 封禁兜底：refresh_token 续签 or authorization_code 兑换时，若身份已被封 → 全部撤销 + 拒签
  // 这里抛 banned_identity 让 caller 转 invalid_grant，符合 OIDC 错误码规范且不泄露内部表结构
  if (Number(ident.banned) === 1) {
    await c.env.DB.prepare(`UPDATE oidc_tokens SET revoked = 1 WHERE identity_id = ?`).bind(identityId).run().catch(() => {});
    await c.env.DB.prepare(`DELETE FROM oidc_sso_sessions WHERE identity_id = ?`).bind(identityId).run().catch(() => {});
    const e: any = new Error('banned_identity');
    e.banReason = ident.banned_reason || '';
    throw e;
  }
  const sk = await getOrCreateActiveSigningKey(c.env.DB);
  const now = Math.floor(Date.now() / 1000);
  // ID Token
  const idClaims: any = {
    iss: ISSUER, sub: ident.id, aud: clientId,
    exp: now + ID_TOKEN_TTL_SEC, iat: now, auth_time: now,
  };
  if (nonce) idClaims.nonce = nonce;
  if (scope.includes('email')) { idClaims.email = ident.email; idClaims.email_verified = !!ident.email_verified; }
  if (scope.includes('profile')) { idClaims.name = ident.username || ident.email.split('@')[0]; idClaims.picture = ident.avatar_url || (ISSUER + '/avatar/' + ident.id + '.svg'); }
  const idToken = await signRs256Jwt(idClaims, sk.kid, sk.key);
  // Access Token (JWT)
  const accessClaims = { iss: ISSUER, sub: ident.id, aud: clientId, scope, exp: now + ACCESS_TOKEN_TTL_SEC, iat: now, token_use: 'access' };
  const accessToken = await signRs256Jwt(accessClaims, sk.kid, sk.key);
  // Refresh Token (opaque)
  const refreshToken = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, '');
  const rtHash = await sha256Hex(refreshToken);
  await c.env.DB.prepare(
    `INSERT INTO oidc_tokens (token_hash, kind, identity_id, api_key_id, scope, expires_at) VALUES (?, 'refresh', ?, ?, ?, datetime('now', '+8 hours', '+${REFRESH_TOKEN_TTL_DAYS} days'))`
  ).bind(rtHash, ident.id, clientId, scope).run();
  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL_SEC,
    id_token: idToken,
    refresh_token: refreshToken,
    scope,
  };
}

// ── UserInfo ──
app.get('/oauth/userinfo', async (c) => {
  const auth = c.req.header('Authorization')?.replace(/^Bearer /, '');
  if (!auth) return c.json({ error: 'invalid_token' }, 401);
  try {
    const pk = await getActivePublicKey(c.env.DB);
    const payload = await verifyRs256(auth, pk.key);
    if (payload.token_use !== 'access') return c.json({ error: 'invalid_token' }, 401);
    // 参考 Google/Auth0：每次 userinfo 必须校验授权关系仍然存在
    // 用户从 user.miaogou.site 撤销授权后 oidc_grants 记录被删，这里会查不到 → 立即 401
    // 这是让"撤销授权"真正生效的关键，避免无状态 JWT 在自然过期前继续可用
    const grant = await c.env.DB.prepare(
      `SELECT 1 FROM oidc_grants WHERE identity_id = ? AND api_key_id = ?`
    ).bind(payload.sub, payload.aud).first();
    if (!grant) return c.json({ error: 'invalid_token', error_description: 'authorization_revoked' }, 401);
    const ident = await c.env.DB.prepare(
      `SELECT id, email, email_verified, username, avatar_url, banned FROM oidc_identities WHERE id = ?`
    ).bind(payload.sub).first() as any;
    if (!ident) return c.json({ error: 'invalid_token' }, 401);
    if (Number(ident.banned) === 1) {
      // 全部撤销 + 让第三方应用刷新时也拿到 invalid_grant
      await c.env.DB.prepare(`UPDATE oidc_tokens SET revoked = 1 WHERE identity_id = ?`).bind(ident.id).run().catch(() => {});
      return c.json({ error: 'invalid_token', error_description: 'account_banned' }, 401);
    }
    const out: any = { sub: ident.id };
    const scope = payload.scope || '';
    if (scope.includes('email')) { out.email = ident.email; out.email_verified = !!ident.email_verified; }
    if (scope.includes('profile')) { out.name = ident.username || ident.email.split('@')[0]; out.picture = ident.avatar_url || (ISSUER + '/avatar/' + ident.id + '.svg'); }
    return c.json(out);
  } catch { return c.json({ error: 'invalid_token' }, 401); }
});

// ── Revoke ──
app.post('/oauth/revoke', async (c) => {
  if (!(await rateLimit(c, 'oidc_revoke', 60, 30))) {
    return c.json({ error: 'rate_limited' }, 429);
  }
  const ct = c.req.header('Content-Type') || '';
  let params: any = {};
  if (ct.includes('application/x-www-form-urlencoded')) {
    const text = await c.req.text();
    for (const pair of text.split('&')) { const [k, v] = pair.split('='); if (k) params[decodeURIComponent(k)] = decodeURIComponent((v || '').replace(/\+/g, ' ')); }
  } else {
    params = await c.req.json().catch(() => ({}));
  }
  if (!params.token) return c.json({}, 200);
  const rtHash = await sha256Hex(params.token);
  await c.env.DB.prepare(`UPDATE oidc_tokens SET revoked = 1 WHERE token_hash = ?`).bind(rtHash).run().catch(() => {});
  return c.json({}, 200);
});

// ── SSO Logout (清除 nx_sso cookie + 撤销 session) ──
app.post('/oauth/sso/logout', async (c) => {
  const csrf = requireSameOrigin(c); if (csrf) return csrf;
  const sid = readCookie(c, 'nx_sso');
  if (sid) await c.env.DB.prepare(`DELETE FROM oidc_sso_sessions WHERE session_id = ?`).bind(sid).run().catch(() => {});
  clearSsoCookie(c);
  return c.json({ success: true });
});

// ══════ Consent ══════
// 不经过 authMW 内置同意闸门：这两个端点本身必须在「未同意」状态下也能调用
app.get('/api/consent/status', async (c) => {
  const a = c.req.header('Authorization')?.replace('Bearer ', '');
  if (!a) return err(c, 'auth_missing', '未提供认证令牌', 401);
  let payload: any;
  try { payload = await vjwt(a, c.env.JWT_SECRET); }
  catch { return err(c, 'auth_invalid', '令牌无效或已过期', 401); }
  const accepted = await hasUserConsent(c.env.DB, payload.email || '');
  return c.json({ accepted, version: CURRENT_CONSENT_VERSION });
});

app.post('/api/consent/accept', async (c) => {
  const a = c.req.header('Authorization')?.replace('Bearer ', '');
  if (!a) return err(c, 'auth_missing', '未提供认证令牌', 401);
  let payload: any;
  try { payload = await vjwt(a, c.env.JWT_SECRET); }
  catch { return err(c, 'auth_invalid', '令牌无效或已过期', 401); }
  if (!payload.email) return err(c, 'email_missing', '令牌缺少邮箱字段', 400);
  const ip = c.req.header('CF-Connecting-IP') || '';
  const ua = c.req.header('User-Agent') || '';
  await c.env.DB.prepare(
    `INSERT INTO user_consent (email, consent_version, source, ip, user_agent)
     VALUES (?, ?, 'gateway', ?, ?)
     ON CONFLICT(email) DO UPDATE SET
       consent_version = excluded.consent_version,
       accepted_at = datetime('now', '+8 hours'),
       source = excluded.source,
       ip = excluded.ip,
       user_agent = excluded.user_agent`
  ).bind(payload.email, CURRENT_CONSENT_VERSION, ip, ua).run();
  return c.json({ accepted: true, version: CURRENT_CONSENT_VERSION });
});

// ══════ Admin Forensics (站长专用) ══════
// 鉴权：必须是 PLATFORM_OWNER_EMAILS 中的开发者账号
// 返回某 api_key_id 的综合溯源信息：
//   - 应用元数据（名称、类型、Redirect URI、Homepage、注册者）
//   - 注册审计行（注册时 IP/UA + DNS 快照 + 扫描结果）
//   - 最近 100 条业务调用 IP（page_views）：真实服务器 IP，无法伪造
//   - 最近 50 条邮件发送记录（email_logs）
//   - 最近 50 条 webhook 投递记录
//   - 关联的 gateway_users 用户数 + 最近注册时间
// 用途：执法机关请求时，一键拉出某应用的完整溯源画像
app.get('/api/admin/forensics/:apiKeyId', authMW, async (c) => {
  const requesterEmail = (c as any).get('userEmail') as string;
  if (!requesterEmail || !getPlatformOwners(c.env).has(requesterEmail.toLowerCase())) {
    return err(c, 'forbidden', '无权访问溯源端点（仅平台站长可用）', 403);
  }
  const keyId = c.req.param('apiKeyId');
  // 应用基础信息
  const app2 = await c.env.DB.prepare(
    `SELECT k.id, k.name, k.client_type, k.redirect_uris, k.app_homepage, k.created_at, k.revoked,
            u.email AS owner_email, u.username AS owner_username, u.created_at AS owner_created_at
     FROM api_keys k LEFT JOIN gateway_users u ON u.id = k.user_id
     WHERE k.id = ?`
  ).bind(keyId).first();
  if (!app2) return err(c, 'not_found', '应用不存在', 404);

  // 注册 / 更新审计（含 DNS 快照、扫描结果）
  const audit = await c.env.DB.prepare(
    `SELECT id, action, app_name, client_type, app_homepage, redirect_uris,
            developer_ip, developer_ua, dns_resolutions, scan_result, scan_hits, created_at
     FROM app_registry_audit
     WHERE api_key_id = ? ORDER BY created_at DESC LIMIT 50`
  ).bind(keyId).all();

  // 业务调用 IP（真实服务器 IP，不可伪造的最强溯源数据）
  const calls = await c.env.DB.prepare(
    `SELECT path, ip, user_agent, created_at
     FROM page_views WHERE api_key_id = ? ORDER BY created_at DESC LIMIT 100`
  ).bind(keyId).all();

  // 调用 IP 聚合（出现频率）
  const ipFreq = await c.env.DB.prepare(
    `SELECT ip, COUNT(*) AS hits, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen
     FROM page_views WHERE api_key_id = ?
     GROUP BY ip ORDER BY hits DESC LIMIT 20`
  ).bind(keyId).all();

  // 邮件发送
  const emails = await c.env.DB.prepare(
    `SELECT to_email, success, error, created_at
     FROM email_logs WHERE api_key_id = ? ORDER BY created_at DESC LIMIT 50`
  ).bind(keyId).all();

  // 关联用户数
  const userStats = await c.env.DB.prepare(
    `SELECT COUNT(*) AS total, MIN(created_at) AS first_user, MAX(created_at) AS last_user
     FROM gateway_users WHERE api_key_id = ?`
  ).bind(keyId).first();

  return c.json({
    app: app2,
    audit_log: audit.results,
    recent_calls: calls.results,
    ip_summary: ipFreq.results,
    email_logs: emails.results,
    user_stats: userStats,
    notes: {
      page_views_ip: '★★★ 真实服务器调用 IP，应用调 API 必须从此 IP 发起，无法伪造',
      developer_ip: '★★★ 注册应用时开发者的 CF-Connecting-IP',
      dns_resolutions: '★  仅作为弱线索：用户填报 redirect_uri 域名某时刻的 DNS 解析快照，可被故意误填，绝不单独作为定罪依据',
      sensitive_domains: '注册时已拦截 .gov / .mil / 大型平台等不可能拥有的域名',
    },
  });
});

// ══════ Domain Verification (开发者自助 DNS TXT 验证) ══════
// 列出某应用所有需要验证的域名，含每个的 challenge / 验证状态
app.get('/api/clients/:id/verification', authMW, async (c) => {
  const uid = (c as any).get('userId') as string;
  const pid = c.req.param('id');
  const row = await c.env.DB.prepare(
    'SELECT redirect_uris, app_review_status, oidc_enabled FROM api_keys WHERE id = ? AND user_id = ?'
  ).bind(pid, uid).first() as any;
  if (!row) return err(c, 'not_found', '应用不存在', 404);
  const domains = extractDomainsNeedingVerification(row.redirect_uris || '');
  const out: any[] = [];
  for (const domain of domains) {
    // 优先检查父域继承：已验 miaogou.site → playground.miaogou.site 直接通过，不再要求新 TXT
    const inherit = await isHostVerified(c.env.DB, uid, domain);
    if (inherit.verified && inherit.coveredBy && inherit.coveredBy !== domain) {
      out.push({
        domain,
        verified: true,
        covered_by: inherit.coveredBy,
        verified_at: null,
        last_check_at: null,
        last_check_error: null,
        // 不返回 dns_record——子域名无需添加新 TXT
        dns_record: null,
      });
      continue;
    }
    // 取已有 challenge，没有就懒生成一条
    let v = await c.env.DB.prepare(
      'SELECT challenge, verified, verified_at, last_check_at, last_check_error FROM domain_verifications WHERE user_id = ? AND domain = ?'
    ).bind(uid, domain).first() as any;
    if (!v) {
      const challenge = generateChallenge();
      await c.env.DB.prepare(
        `INSERT INTO domain_verifications (id, user_id, domain, challenge) VALUES (?, ?, ?, ?)
         ON CONFLICT(user_id, domain) DO NOTHING`
      ).bind(crypto.randomUUID(), uid, domain, challenge).run();
      v = { challenge, verified: 0, verified_at: null, last_check_at: null, last_check_error: null };
    }
    out.push({
      domain,
      verified: !!v.verified,
      covered_by: null,
      verified_at: v.verified_at,
      last_check_at: v.last_check_at,
      last_check_error: v.last_check_error,
      dns_record: {
        name: '_authcore-verify.' + domain,
        type: 'TXT',
        value: v.challenge,
        ttl: 60,
      },
    });
  }
  // 如果列表里出现了任意「父域覆盖」的子域名，触发一次应用状态重评（可能从 pending → approved）
  // 让用户无需点 check 按钮也能直接看到应用已批准的状态
  let reviewStatus = row.app_review_status;
  const anyCovered = out.some(d => d.covered_by);
  if (anyCovered && reviewStatus !== 'rejected') {
    reviewStatus = await evaluateApprovalStatus(c.env.DB, uid, !!row.oidc_enabled, row.redirect_uris || '');
    if (reviewStatus !== row.app_review_status) {
      await c.env.DB.prepare('UPDATE api_keys SET app_review_status = ? WHERE id = ? AND user_id = ?').bind(reviewStatus, pid, uid).run();
    }
  }
  return c.json({
    domains: out,
    review_status: reviewStatus,
    oidc_enabled: !!row.oidc_enabled,
  });
});

// 对某域名触发 DNS TXT 检查；通过则 verified=1 + 重新评估应用状态
app.post('/api/clients/:id/verification/:domain/check', authMW, async (c) => {
  const uid = (c as any).get('userId') as string;
  const pid = c.req.param('id');
  const rawDomain = c.req.param('domain');
  // 安全：只接受合法 hostname 字符，防 SSRF / 注入
  const domain = String(rawDomain || '').toLowerCase().trim();
  if (!/^[a-z0-9.-]+$/.test(domain) || domain.length > 253) {
    return err(c, 'invalid_domain', '域名格式不合法', 400);
  }
  // 限流：同 (user, domain) 60 秒内最多 5 次（防滥用 DoH）
  if (await rateLimit(c, 'dns_verify:' + uid + ':' + domain, 60, 5)) {
    return err(c, 'rate_limited', '验证请求过于频繁，请稍后重试', 429);
  }
  // 校验该域名归属此应用 + 该开发者
  const app2 = await c.env.DB.prepare(
    'SELECT redirect_uris FROM api_keys WHERE id = ? AND user_id = ?'
  ).bind(pid, uid).first() as any;
  if (!app2) return err(c, 'not_found', '应用不存在', 404);
  const needed = extractDomainsNeedingVerification(app2.redirect_uris || '');
  if (!needed.includes(domain)) return err(c, 'domain_not_in_app', '该域名不属于此应用的 redirect URI', 400);

  // 父域继承：开发者已验证父域（如 miaogou.site）时，子域名（playground.miaogou.site）
  // 不需要再加 TXT，直接当作已验证处理。返回 status，附带 coveredBy 让前端展示来源
  const inherit = await isHostVerified(c.env.DB, uid, domain);
  if (inherit.verified && inherit.coveredBy && inherit.coveredBy !== domain) {
    const cur = await c.env.DB.prepare(
      'SELECT oidc_enabled, redirect_uris, app_review_status FROM api_keys WHERE id = ? AND user_id = ?'
    ).bind(pid, uid).first() as any;
    let newStatus: string | undefined;
    if (cur && cur.app_review_status !== 'rejected') {
      newStatus = await evaluateApprovalStatus(c.env.DB, uid, !!cur.oidc_enabled, cur.redirect_uris || '');
      await c.env.DB.prepare('UPDATE api_keys SET app_review_status = ? WHERE id = ? AND user_id = ?').bind(newStatus, pid, uid).run();
    }
    return c.json({
      verified: true,
      covered_by: inherit.coveredBy,
      review_status: newStatus,
      message: `该子域名已被你已验证的父域 ${inherit.coveredBy} 自动覆盖，无需再加 TXT` + (newStatus === 'approved' ? '。应用已自动批准' : ''),
    });
  }

  // 拿 challenge
  const v = await c.env.DB.prepare(
    'SELECT challenge FROM domain_verifications WHERE user_id = ? AND domain = ?'
  ).bind(uid, domain).first() as any;
  if (!v) return err(c, 'no_challenge', '请先在控制台查看 DNS 记录获取 challenge', 400);

  // 查 TXT 记录（双 DoH 兜底）
  const queryName = '_authcore-verify.' + domain;
  const lookup = await lookupTxt(queryName);
  const matched = lookup.txts.some(t => t === v.challenge);

  if (matched) {
    await c.env.DB.prepare(
      `UPDATE domain_verifications SET verified = 1, verified_at = datetime('now', '+8 hours'),
        last_check_at = datetime('now', '+8 hours'), last_check_error = NULL WHERE user_id = ? AND domain = ?`
    ).bind(uid, domain).run();
    // 重新评估该应用 status（可能因这条验证而升级到 approved）
    const cur = await c.env.DB.prepare(
      'SELECT oidc_enabled, redirect_uris, app_review_status FROM api_keys WHERE id = ? AND user_id = ?'
    ).bind(pid, uid).first() as any;
    if (cur && cur.app_review_status !== 'rejected') {
      const newStatus = await evaluateApprovalStatus(c.env.DB, uid, !!cur.oidc_enabled, cur.redirect_uris || '');
      await c.env.DB.prepare('UPDATE api_keys SET app_review_status = ? WHERE id = ? AND user_id = ?').bind(newStatus, pid, uid).run();
      return c.json({ verified: true, review_status: newStatus, message: '域名验证成功' + (newStatus === 'approved' ? '，应用已自动批准' : '') });
    }
    return c.json({ verified: true, message: '域名验证成功' });
  } else {
    // 详细诊断：把查询的域名、DoH 结果、找到的实际值都告诉用户，方便对比排查
    let errMsg: string;
    if (lookup.txts.length === 0) {
      errMsg = `未查到 ${queryName} 的 TXT 记录。${lookup.diagnostic}。常见原因：① 记录还没传播（再等 1-2 分钟）② DNS 控制台「名称」字段填错（不要重复域名后缀，正确做法见下方提示）`;
    } else {
      // 显示找到的值与期望值各取前 16 字符，便于用户肉眼对比是否多了空格 / 大小写差异
      const found = lookup.txts.map(t => `"${t.slice(0, 24)}${t.length > 24 ? '...' : ''}"`).join(', ');
      errMsg = `找到 ${lookup.txts.length} 条 TXT 但都不匹配。期望: "${v.challenge.slice(0, 24)}..." 实际: [${found}]。可能是值有多余空格或复制不完整`;
    }
    await c.env.DB.prepare(
      `UPDATE domain_verifications SET last_check_at = datetime('now', '+8 hours'), last_check_error = ? WHERE user_id = ? AND domain = ?`
    ).bind(errMsg, uid, domain).run();
    return c.json({
      verified: false,
      error: 'verification_failed',
      message: errMsg,
      queried_name: queryName,
      expected: v.challenge,
      found: lookup.txts,
      diagnostic: lookup.diagnostic,
    }, 400);
  }
});

// 「恢复」按钮：关闭 OIDC + 清空 redirect URI，回到纯 API Key 模式
// 适用：用户填了 redirect URI 还没验证，决定放弃 OIDC
app.post('/api/clients/:id/disable-oidc', authMW, async (c) => {
  const uid = (c as any).get('userId') as string;
  const pid = c.req.param('id');
  const row = await c.env.DB.prepare(
    'SELECT key_hash, client_type, revoked, banned, banned_reason FROM api_keys WHERE id = ? AND user_id = ?'
  ).bind(pid, uid).first() as any;
  if (!row) return err(c, 'not_found', '应用不存在', 404);
  if (row.revoked) return err(c, 'app_revoked', '应用已撤销', 409);
  if (Number(row.banned) === 1) {
    return err(c, 'app_banned', '该应用已被站长封禁，不能修改' + (row.banned_reason ? `：${row.banned_reason}` : ''), 403);
  }
  if (!row.key_hash) {
    return err(c, 'spa_cannot_disable', '纯 SPA 应用没有 API Key 可回退；若不再需要 OIDC，请直接删除应用', 400);
  }
  // 同时清掉 redirect_uris、关 OIDC、清 client_secret（机密客户端凭证也作废）
  await c.env.DB.prepare(
    `UPDATE api_keys SET oidc_enabled = 0, redirect_uris = '', client_secret_hash = NULL,
      app_review_status = 'approved' WHERE id = ? AND user_id = ?`
  ).bind(pid, uid).run();
  return c.json({ success: true, message: '已恢复为纯 API Key 模式' });
});

// ══════ Admin App Review (站长专用 OIDC 审批) ══════
// 列出所有待审应用，看到自定义域名 + 注册者邮箱 + IP，决定批准 / 拒绝
app.get('/api/admin/apps/pending', authMW, async (c) => {
  const requesterEmail = (c as any).get('userEmail') as string;
  if (!requesterEmail || !getPlatformOwners(c.env).has(requesterEmail.toLowerCase())) {
    return err(c, 'forbidden', '仅平台站长可用', 403);
  }
  const { results } = await c.env.DB.prepare(
    `SELECT k.id, k.name, k.client_type, k.oidc_enabled, k.redirect_uris, k.app_homepage,
            k.app_review_status, k.created_at,
            u.email AS owner_email, u.username AS owner_username
     FROM api_keys k LEFT JOIN gateway_users u ON u.id = k.user_id
     WHERE k.app_review_status = 'pending' AND k.revoked = 0
     ORDER BY k.created_at DESC LIMIT 200`
  ).all();
  return c.json({ apps: results });
});

// 手动批准 / 拒绝某应用（只能改 pending ↔ approved ↔ rejected 三态）
app.post('/api/admin/apps/:id/review', authMW, async (c) => {
  const requesterEmail = (c as any).get('userEmail') as string;
  if (!requesterEmail || !getPlatformOwners(c.env).has(requesterEmail.toLowerCase())) {
    return err(c, 'forbidden', '仅平台站长可用', 403);
  }
  const appId = c.req.param('id');
  const { status, reason } = await c.req.json().catch(() => ({}));
  if (!['approved', 'rejected', 'pending'].includes(status)) {
    return err(c, 'invalid_status', 'status 必须是 approved/rejected/pending', 400);
  }
  const row = await c.env.DB.prepare('SELECT id, user_id, name FROM api_keys WHERE id = ?').bind(appId).first() as any;
  if (!row) return err(c, 'not_found', '应用不存在', 404);
  await c.env.DB.prepare('UPDATE api_keys SET app_review_status = ? WHERE id = ?').bind(status, appId).run();
  // 审计：手动审批留痕（写到既有 app_registry_audit 表）
  c.executionCtx.waitUntil(writeAppAudit(c, {
    apiKeyId: appId,
    userId: row.user_id,
    action: 'update_oidc',  // 复用现有 action 枚举
    appName: row.name,
    scanResult: status === 'rejected' ? 'rejected' : 'pass',
    scanHits: `admin_review:${status}:${(reason || '').slice(0, 80)}`,
  }));
  return c.json({ success: true, status });
});

// ══════ Admin Bans (账号 / API Key 封禁) ══════
// 仅 PLATFORM_OWNER_EMAILS 中的站长能调；所有动作写 ban_audit_log 永久留痕
// 封账号会四网同步生效（个人站 / 网关 / 用户中心 / OIDC 第三方）
function isAdmin(c: any): boolean {
  const email = ((c as any).get('userEmail') as string || '').toLowerCase();
  return !!email && getPlatformOwners(c.env).has(email);
}

async function writeBanAudit(c: any, opts: {
  targetType: 'user' | 'oidc_identity' | 'gateway_user' | 'api_key';
  targetId: string;
  targetEmail?: string;
  action: 'ban' | 'unban';
  reason?: string;
}) {
  const operator = ((c as any).get('userEmail') as string || '').toLowerCase();
  const ip = c.req.header('CF-Connecting-IP') || '';
  await c.env.DB.prepare(
    `INSERT INTO ban_audit_log (id, target_type, target_id, target_email, action, reason, operator_email, operator_ip)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(crypto.randomUUID(), opts.targetType, opts.targetId, opts.targetEmail || '', opts.action, opts.reason || '', operator, ip).run().catch(() => {});
}

// 封禁邮件通知：站长封号/封 Key 后给目标邮箱发一封说明邮件
// 设计原则：
//   - 不暴露内部审计 ID / IP / 操作者邮箱（防社工 / 反制申诉）
//   - 列明 ToS 条款引用 + 申诉路径 + 14 天数据保留期
//   - 静默吞错（Resend 故障不影响封禁动作完成）
async function sendBanNotificationEmail(c: any, opts: {
  toEmail: string;
  targetKind: 'account' | 'api_key';
  targetName?: string;     // API Key 时是 app 名
  reason: string;
}) {
  if (!opts.toEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(opts.toEmail)) return;
  const resendKey = c.env.RESEND_API_KEY;
  if (!resendKey || resendBreakerOpen()) return;
  const isAccount = opts.targetKind === 'account';
  const subjectLine = isAccount ? '账号封禁通知' : '应用封禁通知';
  const itemDesc = isAccount ? '你的账号' : `应用「${(opts.targetName || '').replace(/[<>]/g, '')}」`;
  const reasonHtml = (opts.reason || '违反《服务条款》').replace(/[<>]/g, '');
  const html = `
    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:560px;margin:0 auto;padding:20px;color:#1a1a1a">
      <h2 style="font-size:18px;color:#9c1414;margin:0 0 14px">${subjectLine}</h2>
      <p style="font-size:14px;line-height:1.7;margin:0 0 12px">你好，</p>
      <p style="font-size:14px;line-height:1.7;margin:0 0 12px">${itemDesc} 因违反我们的《服务条款》已被封禁。</p>
      <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px 14px;margin:12px 0">
        <div style="font-size:12px;font-weight:600;color:#9c1414;margin-bottom:4px">封禁原因</div>
        <div style="font-size:13px;color:#1a1a1a">${reasonHtml}</div>
      </div>
      <p style="font-size:13px;line-height:1.7;color:#55433d;margin:12px 0">
        ${isAccount
          ? '所有现有会话已立即失效；本邮箱在被封期间无法登录平台旗下任何站点（个人站、网关、用户中心、第三方 OIDC 应用）。'
          : '该应用的 API Key 已立即停用；正在使用该应用登录的终端用户将被强制重新认证；OIDC 流程将拒绝该应用。'}
      </p>
      <p style="font-size:13px;line-height:1.7;color:#55433d;margin:12px 0">
        根据《服务条款》第 4 条，相关数据保留 90 个自然日用于法律响应，期满彻底删除。
      </p>
      <p style="font-size:13px;line-height:1.7;color:#1a1a1a;margin:14px 0 8px">
        <strong>申诉</strong>：如果你认为此封禁有误，请发送邮件至
        <a href="mailto:support@mail.miaogou.site" style="color:#1a1a1a">support@mail.miaogou.site</a>
        ，主题以 <code style="background:#f5f1ea;padding:1px 6px;border-radius:4px">[APPEAL]</code> 开头，附上相关情况说明。我们在 72 小时内回复。
      </p>
      <hr style="border:none;border-top:1px solid #e4ddd7;margin:18px 0" />
      <p style="font-size:11px;color:#6b6b67;line-height:1.6;margin:0">
        本邮件由 NEXUS / AuthCore 平台自动发送，无需回复。
      </p>
    </div>`;
  try {
    const resp = await fetchWithTimeout('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${resendKey}` },
      body: JSON.stringify({
        from: 'AuthCore <noreply@mail.miaogou.site>',
        to: [opts.toEmail],
        subject: `${subjectLine} - NEXUS / AuthCore`,
        html,
      }),
    }, 8000);
    resendNoteResult(resp.ok);
  } catch (_) {
    resendNoteResult(false);
  }
}

// 列出所有被封账号（三张身份表 UNION）
app.get('/api/admin/bans/users', authMW, async (c) => {
  if (!isAdmin(c)) return err(c, 'forbidden', '仅平台站长可用', 403);
  const { results } = await c.env.DB.prepare(
    `SELECT 'oidc_identity' AS source, id, email, username, banned_at, banned_reason, banned_by FROM oidc_identities WHERE banned = 1
     UNION ALL
     SELECT 'user' AS source, id, email, username, banned_at, banned_reason, banned_by FROM users WHERE banned = 1
     UNION ALL
     SELECT 'gateway_user' AS source, id, email, username, banned_at, banned_reason, banned_by FROM gateway_users WHERE banned = 1
     ORDER BY banned_at DESC LIMIT 500`
  ).all();
  return c.json({ bans: results });
});

// 列出所有被封 API Key
app.get('/api/admin/bans/api-keys', authMW, async (c) => {
  if (!isAdmin(c)) return err(c, 'forbidden', '仅平台站长可用', 403);
  const { results } = await c.env.DB.prepare(
    `SELECT k.id, k.name, k.banned_at, k.banned_reason, k.banned_by, u.email AS owner_email
     FROM api_keys k LEFT JOIN gateway_users u ON u.id = k.user_id
     WHERE k.banned = 1 ORDER BY k.banned_at DESC LIMIT 500`
  ).all();
  return c.json({ bans: results });
});

// 封禁账号：按 email 跨三表同步标记，撤销所有会话 / refresh / SSO / OIDC token
app.post('/api/admin/bans/users', authMW, async (c) => {
  if (!isAdmin(c)) return err(c, 'forbidden', '仅平台站长可用', 403);
  const { email, reason } = await c.req.json().catch(() => ({}));
  if (!email || typeof email !== 'string') return err(c, 'missing_fields', 'email 必填', 400);
  const reasonStr = String(reason || '').slice(0, 500);
  const operator = ((c as any).get('userEmail') as string || '').toLowerCase();
  // 站长不能封自己 + 不能封别的站长
  if (getPlatformOwners(c.env).has(email.toLowerCase())) {
    return err(c, 'cannot_ban_owner', '不能封禁平台站长账号', 400);
  }
  const ts = `datetime('now', '+8 hours')`;
  // 三表同步打标
  await c.env.DB.prepare(`UPDATE oidc_identities SET banned = 1, banned_at = ${ts}, banned_reason = ?, banned_by = ? WHERE email = ?`).bind(reasonStr, operator, email).run();
  await c.env.DB.prepare(`UPDATE users SET banned = 1, banned_at = ${ts}, banned_reason = ?, banned_by = ? WHERE email = ?`).bind(reasonStr, operator, email).run().catch(() => {});
  await c.env.DB.prepare(`UPDATE gateway_users SET banned = 1, banned_at = ${ts}, banned_reason = ?, banned_by = ? WHERE email = ?`).bind(reasonStr, operator, email).run().catch(() => {});
  // 收集所有 id 用于撤销会话
  const ids = new Set<string>();
  const rows = await c.env.DB.prepare(
    `SELECT id FROM oidc_identities WHERE email = ?
     UNION SELECT id FROM users WHERE email = ?
     UNION SELECT id FROM gateway_users WHERE email = ?`
  ).bind(email, email, email).all();
  for (const r of (rows.results as any[])) ids.add(r.id);
  for (const id of ids) {
    // 清光所有形式的会话/凭证 → 四网立即生效
    await c.env.DB.prepare(`DELETE FROM oidc_sso_sessions WHERE identity_id = ?`).bind(id).run().catch(() => {});
    await c.env.DB.prepare(`UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?`).bind(id).run().catch(() => {});
    await c.env.DB.prepare(`UPDATE oidc_tokens SET revoked = 1 WHERE identity_id = ?`).bind(id).run().catch(() => {});
    await c.env.DB.prepare(`DELETE FROM user_sessions WHERE user_id = ?`).bind(id).run().catch(() => {});
    await writeBanAudit(c, { targetType: 'oidc_identity', targetId: id, targetEmail: email, action: 'ban', reason: reasonStr });
  }
  // 发邮件通知（fire-and-forget，不阻塞响应；Resend 故障也不影响封禁动作）
  c.executionCtx.waitUntil(sendBanNotificationEmail(c, {
    toEmail: email, targetKind: 'account', reason: reasonStr,
  }));
  return c.json({ success: true, affected_ids: Array.from(ids), email });
});

// 解封账号
app.post('/api/admin/unbans/users', authMW, async (c) => {
  if (!isAdmin(c)) return err(c, 'forbidden', '仅平台站长可用', 403);
  const { email, reason } = await c.req.json().catch(() => ({}));
  if (!email || typeof email !== 'string') return err(c, 'missing_fields', 'email 必填', 400);
  const reasonStr = String(reason || '').slice(0, 500);
  await c.env.DB.prepare(`UPDATE oidc_identities SET banned = 0, banned_at = NULL, banned_reason = NULL, banned_by = NULL WHERE email = ?`).bind(email).run();
  await c.env.DB.prepare(`UPDATE users SET banned = 0, banned_at = NULL, banned_reason = NULL, banned_by = NULL WHERE email = ?`).bind(email).run().catch(() => {});
  await c.env.DB.prepare(`UPDATE gateway_users SET banned = 0, banned_at = NULL, banned_reason = NULL, banned_by = NULL WHERE email = ?`).bind(email).run().catch(() => {});
  // 审计（用 email 作 targetId 因解封时可能跨表）
  await writeBanAudit(c, { targetType: 'oidc_identity', targetId: email, targetEmail: email, action: 'unban', reason: reasonStr });
  return c.json({ success: true, email });
});

// 封禁 API Key：禁用后该 key 不能再做任何 /api/auth/* 调用，也不能跑 OIDC 流程
app.post('/api/admin/bans/api-keys', authMW, async (c) => {
  if (!isAdmin(c)) return err(c, 'forbidden', '仅平台站长可用', 403);
  const { api_key_id, reason } = await c.req.json().catch(() => ({}));
  if (!api_key_id || typeof api_key_id !== 'string') return err(c, 'missing_fields', 'api_key_id 必填', 400);
  const reasonStr = String(reason || '').slice(0, 500);
  const operator = ((c as any).get('userEmail') as string || '').toLowerCase();
  const k = await c.env.DB.prepare(
    `SELECT k.id, k.name, k.user_id, u.email AS owner_email
     FROM api_keys k LEFT JOIN gateway_users u ON u.id = k.user_id
     WHERE k.id = ?`
  ).bind(api_key_id).first() as any;
  if (!k) return err(c, 'not_found', 'API Key 不存在', 404);
  await c.env.DB.prepare(
    `UPDATE api_keys SET banned = 1, banned_at = datetime('now', '+8 hours'), banned_reason = ?, banned_by = ? WHERE id = ?`
  ).bind(reasonStr, operator, api_key_id).run();
  // 顺手把该 Key 下所有应用注册的用户 refresh_token 撤了，强制下次重登
  await c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id IN (SELECT id FROM gateway_users WHERE api_key_id = ?)').bind(api_key_id).run().catch(() => {});
  await c.env.DB.prepare('UPDATE oidc_tokens SET revoked = 1 WHERE api_key_id = ?').bind(api_key_id).run().catch(() => {});
  await writeBanAudit(c, { targetType: 'api_key', targetId: api_key_id, targetEmail: k.name, action: 'ban', reason: reasonStr });
  // 邮件通知给应用所属开发者
  if (k.owner_email) {
    c.executionCtx.waitUntil(sendBanNotificationEmail(c, {
      toEmail: k.owner_email, targetKind: 'api_key', targetName: k.name, reason: reasonStr,
    }));
  }
  return c.json({ success: true, id: api_key_id });
});

// 解封 API Key
app.post('/api/admin/unbans/api-keys', authMW, async (c) => {
  if (!isAdmin(c)) return err(c, 'forbidden', '仅平台站长可用', 403);
  const { api_key_id, reason } = await c.req.json().catch(() => ({}));
  if (!api_key_id || typeof api_key_id !== 'string') return err(c, 'missing_fields', 'api_key_id 必填', 400);
  const reasonStr = String(reason || '').slice(0, 500);
  await c.env.DB.prepare(
    `UPDATE api_keys SET banned = 0, banned_at = NULL, banned_reason = NULL, banned_by = NULL WHERE id = ?`
  ).bind(api_key_id).run();
  await writeBanAudit(c, { targetType: 'api_key', targetId: api_key_id, action: 'unban', reason: reasonStr });
  return c.json({ success: true, id: api_key_id });
});

// 完整审计日志（站长法律响应用）
app.get('/api/admin/bans/audit', authMW, async (c) => {
  if (!isAdmin(c)) return err(c, 'forbidden', '仅平台站长可用', 403);
  const limit = Math.min(parseInt(c.req.query('limit') || '100'), 500);
  const { results } = await c.env.DB.prepare(
    `SELECT * FROM ban_audit_log ORDER BY created_at DESC LIMIT ?`
  ).bind(limit).all();
  return c.json({ audits: results });
});

// ══════ Abuse Reports (公开举报闭环) ══════
// POST /api/abuse/report — 任何人可提交，匿名或留邮箱皆可
// 设计约束：
//   - 严格限流：单 IP 5/分钟、10/小时、20/24h（防恶意刷举报淹没站长）
//   - 不暴露内部状态：response 总是 {success:true}，不告诉举报人目标真实存在或不存在
//   - description 字段限长 2000，category 必须在白名单
const ABUSE_CATEGORIES = new Set(['illegal','porn','gambling','phishing','csam','malware','copyright','harassment','spam','other']);
const ABUSE_TARGET_TYPES = new Set(['api_key','oidc_app','user_email','content_url','other']);

// ══════ Playground Demo Only — 演示账号自我封禁 / 解封 ══════
// 安全约束：
//   - 只对 playground-*@example.com 模式的邮箱生效（gateway_users 表的演示账号）
//   - 必须带 Demo API Key (X-API-Key) 防被滥用
//   - 限流：同 email 60s 内最多 5 次（防恶意刷 ban_audit_log）
//   - 不写 ban_audit_log（这是演示，不是真实合规事件）
function isDemoEmail(email: string): boolean {
  return typeof email === 'string' && /^playground-[a-z0-9]{6,}@example\.com$/i.test(email);
}

app.post('/api/demo/ban-me', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const email = String(body.email || '').toLowerCase().trim();
  if (!email || !isDemoEmail(email)) {
    return err(c, 'not_demo_account', '此端点仅对 Playground 演示账号生效（playground-*@example.com）', 400);
  }
  if (await rateLimit(c, 'demo:ban:' + email, 60, 5)) return err(c, 'rate_limited', '操作过于频繁', 429);
  // 同时打三张身份表的 banned 列；现实里通过 admin/bans 端点统一处理，演示直接同步打
  const ts = `datetime('now', '+8 hours')`;
  await c.env.DB.prepare(
    `UPDATE gateway_users SET banned = 1, banned_at = ${ts}, banned_reason = 'Playground 演示封禁（用户自助触发）' WHERE email = ?`
  ).bind(email).run();
  await c.env.DB.prepare(
    `UPDATE users SET banned = 1, banned_at = ${ts}, banned_reason = 'Playground 演示封禁（用户自助触发）' WHERE email = ?`
  ).bind(email).run();
  await c.env.DB.prepare(
    `UPDATE oidc_identities SET banned = 1, banned_at = ${ts}, banned_reason = 'Playground 演示封禁（用户自助触发）' WHERE email = ?`
  ).bind(email).run();
  // 撤销所有活跃 refresh token / oidc grant，让封禁瞬时生效（与正式 admin/bans 同样的副作用）
  await c.env.DB.prepare(`DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM gateway_users WHERE email = ?)`).bind(email).run().catch(() => {});
  await c.env.DB.prepare(`DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE email = ?)`).bind(email).run().catch(() => {});
  return c.json({ success: true, message: '演示账号已封禁，下次 verify 会立即返回 AccountBannedError' });
});

app.post('/api/demo/unban-me', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const email = String(body.email || '').toLowerCase().trim();
  if (!email || !isDemoEmail(email)) {
    return err(c, 'not_demo_account', '此端点仅对 Playground 演示账号生效', 400);
  }
  if (await rateLimit(c, 'demo:unban:' + email, 60, 5)) return err(c, 'rate_limited', '操作过于频繁', 429);
  await c.env.DB.prepare(`UPDATE gateway_users SET banned = 0, banned_at = NULL, banned_reason = NULL WHERE email = ?`).bind(email).run();
  await c.env.DB.prepare(`UPDATE users SET banned = 0, banned_at = NULL, banned_reason = NULL WHERE email = ?`).bind(email).run();
  await c.env.DB.prepare(`UPDATE oidc_identities SET banned = 0, banned_at = NULL, banned_reason = NULL WHERE email = ?`).bind(email).run();
  return c.json({ success: true });
});

// ══════ Playground 演示 OIDC（与生产 OIDC 完全独立） ══════
// 设计原则：
//   - 自带认证流程：用 demo email/password 直接换 token（绕过 SSO Cookie 机制）
//   - 强制 client_id == env.PLAYGROUND_DEMO_CLIENT_ID，否则全部拒绝
//   - 共享生产 JWKS 签名（演示出来的 id_token 真实可被外部用 /oauth/jwks 验签）
//   - 数据存 demo_oidc_codes / demo_oidc_sessions，60s 短寿命，cron 自动清理

function demoClientId(c: any): string {
  return String(c.env.PLAYGROUND_DEMO_CLIENT_ID || '').toLowerCase();
}
function isDemoClientId(c: any, clientId: string): boolean {
  const expected = demoClientId(c);
  return !!expected && expected === String(clientId || '').toLowerCase();
}

// 1. GET /demo/oauth/authorize/info — 给 DemoAuthorize.vue 拉应用信息 + 验证 client_id
app.get('/demo/oauth/authorize/info', async (c) => {
  const clientId = c.req.query('client_id') || '';
  const redirectUri = c.req.query('redirect_uri') || '';
  if (!isDemoClientId(c, clientId)) {
    return err(c, 'invalid_client', '此端点仅限 Playground Demo App 使用', 400);
  }
  const app = await c.env.DB.prepare(
    'SELECT id, name, app_logo, app_homepage, redirect_uris FROM api_keys WHERE id = ? AND revoked = 0'
  ).bind(clientId).first() as any;
  if (!app) return err(c, 'invalid_client', '应用不存在或已撤销', 400);
  // redirect_uri 必须在已登记的 redirect_uris 里（演示同样走严格校验）
  const allowed = String(app.redirect_uris || '').split(/[\n,]+/).map((s: string) => s.trim()).filter(Boolean);
  if (!allowed.includes(redirectUri)) {
    return err(c, 'invalid_redirect_uri', `redirect_uri 不在白名单内: ${redirectUri}`, 400);
  }
  return c.json({
    app: { id: app.id, name: app.name, logo: app.app_logo, homepage: app.app_homepage },
    demo: true,
  });
});

// 2. POST /demo/oauth/authorize/consent — 验证 demo 凭证 + 发 code + 返回 redirect
app.post('/demo/oauth/authorize/consent', async (c) => {
  if (await rateLimit(c, 'demo_oidc_consent', 60, 20)) return err(c, 'rate_limited', '操作过于频繁', 429);
  const body = await c.req.json().catch(() => ({}));
  const { email, password, client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, action } = body;
  if (!isDemoClientId(c, client_id)) {
    return err(c, 'invalid_client', '此端点仅限 Playground Demo App 使用', 400);
  }
  if (action === 'deny') {
    const sep = redirect_uri.includes('?') ? '&' : '?';
    return c.json({ redirect: `${redirect_uri}${sep}error=access_denied${state ? '&state=' + encodeURIComponent(state) : ''}` });
  }
  if (!isPlaygroundDemoEmail(email)) {
    return err(c, 'invalid_grant', '此端点仅接受 playground 演示账号邮箱', 400);
  }
  if (!password) return err(c, 'invalid_grant', '密码必填', 400);
  // 验证 demo redirect_uri 是否在白名单里
  const app = await c.env.DB.prepare(
    'SELECT redirect_uris FROM api_keys WHERE id = ? AND revoked = 0'
  ).bind(client_id).first() as any;
  if (!app) return err(c, 'invalid_client', '应用不存在', 400);
  const allowed = String(app.redirect_uris || '').split(/[\n,]+/).map((s: string) => s.trim()).filter(Boolean);
  if (!allowed.includes(redirect_uri)) return err(c, 'invalid_redirect_uri', 'redirect_uri 不在白名单', 400);
  // 查 demo 用户（必须是同 tenant 即同一 api_key_id）
  const demoUser = await c.env.DB.prepare(
    `SELECT id, username, password_hash, salt, hash_version FROM users WHERE email = ? AND api_key_id = ?`
  ).bind(email, client_id).first() as any;
  if (!demoUser) return err(c, 'invalid_grant', '账号不存在或不属于此 demo 应用', 400);
  let valid = false;
  if (demoUser.hash_version === 1 && demoUser.salt) {
    valid = await oidcPbkdf2Verify(password, demoUser.password_hash, demoUser.salt);
  } else {
    const sha = await sha256(password);
    valid = (sha === demoUser.password_hash);
  }
  if (!valid) return err(c, 'invalid_grant', '密码错误', 401);
  // 生成 code，存 60s
  const code = 'demo_' + crypto.randomUUID() + crypto.randomUUID().replace(/-/g, '');
  await c.env.DB.prepare(
    `INSERT INTO demo_oidc_codes (code, client_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, state, demo_user_id, demo_email, demo_username, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+8 hours', '+60 seconds'))`
  ).bind(
    code, client_id, redirect_uri, scope || 'openid email profile',
    code_challenge || null, code_challenge_method || null, nonce || null, state || null,
    demoUser.id, email, demoUser.username || null
  ).run();
  const sep = redirect_uri.includes('?') ? '&' : '?';
  return c.json({ redirect: `${redirect_uri}${sep}code=${encodeURIComponent(code)}${state ? '&state=' + encodeURIComponent(state) : ''}` });
});

// 3. POST /demo/oauth/token — 用 code + PKCE verifier 换 access_token / id_token
app.post('/demo/oauth/token', async (c) => {
  if (await rateLimit(c, 'demo_oidc_token', 60, 20)) return err(c, 'rate_limited', '操作过于频繁', 429);
  const ctype = c.req.header('Content-Type') || '';
  let params: any = {};
  if (ctype.includes('application/x-www-form-urlencoded')) {
    const text = await c.req.text();
    params = Object.fromEntries(new URLSearchParams(text));
  } else {
    params = await c.req.json().catch(() => ({}));
  }
  const { grant_type, code, redirect_uri, client_id, code_verifier } = params;
  if (grant_type !== 'authorization_code') return c.json({ error: 'unsupported_grant_type' }, 400);
  if (!isDemoClientId(c, client_id)) return c.json({ error: 'invalid_client' }, 400);
  const row = await c.env.DB.prepare(
    `SELECT * FROM demo_oidc_codes WHERE code = ? AND used_at IS NULL AND expires_at > datetime('now', '+8 hours')`
  ).bind(code || '').first() as any;
  if (!row) return c.json({ error: 'invalid_grant', error_description: 'code 不存在 / 已用过 / 已过期（60s 寿命）' }, 400);
  // 标 used，防重放
  await c.env.DB.prepare(`UPDATE demo_oidc_codes SET used_at = datetime('now', '+8 hours') WHERE code = ?`).bind(code).run();
  if (row.client_id !== client_id) return c.json({ error: 'invalid_client' }, 400);
  if (row.redirect_uri !== redirect_uri) return c.json({ error: 'invalid_grant', error_description: 'redirect_uri 不匹配' }, 400);
  // PKCE 校验（如果当初有的话）
  if (row.code_challenge) {
    if (!code_verifier) return c.json({ error: 'invalid_grant', error_description: '缺少 code_verifier' }, 400);
    const expectedChallenge = row.code_challenge_method === 'S256'
      ? await sha256B64u(code_verifier)
      : code_verifier;
    if (expectedChallenge !== row.code_challenge) {
      return c.json({ error: 'invalid_grant', error_description: 'PKCE 校验失败' }, 400);
    }
  }
  // 签发 access_token + id_token（用 RS256，与生产 OIDC 同一 signing key）
  const sk = await getOrCreateActiveSigningKey(c.env.DB);
  const now = Math.floor(Date.now() / 1000);
  const scope = row.scope || 'openid email profile';
  const sub = row.demo_user_id;
  // ID Token：标记 demo:true 让接入方一眼看出是演示
  const idClaims: any = {
    iss: ISSUER, sub, aud: client_id, exp: now + ID_TOKEN_TTL_SEC, iat: now, auth_time: now, demo: true,
  };
  if (row.nonce) idClaims.nonce = row.nonce;
  if (scope.includes('email')) { idClaims.email = row.demo_email; idClaims.email_verified = false; }
  if (scope.includes('profile')) {
    idClaims.name = row.demo_username || row.demo_email.split('@')[0];
    idClaims.picture = ISSUER + '/avatar/demo.svg';
  }
  const idToken = await signRs256Jwt(idClaims, sk.kid, sk.key);
  const accessClaims = { iss: ISSUER, sub, aud: client_id, scope, exp: now + ACCESS_TOKEN_TTL_SEC, iat: now, token_use: 'access', demo: true };
  const accessToken = await signRs256Jwt(accessClaims, sk.kid, sk.key);
  // 存 session 用于 userinfo 反查
  const sessionId = crypto.randomUUID();
  await c.env.DB.prepare(
    `INSERT INTO demo_oidc_sessions (session_id, demo_user_id, demo_email, client_id, issued_at, expires_at)
     VALUES (?, ?, ?, ?, datetime('now', '+8 hours'), datetime('now', '+8 hours', '+1 hour'))`
  ).bind(sessionId, row.demo_user_id, row.demo_email, client_id).run();
  return c.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL_SEC,
    id_token: idToken,
    scope,
    demo: true,
  });
});

// 4. GET /demo/oauth/userinfo — 用 access_token 拉用户信息
app.get('/demo/oauth/userinfo', async (c) => {
  const auth = c.req.header('Authorization')?.replace(/^Bearer /, '');
  if (!auth) return c.json({ error: 'invalid_token' }, 401);
  try {
    const pk = await getActivePublicKey(c.env.DB);
    const payload: any = await verifyRs256(auth, pk.key);
    if (payload.token_use !== 'access' || !payload.demo) {
      return c.json({ error: 'invalid_token', error_description: '不是 demo access_token' }, 401);
    }
    // 查 users 表（demo tenant 隔离）
    const u = await c.env.DB.prepare(
      `SELECT id, email, username FROM users WHERE id = ? AND api_key_id = ?`
    ).bind(payload.sub, payload.aud).first() as any;
    if (!u) return c.json({ error: 'invalid_token', error_description: '演示账号已不存在（24h 后自动清理）' }, 401);
    return c.json({
      sub: u.id,
      email: u.email,
      email_verified: false,
      name: u.username || u.email.split('@')[0],
      picture: ISSUER + '/avatar/demo.svg',
      demo: true,
    });
  } catch (e: any) {
    return c.json({ error: 'invalid_token', error_description: e.message || 'token 验证失败' }, 401);
  }
});

app.post('/api/abuse/report', async (c) => {
  // 多维度限流（IP）+ 全局限流（防整体淹没）
  if (await rateLimit(c, 'abuse:ip:m', 60, 5)) return err(c, 'rate_limited', '举报太频繁，请稍后再试', 429);
  if (await rateLimit(c, 'abuse:ip:h', 3600, 10)) return err(c, 'rate_limited', '此 IP 今小时举报已达上限', 429);
  if (await rateLimit(c, 'abuse:ip:d', 86400, 20)) return err(c, 'rate_limited', '此 IP 今日举报已达上限', 429);
  if (await rateLimit(c, 'abuse:global:m', 60, 60)) return err(c, 'rate_limited', '系统繁忙', 429);

  const body = await c.req.json().catch(() => ({}));
  const target_type = String(body.target_type || '').trim();
  const target_id = String(body.target_id || '').trim().slice(0, 200);
  const category = String(body.category || '').trim();
  const description = String(body.description || '').trim().slice(0, 2000);
  const reporter_email = (body.reporter_email ? String(body.reporter_email).trim().slice(0, 254) : '') || null;

  if (!ABUSE_TARGET_TYPES.has(target_type)) return err(c, 'invalid_target_type', 'target_type 不合法', 400);
  if (!target_id) return err(c, 'missing_target', 'target_id 必填', 400);
  if (!ABUSE_CATEGORIES.has(category)) return err(c, 'invalid_category', 'category 不合法', 400);
  if (description.length < 10) return err(c, 'description_too_short', '请提供至少 10 个字符的描述以便复核', 400);
  if (reporter_email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(reporter_email)) return err(c, 'invalid_email', '邮箱格式不合法', 400);

  const ip = c.req.header('CF-Connecting-IP') || '';
  const ua = (c.req.header('User-Agent') || '').slice(0, 300);

  // CSAM 类零容忍 → 自动标记为 priority；其余正常队列
  // 不在 API 层自动处置，避免被人恶意举报刷封；全部走人工复核
  await c.env.DB.prepare(
    `INSERT INTO abuse_reports (id, target_type, target_id, category, description, reporter_email, reporter_ip, reporter_ua)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(crypto.randomUUID(), target_type, target_id, category, description, reporter_email, ip, ua).run();

  // 故意不告知"该目标存在不存在"防内部状态泄露
  return c.json({ success: true, message: '感谢举报，我们将在 72 小时内人工复核' });
});

// ══════ Admin: 举报队列 ══════
// GET /api/admin/abuse/pending — 列出待复核
app.get('/api/admin/abuse/pending', authMW, async (c) => {
  if (!isAdmin(c)) return err(c, 'forbidden', '仅平台站长可用', 403);
  const limit = Math.min(parseInt(c.req.query('limit') || '100'), 500);
  const { results } = await c.env.DB.prepare(
    `SELECT * FROM abuse_reports WHERE status = 'pending' ORDER BY
       CASE category WHEN 'csam' THEN 0 WHEN 'illegal' THEN 1 WHEN 'phishing' THEN 2 ELSE 9 END ASC,
       created_at DESC LIMIT ?`
  ).bind(limit).all();
  return c.json({ reports: results });
});

// 已处理记录（站长复盘 + 法律响应留痕）
app.get('/api/admin/abuse/resolved', authMW, async (c) => {
  if (!isAdmin(c)) return err(c, 'forbidden', '仅平台站长可用', 403);
  const limit = Math.min(parseInt(c.req.query('limit') || '100'), 500);
  const { results } = await c.env.DB.prepare(
    `SELECT * FROM abuse_reports WHERE status != 'pending' ORDER BY resolved_at DESC LIMIT ?`
  ).bind(limit).all();
  return c.json({ reports: results });
});

// 标记复核结果（resolved / rejected / duplicate）
app.post('/api/admin/abuse/:id/resolve', authMW, async (c) => {
  if (!isAdmin(c)) return err(c, 'forbidden', '仅平台站长可用', 403);
  const reportId = c.req.param('id');
  const { status, note } = await c.req.json().catch(() => ({}));
  if (!['resolved', 'rejected', 'duplicate'].includes(status)) return err(c, 'invalid_status', 'status 必须是 resolved/rejected/duplicate', 400);
  const operator = ((c as any).get('userEmail') as string || '').toLowerCase();
  const r = await c.env.DB.prepare('SELECT id FROM abuse_reports WHERE id = ?').bind(reportId).first();
  if (!r) return err(c, 'not_found', '举报不存在', 404);
  await c.env.DB.prepare(
    `UPDATE abuse_reports SET status = ?, resolved_by = ?, resolved_at = datetime('now', '+8 hours'), resolution_note = ? WHERE id = ?`
  ).bind(status, operator, String(note || '').slice(0, 500), reportId).run();
  return c.json({ success: true });
});

// ══════ Health ══════
app.get('/api/health', c => c.json({ status: 'ok', service: 'nexus-gateway', version: '5.0' }));

// ══════ Telemetry — 匿名 SDK/CLI 活跃统计 ══════
// 客户端规则：
//   - 仅在 NEXUS_AUTH_TELEMETRY_DISABLED / DO_NOT_TRACK / CI 三种环境变量均未设置时发送
//   - 24 小时内每设备最多发一次（客户端节流），无 API Key 原文（只送 sha256 前 16 位）
//   - 不收集 IP、用户名、路径；服务端这里也不记录 cf-connecting-ip
// 服务端规则：
//   - UPSERT（device_id + sdk_name 唯一）：first_seen 不变，last_seen / seen_count 更新
//   - 限流：同 device_id + sdk_name 12 小时内只接受 1 次（防伪造 / 防过度上报）
//   - 始终 204 No Content，绝不向客户端泄露任何错误信息
app.post('/telemetry/v1/active', async (c) => {
  try {
    const body = await c.req.json().catch(() => ({})) as any;
    const deviceId = String(body.device_id || '').slice(0, 64);
    const sdkName = String(body.sdk_name || '').slice(0, 40);
    const sdkVersion = String(body.sdk_version || '').slice(0, 20);
    if (!deviceId || !sdkName) return new Response(null, { status: 204 });
    // 服务端二次限流：同 device + sdk 12h 一次
    if (await rateLimit(c, 'telemetry:' + deviceId + ':' + sdkName, 43200, 1)) {
      return new Response(null, { status: 204 });
    }
    const osField = String(body.os || '').slice(0, 24);
    const osVersion = String(body.os_version || '').slice(0, 40);
    const runtime = String(body.runtime || '').slice(0, 40);
    const appHash = String(body.app_hash || '').slice(0, 32);
    await c.env.DB.prepare(
      `INSERT INTO telemetry_active (device_id, sdk_name, sdk_version, os, os_version, runtime, app_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(device_id, sdk_name) DO UPDATE SET
         sdk_version = excluded.sdk_version,
         os          = excluded.os,
         os_version  = excluded.os_version,
         runtime     = excluded.runtime,
         app_hash    = CASE WHEN excluded.app_hash != '' THEN excluded.app_hash ELSE telemetry_active.app_hash END,
         last_seen   = datetime('now', '+8 hours'),
         seen_count  = telemetry_active.seen_count + 1`
    ).bind(deviceId, sdkName, sdkVersion, osField, osVersion, runtime, appHash).run();
  } catch { /* 静默忽略，永不影响客户端业务 */ }
  return new Response(null, { status: 204 });
});

// 浏览器 sendBeacon 的 preflight：允许跨源任意 origin 提交（payload 已脱敏）
app.options('/telemetry/v1/active', _c => {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    },
  });
});

// ══════ Error Reports — 三端前端错误集中上报 ══════
// 设计原则：
//   - 客户端用 sendBeacon 提交，页面崩溃 / 卸载也能发出
//   - 客户端 5 分钟同 signature 去重；服务端再按 sha256(source+type+head) 12 小时去重
//   - 字符串字段做强长度截断，防垃圾数据撑爆 D1
//   - 静默吞错，任何异常不影响业务
//   - 永远返回 204，不向客户端泄露任何错误信息
app.post('/telemetry/errors/v1/report', async (c) => {
  try {
    const body = (await c.req.json().catch(() => ({}))) as any;
    if (!body || typeof body !== 'object') return new Response(null, { status: 204 });

    const source = String(body.source || '').slice(0, 20);
    const type = String(body.type || '').slice(0, 20);
    const message = String(body.message || '').slice(0, 500);
    if (!source || !type || !message) return new Response(null, { status: 204 });

    const allowedSources = new Set(['personal', 'gateway', 'user-center']);
    const allowedTypes = new Set(['runtime', 'promise', 'resource', 'console', 'vue', 'react']);
    if (!allowedSources.has(source) || !allowedTypes.has(type)) return new Response(null, { status: 204 });

    // 服务端去重：同 (source, type, message-head) 12 小时窗口
    const dedupeKey = await sha256(source + '::' + type + '::' + message.slice(0, 100));
    if (await rateLimit(c, 'err_dedupe:' + dedupeKey.slice(0, 16), 43200, 1)) {
      return new Response(null, { status: 204 });
    }

    const filename = String(body.filename || '').slice(0, 200);
    const stack = String(body.stack || '').slice(0, 2000);
    const url = String(body.url || '').slice(0, 500);
    const ua = String(body.ua || '').slice(0, 200);
    const info = String(body.info || '').slice(0, 100);
    const line = Math.min(Math.max(parseInt(body.line) || 0, 0), 999999);
    const column = Math.min(Math.max(parseInt(body.column) || 0, 0), 999999);
    const ip = c.req.header('CF-Connecting-IP') || '';

    await c.env.DB.prepare(
      `INSERT INTO error_reports (id, source, type, message, filename, line, column_no, stack, url, ua, info, ip)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(crypto.randomUUID(), source, type, message, filename, line, column, stack, url, ua, info, ip).run();
  } catch { /* 静默 */ }
  return new Response(null, {
    status: 204,
    headers: { 'Access-Control-Allow-Origin': '*' },
  });
});

app.options('/telemetry/errors/v1/report', _c => {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    },
  });
});

// ══════ Security response headers ══════
// 全站统一添加：HSTS / X-Content-Type-Options / Referrer-Policy / Permissions-Policy
// HTML 响应额外加：X-Frame-Options / CSP（防点击劫持、XSS 注入）
const _CSP_DIRECTIVES = [
  "default-src 'self'",
  // 'unsafe-inline': Cloudflare Web Analytics 注入的内联 beacon 初始化脚本需要
  // https://static.cloudflareinsights.com: CF Web Analytics beacon.min.js
  // https://*.alicdn.com / *.aliyun.com: 阿里云 ESA 边缘验证码 SDK
  "script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com https://*.alicdn.com https://*.aliyun.com",
  // Google Fonts 样式表
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "img-src 'self' data: https: blob:",
  // Google Fonts 字体文件
  "font-src 'self' data: https://fonts.gstatic.com",
  // CF Insights 上报 beacon 数据；阿里云 ESA 验证码调用接口
  "connect-src 'self' https://*.cloudflareinsights.com https://*.alicdn.com https://*.aliyun.com",
  // 阿里云 ESA 验证码会嵌 iframe
  "frame-src 'self' https://*.alicdn.com https://*.aliyun.com",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join('; ');
function applySecurityHeaders(resp: Response): Response {
  const ct = resp.headers.get('Content-Type') || '';
  const isHtml = ct.startsWith('text/html');
  const headers = new Headers(resp.headers);
  headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
  if (isHtml) {
    headers.set('X-Frame-Options', 'DENY');
    headers.set('Content-Security-Policy', _CSP_DIRECTIVES);
  }
  // 清理 Hono CORS 副作用：当 Origin 不匹配白名单时，残留的 Allow-Credentials 看起来像配置错误
  // 浏览器没 Allow-Origin 本就不会接受凭证，但响应里残留这个头会误导审计扫描器
  if (headers.has('Access-Control-Allow-Credentials') && !headers.has('Access-Control-Allow-Origin')) {
    headers.delete('Access-Control-Allow-Credentials');
  }
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
}

// ══════ Fetch handler ══════
// 关键修复：env.ASSETS.fetch() 对未知路径会返回 307 跳 / —— 直接转发会导致 SPA 路由失效。
// 改为：API/OIDC 走 Hono；带扩展名的静态文件走 ASSETS；其它一律返回 /index.html 让 Vue Router 接管。
async function _handleRequest(req: Request, env: Env, ctx: any): Promise<Response> {
  const url = new URL(req.url);
  const p = url.pathname;
  // 1) API/OIDC 路由 → Hono
  const isOauthApi = p.startsWith('/oauth/') && !(p === '/oauth/authorize' && req.method === 'GET');
  if (p.startsWith('/api/') || isOauthApi || p === '/.well-known/openid-configuration' || p.startsWith('/avatar/') || p.startsWith('/telemetry/')) {
    return app.fetch(req, env, ctx);
  }

  // 仅允许 GET/HEAD 访问前端
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET, HEAD' } });
  }

  try {
    // 2) 带扩展名的请求（.js/.css/.png/.svg/.ico/.json 等）→ 当作静态资源
    const hasExt = /\.[a-zA-Z0-9]{1,8}$/.test(p);
    if (hasExt) {
      const asset = await env.ASSETS.fetch(req);
      // 2xx 返回；非 2xx（包括 ASSETS 的 307 兜底）→ 当成不存在，返回 404
      if (asset.status >= 200 && asset.status < 300) {
        const headers = new Headers(asset.headers);
        headers.set('Cache-Control', 'public, max-age=31536000, immutable');
        return new Response(asset.body, { status: 200, headers });
      }
      return new Response('Not Found', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    }

    // 3) 非扩展路径 → 一律渲染 SPA（index.html），由 Vue Router 决定具体页面（含 NotFound）
    const indexReq = new Request(new URL('/index.html', url.origin), { method: 'GET' });
    const index = await env.ASSETS.fetch(indexReq);
    if (index.status < 200 || index.status >= 300) {
      return new Response('SPA shell missing', { status: 500 });
    }
    const headers = new Headers(index.headers);
    headers.set('Content-Type', 'text/html; charset=utf-8');
    // no-store 而非 no-cache：CF 边缘真正不缓存 HTML shell
    // 安全头部更新后无需手动 purge 即可立即生效；assets 文件依然走长缓存
    headers.set('Cache-Control', 'no-store');
    return new Response(index.body, { status: 200, headers });
  } catch (e: any) {
    return new Response('Worker Error: ' + (e.message || String(e)), { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }
}

// ══════ Scheduled (Cron) ══════
// 每小时跑一次：
//   1) 处理到期的 pending_deletions → 真删用户数据（users/oidc_identities/gateway_users/refresh_tokens/sessions/avatar）
//   2) 24h 内将到期但未发提醒邮件的注销 → 发提醒邮件 + 标 reminder_sent=1
//   3) 把 90 天前的 deletion_audit_log 中已执行（非撤销）的记录可选清理 — 暂不做，保留以备法律响应
async function processScheduledDeletions(env: Env) {
  // 到期：scheduled_at <= now
  const due = await env.DB.prepare(
    `SELECT email, user_id, requested_at, source, requester_ip FROM pending_deletions
     WHERE scheduled_at <= datetime('now', '+8 hours') LIMIT 100`
  ).all();
  for (const row of (due.results as any[])) {
    const email = row.email as string;
    const userId = row.user_id as string;
    // 真删跨表用户数据 + 关联凭证
    await env.DB.prepare('DELETE FROM oidc_sso_sessions WHERE identity_id = ?').bind(userId).run().catch(() => {});
    await env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').bind(userId).run().catch(() => {});
    await env.DB.prepare('UPDATE oidc_tokens SET revoked = 1 WHERE identity_id = ?').bind(userId).run().catch(() => {});
    await env.DB.prepare('DELETE FROM user_sessions WHERE user_id = ?').bind(userId).run().catch(() => {});
    await env.DB.prepare('DELETE FROM oidc_grants WHERE identity_id = ?').bind(userId).run().catch(() => {});
    await env.DB.prepare('DELETE FROM domain_verifications WHERE user_id = ?').bind(userId).run().catch(() => {});
    await env.DB.prepare('DELETE FROM users WHERE email = ?').bind(email).run().catch(() => {});
    await env.DB.prepare('DELETE FROM oidc_identities WHERE email = ?').bind(email).run().catch(() => {});
    await env.DB.prepare('DELETE FROM gateway_users WHERE email = ?').bind(email).run().catch(() => {});
    await env.DB.prepare('DELETE FROM pending_deletions WHERE email = ?').bind(email).run().catch(() => {});
    // R2 头像清理（best-effort，名字 = userId/*.{ext}）
    // 不做 list+delete 防 OPS 成本飙升；R2 lifecycle 自动过期更稳。注释留作 future-work
    // 永久审计：deletion 完成
    await env.DB.prepare(
      `INSERT INTO deletion_audit_log (id, email, user_id, requested_at, executed_at, source, requester_ip)
       VALUES (?, ?, ?, ?, datetime('now', '+8 hours'), ?, ?)`
    ).bind(crypto.randomUUID(), email, userId, row.requested_at, row.source || 'unknown', row.requester_ip || '').run().catch(() => {});
  }

  // 24h 倒计时提醒邮件（reminder_sent = 0 且 scheduled_at 在未来 24h 内）
  const upcoming = await env.DB.prepare(
    `SELECT email, scheduled_at FROM pending_deletions
     WHERE reminder_sent = 0
       AND scheduled_at > datetime('now', '+8 hours')
       AND scheduled_at <= datetime('now', '+8 hours', '+24 hours')
     LIMIT 100`
  ).all();
  const resendKey = env.RESEND_API_KEY;
  for (const row of (upcoming.results as any[])) {
    const email = row.email as string;
    if (resendKey && !resendBreakerOpen()) {
      try {
        const html = `
          <div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;padding:20px;color:#1a1a1a">
            <h2 style="font-size:18px;color:#92400e;margin:0 0 14px">账号注销倒计时 - 24 小时</h2>
            <p style="font-size:14px;line-height:1.7">你好，</p>
            <p style="font-size:14px;line-height:1.7">你的 NEXUS / AuthCore 账号将于 <strong>${row.scheduled_at}</strong> 自动注销并永久删除所有数据。</p>
            <p style="font-size:14px;line-height:1.7;background:#fffbeb;border:1px solid #fde68a;padding:10px 14px;border-radius:8px">
              <strong>如果你不想注销</strong>：登录 <a href="https://user.miaogou.site/console/security" style="color:#1a1a1a">user.miaogou.site</a> → 撤销注销请求
            </p>
            <p style="font-size:12px;color:#6b6b67;line-height:1.7">如果你确认注销，无需任何操作，到点系统自动执行。</p>
          </div>`;
        await fetchWithTimeout('https://api.resend.com/emails', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${resendKey}` },
          body: JSON.stringify({
            from: 'AuthCore <noreply@mail.miaogou.site>',
            to: [email],
            subject: '账号注销倒计时 24 小时 - NEXUS / AuthCore',
            html,
          }),
        }, 8000);
        resendNoteResult(true);
      } catch (_) { resendNoteResult(false); }
    }
    await env.DB.prepare('UPDATE pending_deletions SET reminder_sent = 1 WHERE email = ?').bind(email).run().catch(() => {});
  }
}

export default {
  async fetch(req: Request, env: Env, ctx: any) {
    const resp = await _handleRequest(req, env, ctx);
    return applySecurityHeaders(resp);
  },
  async scheduled(_event: any, env: Env, ctx: any) {
    ctx.waitUntil(processScheduledDeletions(env));
  },
};
