/**
 * AuthCore OIDC 工具：RSA 签名 + JWT + PKCE
 * 设计：所有密钥懒生成、存 D1；access_token/id_token 用 RS256；refresh_token 用 UUID + DB 哈希
 */

// ── base64url helpers ──
function bytesToB64u(buf: ArrayBuffer | Uint8Array): string {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64uToBytes(s: string): Uint8Array {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}
function strToB64u(s: string): string {
  return bytesToB64u(new TextEncoder().encode(s));
}

export async function sha256B64u(s: string): Promise<string> {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return bytesToB64u(h);
}

export async function sha256Hex(s: string): Promise<string> {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── RSA 密钥懒生成 + 缓存 ──
let cachedSigningKey: { kid: string; key: CryptoKey } | null = null;

export async function getOrCreateActiveSigningKey(db: any): Promise<{ kid: string; key: CryptoKey; publicJwk: any }> {
  // 先查 D1
  const row = await db.prepare(`SELECT kid, public_jwk, private_pkcs8 FROM oidc_signing_keys WHERE active = 1 ORDER BY created_at DESC LIMIT 1`).first() as any;
  if (row) {
    if (cachedSigningKey && cachedSigningKey.kid === row.kid) {
      return { kid: row.kid, key: cachedSigningKey.key, publicJwk: JSON.parse(row.public_jwk) };
    }
    const pkcs8 = b64uToBytes(row.private_pkcs8);
    const key = await crypto.subtle.importKey(
      'pkcs8',
      pkcs8,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );
    cachedSigningKey = { kid: row.kid, key };
    return { kid: row.kid, key, publicJwk: JSON.parse(row.public_jwk) };
  }
  // 首次生成 RSA-2048 keypair
  const pair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  ) as CryptoKeyPair;
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const privatePkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  const kid = 'k-' + crypto.randomUUID().slice(0, 8);
  publicJwk.kid = kid;
  publicJwk.use = 'sig';
  publicJwk.alg = 'RS256';
  await db.prepare(
    `INSERT INTO oidc_signing_keys (kid, alg, public_jwk, private_pkcs8, active) VALUES (?, 'RS256', ?, ?, 1)`
  ).bind(kid, JSON.stringify(publicJwk), bytesToB64u(privatePkcs8)).run();
  cachedSigningKey = { kid, key: pair.privateKey };
  return { kid, key: pair.privateKey, publicJwk };
}

export async function listJwks(db: any): Promise<{ keys: any[] }> {
  const { results } = await db.prepare(`SELECT public_jwk FROM oidc_signing_keys WHERE active = 1`).all();
  const keys = (results as any[]).map(r => JSON.parse(r.public_jwk));
  return { keys };
}

// ── JWT 签名 (RS256) ──
export async function signRs256Jwt(payload: any, kid: string, privateKey: CryptoKey): Promise<string> {
  const header = { alg: 'RS256', typ: 'JWT', kid };
  const headB64 = strToB64u(JSON.stringify(header));
  const payB64 = strToB64u(JSON.stringify(payload));
  const data = new TextEncoder().encode(headB64 + '.' + payB64);
  const sig = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, privateKey, data);
  return headB64 + '.' + payB64 + '.' + bytesToB64u(sig);
}

// ── PKCE ──
export async function verifyPkce(verifier: string, challenge: string, method: string): Promise<boolean> {
  if (!challenge) return true; // 没存挑战 = 未启用 PKCE
  if (!verifier) return false;
  // 拒绝 plain（OAuth 2.1 / RFC 9700）
  if (method !== 'S256') return false;
  const hash = await sha256B64u(verifier);
  return hash === challenge;
}

// ── PBKDF2（与 nexus-gateway/index.ts 一致以便跨表共用密码） ──
export async function pbkdf2Hash(password: string): Promise<{ hash: string; salt: string }> {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const salt = Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, key, 256);
  const hash = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  return { hash, salt };
}
export async function pbkdf2Verify(password: string, storedHash: string, salt: string): Promise<boolean> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, key, 256);
  const hash = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  return hash === storedHash;
}

// ── 客户端凭证 ──
export function generateClientSecret(): string {
  // 32 字节随机，base64url，约 43 字符
  return bytesToB64u(crypto.getRandomValues(new Uint8Array(32)));
}

// ── redirect_uri 严格校验 ──
export function isValidRedirectUri(provided: string, registered: string): boolean {
  // 拆按行/逗号分隔的注册列表，精确匹配（含 query / hash 必须完全一致）
  const list = (registered || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
  return list.includes(provided);
}

// ── 解析 Bearer token (RS256) — 不校验签名（信任内部签发）只解 payload，必要时用 jose 验签 ──
export function decodeJwtPayload(token: string): any {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('invalid_token');
  const payJson = new TextDecoder().decode(b64uToBytes(parts[1]));
  return JSON.parse(payJson);
}

export async function verifyRs256(token: string, publicKey: CryptoKey): Promise<any> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('invalid_token');
  const ok = await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    publicKey,
    b64uToBytes(parts[2]),
    new TextEncoder().encode(parts[0] + '.' + parts[1])
  );
  if (!ok) throw new Error('invalid_signature');
  const payload = JSON.parse(new TextDecoder().decode(b64uToBytes(parts[1])));
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) throw new Error('expired');
  return payload;
}

// ── 获取活动公钥 CryptoKey（用于本服务内自校验 access_token） ──
let cachedPublicKey: { kid: string; key: CryptoKey } | null = null;
export async function getActivePublicKey(db: any): Promise<{ kid: string; key: CryptoKey }> {
  const row = await db.prepare(`SELECT kid, public_jwk FROM oidc_signing_keys WHERE active = 1 ORDER BY created_at DESC LIMIT 1`).first() as any;
  if (!row) throw new Error('no_active_key');
  if (cachedPublicKey && cachedPublicKey.kid === row.kid) return cachedPublicKey;
  const jwk = JSON.parse(row.public_jwk);
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
  cachedPublicKey = { kid: row.kid, key };
  return cachedPublicKey;
}
