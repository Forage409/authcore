<div align="center">

# AuthCore

**Open-source Auth-as-a-Service on Cloudflare Workers**
Password auth · OpenID Connect SSO · JWT + refresh tokens · User moderation · Deploy in 5 minutes

[![npm version](https://img.shields.io/npm/v/nexus-auth-sdk.svg?color=1a1a1a)](https://www.npmjs.com/package/nexus-auth-sdk)
[![npm downloads](https://img.shields.io/npm/dm/nexus-auth-sdk.svg?color=1a1a1a)](https://www.npmjs.com/package/nexus-auth-sdk)
[![License](https://img.shields.io/github/license/Forage409/authcore.svg?color=1a1a1a)](LICENSE)
[![Stars](https://img.shields.io/github/stars/Forage409/authcore.svg?style=social)](https://github.com/Forage409/authcore/stargazers)

[**Live Playground**](https://playground.miaogou.site) · [**Dashboard**](https://auth.miaogou.site) · [**npm**](https://www.npmjs.com/package/nexus-auth-sdk) · [**Scaffolding CLI**](https://www.npmjs.com/package/create-nexus-auth)

No sign-up needed — [**try it now**](https://playground.miaogou.site): Register → Login → OIDC SSO → Ban demo

[**中文文档 / Chinese Docs**](README.zh-CN.md)

</div>

---

## 30-Second Setup

```bash
npx create-nexus-auth my-app    # scaffold a full auth app in one command
cd my-app && npm install && npm run dev
```

Or use the SDK directly:

```ts
import { AuthCore, AccountBannedError } from 'nexus-auth-sdk';

const auth = new AuthCore({ apiKey: 'nx_xxx' });

// Register (handles email verification / captcha automatically)
await auth.register({ email, password });

// Login returns JWT + Refresh Token
const { token, refreshToken, user } = await auth.login({ email, password });

// Verify any token (password login + OIDC auto-detected)
const { valid, source } = await auth.verifyAny(token);  // source: 'jwt' | 'oidc'

// Named error classes — no hardcoded error strings
try { await auth.login({ email, password }); }
catch (e) {
  if (e instanceof AccountBannedError) showBannedUI(e.reason);
  else throw e;
}
```

## How It Works

```
   Your App (Browser)                                    AuthCore Gateway
   ──────────────────                                   ─────────────────
        │                                                       │
        │  1. POST /auth/register { email, password }           │
        │ ─────────────────────────────────────────────────►    │
        │                                                       │
        │                                  PBKDF2 100k + salt   │
        │                                  Store in D1 (users)  │
        │                                  Issue JWT + Refresh  │
        │                                                       │
        │ ◄─────────────────────────────────────────────────    │
        │     { token, refreshToken, user }                     │
        │                                                       │
        │  2. GET /auth/verify  Bearer <token>                  │
        │ ─────────────────────────────────────────────────►    │
        │                         If account is banned →        │
        │                         instant 403 response          │
        │ ◄─────────────────────────────────────────────────    │
        │                                                       │
        │  3. JWT expires (1h), auto-refresh (SDK handles it)   │
        │ ─────────────────────────────────────────────────►    │
        │ ◄─────────────────────────────────────────────────    │
        │     { token (new), refreshToken (rotated) }           │
```

```
   OIDC SSO Client                                       AuthCore Gateway
   ────────────────                                     ─────────────────
        │                                                       │
        │  /oauth/authorize ?response_type=code &PKCE &state    │
        │ ─────────────────────────────────────────────────►    │
        │                                                       │
        │       User confirms on AuthCore consent page          │
        │                                                       │
        │ ◄── 302 redirect_uri ?code=xxx &state=yyy ──────     │
        │                                                       │
        │  POST /oauth/token { code, code_verifier }            │
        │ ─────────────────────────────────────────────────►    │
        │ ◄── { access_token, refresh_token, id_token (RS256) } │
        │                                                       │
        │  GET /oauth/userinfo  Bearer <access_token>           │
        │ ─────────────────────────────────────────────────►    │
        │ ◄── { sub, email, name, picture, email_verified } ──  │
```

## Why AuthCore?

|  | AuthCore | Auth0 | Clerk | DIY |
|---|---|---|---|---|
| Deploy | CF Workers, 5 min | Closed SaaS | Closed SaaS | Weeks to months |
| Price | **Free** (self-host) | From $25/mo | From $25/mo | Engineering cost |
| OIDC SSO | ✓ | ✓ | ✓ | Build it yourself |
| User ban / moderation | ✓ | Partial | Partial | Build it yourself |
| 14-day account deletion | ✓ | Partial | Partial | Build it yourself |
| Source code | MIT, fully open | ✗ | ✗ | Your code |

## Features

**Authentication & Authorization**
- Email + password registration with PBKDF2 (100k iterations + random salt)
- JWT (1h) + Refresh Token (30d sliding window)
- Full OpenID Connect Provider (RS256 + JWKS + PKCE + state/nonce validation)
- 6 OIDC endpoints + Google-style consent page

**Security**
- Brute-force protection (5 attempts / 15 min lockout)
- API key IP allowlist, SSRF protection, security headers
- Full account ban system (4 identity tables + permanent audit log)
- Named error classes (`AccountBannedError` / `ApiKeyBannedError` / `AppBannedError`)

**Compliance**
- Self-service 14-day account deletion + cron hard-delete
- Public abuse report endpoint `/api/abuse/report` (rate-limited)
- Banned content retained 90 days for legal response

**Developer Experience**
- Webhooks with `app_id` field for multi-key routing
- 4 granular 403 error codes propagated end-to-end through the SDK
- React hooks: `useAuth()`, `useOIDC()`

## Repository Structure

| Directory | Description |
|-----------|-------------|
| [`workers/nexus-gateway/`](workers/nexus-gateway) | Auth gateway Worker (Hono + D1 + R2), entry: [`index.ts`](workers/nexus-gateway/index.ts) |
| [`workers/nexus-gateway/sdk/`](workers/nexus-gateway/sdk) | npm package `nexus-auth-sdk` source |
| [`workers/migrations/`](workers/migrations) | D1 database migration scripts |
| [`create-authcore-app/`](create-authcore-app) | npm package `create-nexus-auth` — scaffolding CLI |

## Self-Hosting

### 1. Create Cloudflare Resources

```bash
npx wrangler d1 create nexus-db
npx wrangler r2 bucket create nexus-avatars
```

Add the `database_id` to [`workers/nexus-gateway/wrangler.toml`](workers/nexus-gateway/wrangler.toml).

### 2. Run Migrations

```bash
cd workers/nexus-gateway
npx wrangler d1 execute nexus-db --file=../migrations/0004_api_keys.sql --remote
npx wrangler d1 execute nexus-db --file=../migrations/0005_oauth_codes.sql --remote
# ... run gateway-related SQL files in order
```

### 3. Set Secrets

```bash
cd workers/nexus-gateway
npx wrangler secret put JWT_SECRET           # random 32+ char string
npx wrangler secret put RESEND_API_KEY       # Resend email API key
npx wrangler secret put PLATFORM_OWNERS      # admin emails, comma-separated
```

### 4. Deploy

```bash
cd workers/nexus-gateway && npx wrangler deploy
```

## npm Packages

```bash
npm install nexus-auth-sdk        # SDK
npx create-nexus-auth my-app      # scaffolding CLI
```

- [`nexus-auth-sdk`](https://www.npmjs.com/package/nexus-auth-sdk) — 4 entry points: `/` (core), `/react`, `/oidc`, `/oidc-react`
- [`create-nexus-auth`](https://www.npmjs.com/package/create-nexus-auth) — 3 templates: full (frontend + backend), oidc-only (SPA), backend-only

## Tech Stack

- **Runtime**: Cloudflare Workers + Hono + TypeScript
- **Database**: D1 (SQLite) + R2 (avatars)
- **Email**: Resend
- **CAPTCHA**: Alibaba Cloud ESA Edge CAPTCHA

## License

MIT
