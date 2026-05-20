<div align="center">

# AuthCore

**跑在 Cloudflare Workers 上的开源认证即服务**
密码注册 / 登录 · OpenID Connect 跨应用 SSO · 中文文档 · 一行脚手架接入

[![npm version](https://img.shields.io/npm/v/nexus-auth-sdk.svg?color=1a1a1a)](https://www.npmjs.com/package/nexus-auth-sdk)
[![npm downloads](https://img.shields.io/npm/dm/nexus-auth-sdk.svg?color=1a1a1a)](https://www.npmjs.com/package/nexus-auth-sdk)
[![License](https://img.shields.io/github/license/Forage409/authcore.svg?color=1a1a1a)](LICENSE)
[![Stars](https://img.shields.io/github/stars/Forage409/authcore.svg?style=social)](https://github.com/Forage409/authcore/stargazers)

[**▶ 在线 Playground**](https://playground.miaogou.site) · [**控制台**](https://auth.miaogou.site) · [**npm 包**](https://www.npmjs.com/package/nexus-auth-sdk) · [**脚手架**](https://www.npmjs.com/package/create-nexus-auth)

无需注册账号，[**点这里**](https://playground.miaogou.site) 5 分钟亲手玩一遍：注册 → 登录 → OIDC SSO → 封禁演示

</div>

---

## 30 秒接入

```bash
npx create-nexus-auth my-app   # 一行脚手架，自动生成接入代码
cd my-app && npm install && npm run dev
```

或者直接 SDK：

```ts
import { AuthCore, AccountBannedError } from 'nexus-auth-sdk';

const auth = new AuthCore({ apiKey: 'nx_xxx' });

// 注册（自动处理邮箱验证码 / captcha 等开关，前端无需写条件分支）
await auth.register({ email, password });

// 登录返回 JWT + Refresh Token
const { token, refreshToken, user } = await auth.login({ email, password });

// 校验任意 token（密码登录 + OIDC 自动二选一）
const { valid, source } = await auth.verifyAny(token);   // source: 'jwt' | 'oidc'

// 命名异常类——instanceof 判断免硬编码 error string
try { await auth.login({ email, password }); }
catch (e) {
  if (e instanceof AccountBannedError) showBannedUI(e.reason);
  else throw e;
}
```

## 它是怎么运作的

```
   你的应用 (Browser)                                    AuthCore Gateway
   ─────────────────                                    ─────────────────
        │                                                       │
        │  1. POST /auth/register { email, password }            │
        │ ──────────────────────────────────────────────────► │
        │                                                       │
        │                                  PBKDF2 100k + salt   │
        │                                  写入 D1 (users)       │
        │                                  签发 JWT + Refresh    │
        │                                                       │
        │ ◄─────────────────────────────────────────────────── │
        │     { token, refreshToken, user }                      │
        │                                                       │
        │  2. GET  /auth/verify   Bearer <token>                 │
        │ ──────────────────────────────────────────────────► │
        │                              ★ 中途若账号被封禁        │
        │                              ★ 这里立刻 403 banned     │
        │ ◄─────────────────────────────────────────────────── │
        │                                                       │
        │  3. JWT 1h 过期，自动 refresh（SDK 内置单飞锁）         │
        │ ──────────────────────────────────────────────────► │
        │ ◄─────────────────────────────────────────────────── │
        │     { token (new), refreshToken (rotated) }            │
        │                                                       │
```

```
   OIDC SSO 跨应用                                       AuthCore Gateway
   ─────────────────                                    ─────────────────
        │                                                       │
        │  /oauth/authorize ?response_type=code &PKCE &state     │
        │ ──────────────────────────────────────────────────► │
        │                                                       │
        │       用户在 AuthCore 授权页确认（Google 风格）         │
        │                                                       │
        │ ◄─ 302 redirect_uri ?code=xxx &state=yyy ─────────── │
        │                                                       │
        │  POST /oauth/token  { code, code_verifier }            │
        │ ──────────────────────────────────────────────────► │
        │ ◄─ { access_token, refresh_token, id_token (RS256) } │
        │                                                       │
        │  GET  /oauth/userinfo  Bearer <access_token>           │
        │ ──────────────────────────────────────────────────► │
        │ ◄─ { sub, email, name, picture, email_verified } ─── │
```

## 为什么选 AuthCore

|  | AuthCore | Auth0 | Clerk | 自己造 |
|---|---|---|---|---|
| 部署 | CF Workers 5 分钟 | 闭源 SaaS | 闭源 SaaS | 几周到几月 |
| 价格 | **免费**（自部署）| $25/mo 起 | $25/mo 起 | 工时成本 |
| OIDC SSO | ✓ | ✓ | ✓ | 自己写 |
| 中文文档 / 合规 | ✓ | ✗ | ✗ | — |
| 14 天注销 / 举报 / 封禁审计 | ✓ | 部分 | 部分 | 自己写 |
| 源码可改 | MIT 全开源 | ✗ | ✗ | 你的代码 |

## 仓库内容

| 目录 | 说明 |
|------|------|
| [`workers/nexus-gateway/`](workers/nexus-gateway) | 认证网关 Worker（Hono + D1 + R2），主入口 [`index.ts`](workers/nexus-gateway/index.ts) |
| [`workers/nexus-gateway/sdk/`](workers/nexus-gateway/sdk) | npm 包 `nexus-auth-sdk` 源码 |
| [`workers/migrations/`](workers/migrations) | D1 数据库迁移脚本（按序号执行） |
| [`create-authcore-app/`](create-authcore-app) | npm 包 `create-nexus-auth` —— 脚手架，一行 `npx` 生成接入项目 |

> 本仓库**只开源后端**。开发者控制台（`auth.miaogou.site`）的 Vue 前端、平台管理员视图、个人站等暂不开源。

## npm 包

```bash
npm install nexus-auth-sdk        # 接入 SDK（已发布到 npm）
npx create-nexus-auth my-app      # 一行脚手架（已发布到 npm）
```

- [`nexus-auth-sdk`](https://www.npmjs.com/package/nexus-auth-sdk) —— 4 种入口：`/`（核心）、`/react`、`/oidc`、`/oidc-react`
- [`create-nexus-auth`](https://www.npmjs.com/package/create-nexus-auth) —— 三种模板：full（前后端）、oidc-only（纯 SPA）、backend-only

## 主要能力

**认证 / 授权**
- 密码注册 + 邮箱验证码（PBKDF2 100k 迭代 + 随机盐）
- JWT (1h) + Refresh Token (30d 滑动续期)
- OpenID Connect（RS256 + JWKS + PKCE + state/nonce 强制校验）
- 6 个 OIDC 端点 + Google 风格授权页

**安全**
- 阿里云 ESA 边缘验证码托底（防邮箱枚举 DoS）
- 全社区每日邮件配额，耗尽自动关 captcha、次日恢复
- 撞库检测（15min/5 次锁）、API Key IP 白名单、SSRF 防护、安全响应头
- 完整账号封禁系统（四张身份表 + 永久审计日志 + 四网同步生效）
- 命名异常类（`AccountBannedError` / `ApiKeyBannedError` / `AppBannedError` 等），`instanceof` 判断

**合规**
- 自助 14 天注销 + cron 真删（兑现 ToS § 6）
- 公开举报端点 `/api/abuse/report`（强限流，CSAM 优先复核但不自动处置防恶意刷封）
- 被封禁内容保留 90 天用于法律响应

**开发者体验**
- Webhook 创建 / 测试 / 删除，payload 带 `app_id` 字段（多 Key 共用 webhook 时区分来源）
- 4 个 403 错误码（`account_banned` / `api_key_banned` / `api_key_owner_banned` / `app_banned`）端到端打通到 SDK

## 自部署

### 1. 创建 Cloudflare 资源

```bash
npx wrangler d1 create nexus-db
npx wrangler r2 bucket create nexus-avatars
```

将得到的 `database_id` 填入 [`workers/nexus-gateway/wrangler.toml`](workers/nexus-gateway/wrangler.toml)。

### 2. 跑迁移（按序号执行）

```bash
cd workers/nexus-gateway
npx wrangler d1 execute nexus-db --file=../migrations/0004_api_keys.sql --remote
npx wrangler d1 execute nexus-db --file=../migrations/0005_oauth_codes.sql --remote
# ... 依次执行 migrations/ 中网关相关 SQL
```

> 部分早期 migration 是个人站专用（posts/friends 等），自部署时可跳过——网关只用到 api_keys / oauth_codes / gateway_users / rate_limits / refresh_tokens / verification_codes / webhooks / oidc_* / ban_audit_log / abuse_reports 等表。

### 3. 设置 Secrets

```bash
cd workers/nexus-gateway
npx wrangler secret put JWT_SECRET           # 随机 32+ 位字符串
npx wrangler secret put RESEND_API_KEY       # Resend 邮件 API Key
npx wrangler secret put PLATFORM_OWNERS      # 平台站长邮箱，逗号分隔
                                             # 例: you@example.com,backup@example.com
```

`PLATFORM_OWNERS` 决定谁能调 `/api/admin/*` 站长接口（封禁 / 应用审批 / 溯源等），**必须设置**否则站长功能全部失效。

### 4. 部署

```bash
cd workers/nexus-gateway && npx wrangler deploy
```

## SDK 接入示例

```ts
import { AuthCore, AccountBannedError } from 'nexus-auth-sdk';

const auth = new AuthCore({ apiKey: process.env.AUTHCORE_API_KEY });

try {
  const res = await auth.login({ email, password });
  // res.token / res.refreshToken / res.user
} catch (e) {
  if (e instanceof AccountBannedError) {
    showBannedUI(e.reason);
  } else throw e;
}
```

详见 [`workers/nexus-gateway/sdk/README.md`](workers/nexus-gateway/sdk/README.md)。

## 技术栈

- **运行时**：Cloudflare Workers + Hono + TypeScript
- **数据库**：D1 (SQLite) + R2 (avatars)
- **邮件**：Resend
- **验证码**：阿里云 ESA Edge CAPTCHA

## 许可证

MIT
