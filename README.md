# AuthCore

跑在 Cloudflare Workers 上的认证即服务（Auth-as-a-Service）后端。开发者注册后拿到 API Key，即可用一套 SDK 给自家应用接上密码注册 / 登录 + OpenID Connect 跨应用 SSO。

线上：**https://auth.miaogou.site**

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
