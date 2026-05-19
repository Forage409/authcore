# nexus-auth-sdk

> v5.3.2 · 用户认证即服务。一个包同时支持「邮箱密码注册」与「OIDC 跨应用单点登录」两种模式，按需引入。

## 快速开始

```bash
npm install nexus-auth-sdk
```

```js
import { AuthCore } from 'nexus-auth-sdk';

const auth = new AuthCore({ apiKey: 'nx_xxxxxxxx' });

// 注册
const { token, refreshToken, user } = await auth.register({
  email: 'user@example.com',
  password: 'Pass1234',
});

// 登录
const result = await auth.login({ email, password });

// 校验 token（如鉴权中间件中使用）
const { valid, user: u } = await auth.verify(token);
```

## 四个入口

| 入口路径 | 用途 | 主要导出 |
|---|---|---|
| `nexus-auth-sdk` | Node / 任意 JS 后端，邮箱密码模式 | `AuthCore` |
| `nexus-auth-sdk/react` | React 应用，含 SignIn / SignUp 现成组件 | `AuthCoreProvider`, `SignIn`, `SignUp`, `useAuthCore` |
| `nexus-auth-sdk/oidc` | 浏览器/Node，"用 AuthCore 登录"按钮，跨应用 SSO | `OidcClient`（带 PKCE） |
| `nexus-auth-sdk/oidc-react` | React 应用接 OIDC SSO | `OidcProvider`, `OidcSignInButton`, `OidcCallback`, `useOidc` |

不确定从哪开始？跑 `npx create-nexus-auth my-app` 拿到一个可直接运行的完整 Demo 项目（含前后端登录/注册页 + Express），改一行 API Key 就能跑。

---

## v5.3 新增：会话撤销自动登出

当用户从 [user.miaogou.site](https://user.miaogou.site) 撤销了对你的应用的授权后，access_token 在自然过期前仍可能缓存在客户端。SDK 现在内置 401 拦截，配合下面两个 API 让你的应用**自动登出**：

```js
// 1. 注册回调：任意 SDK 调用收到 401 即触发
auth.onSessionRevoked(() => {
  localStorage.removeItem('token');
  location.href = '/login?reason=revoked';
});

// 2. （可选）启动轻量轮询，让用户在静默期内也能感知撤销
const stop = auth.startSessionWatch(token, { intervalMs: 60_000 });
// 离开页面时：stop();

// OIDC 模式：
auth.startSessionWatch(accessToken, { oidc: true });
```

这是 Google / GitHub 等业界标准的被动撤销模型 —— 撤销方只清服务端 token，调用方通过 401 自然感知后清理本地态。

---

## v5.0 新增：OIDC 跨应用 SSO

```js
import { OidcClient } from 'nexus-auth-sdk/oidc';

const oidc = new OidcClient({
  clientId: 'YOUR_CLIENT_ID',          // 控制台应用的 Client ID（= API Key 的 id 列）
  redirectUri: window.location.origin + '/callback',
});

// 登录按钮：跳转到 auth.miaogou.site/oauth/authorize
document.getElementById('login').onclick = () => oidc.signIn();

// 在 /callback 页面：
const { idToken, accessToken, user } = await oidc.handleCallback();
// user = { sub, email, name, picture }
```

React：

```jsx
import { OidcProvider, OidcSignInButton, OidcCallback, useOidc } from 'nexus-auth-sdk/oidc-react';

<OidcProvider clientId="YOUR_CLIENT_ID" redirectUri={origin + '/callback'}>
  <OidcSignInButton>用 AuthCore 登录</OidcSignInButton>
</OidcProvider>

// /callback 路由：
<OidcProvider clientId="..." redirectUri={origin + '/callback'}>
  <OidcCallback onComplete={(t) => navigate('/')} />
</OidcProvider>
```

OIDC 服务地址：
- Issuer: `https://auth.miaogou.site`
- Discovery: `https://auth.miaogou.site/.well-known/openid-configuration`
- 在 AuthCore 控制台开应用 → 编辑 → 开启 OIDC → 填 redirect_uris → 可选生成 Client Secret

---

## API Key 密码注册（v4.x 保留）

**v4.5 起：邮箱验证由 SDK 自动检测。** 不再需要手动传 `emailVerification` prop —— `<SignUp />` 会在挂载时调用 `client.getConfig()`，根据 effective 状态自动渲染 UI（含社区邮件配额耗尽时的自动降级）。

## 社区邮件配额自动降级

我们的免费邮件额度为**每天 100 封全社区共享**（含所有 API Key 调用 send-code 的总和）。当配额耗尽时：

- 后端 `/api/auth/config` 返回 `require_email_verification: false`、`captcha_forced_off: true`
- SDK 自动隐藏「发送验证码」按钮和「验证码输入框」
- 注册接口会接受不带验证码的请求
- 控制台中所有 API Key 的「邮箱验证」开关会被**系统暂时强制关闭且禁止手动开启**，次日 00:00（北京时间）按你之前的设置精确恢复（开的还开、关的还关）

如果你需要更高额度，请自行接入第三方邮件服务（Resend、SendGrid 等）并把验证码下发改成你自己的实现。

## 安装

```bash
npm install nexus-auth-sdk
```

## 两条接入路径

接入方式取决于你在控制台创建 API Key 时是否开启「邮箱验证」：

| | 路径 A · 未开启邮箱验证 | 路径 B · 已开启邮箱验证 |
|---|---|---|
| 流程 | 直接 `register` | `sendCode` → `verifyCode` → `register` |
| 适用 | 内部系统、对邮箱真实性要求不高 | 防垃圾注册、需要邮箱可达 |
| 注册接口行为 | 直接创建用户 | 未验证的邮箱会被拒绝（`email_not_verified`） |

```js
// 路径 A：直接注册
const { token, user } = await auth.register({ email, password, username });

// 路径 B：先验证邮箱再注册
await auth.sendCode({ email });                    // 1. 发码
const { valid } = await auth.verifyCode({ email, code });  // 2. 验码
if (valid) await auth.register({ email, password, username }); // 3. 注册

// 推荐：先查一次 effective 配置（已合并配额耗尽降级）
const cfg = await auth.getConfig();
if (cfg.require_email_verification) {
  // 走路径 B
} else {
  // 走路径 A（可能是你没开，也可能是社区配额耗尽今日降级）
  if (cfg.captcha_forced_off) console.warn('今日邮件配额已用完，已自动降级为免验证码注册');
}
```

## 5 分钟快速上手

### 1. 获取 API Key

在 [AuthCore 控制台](https://auth.miaogou.site) 注册并创建应用，获得 `nx_` 开头的 API Key。

### 2. 在你的后端加入认证

```js
const { AuthCore } = require('nexus-auth-sdk');
const auth = new AuthCore({ apiKey: 'nx_your_key_here' });

// 注册
app.post('/api/register', async (req, res) => {
  try {
    const { token, user } = await auth.register(req.body);
    res.cookie('token', token, { httpOnly: true });
    res.json({ user });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// 登录
app.post('/api/login', async (req, res) => {
  try {
    const { token, user } = await auth.login(req.body);
    res.cookie('token', token, { httpOnly: true });
    res.json({ user });
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
});

// 校验 Token
app.get('/api/me', async (req, res) => {
  const t = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  const { valid, user } = await auth.verify(t);
  valid ? res.json({ user }) : res.status(401).json({ error: 'Unauthorized' });
});
```

## API

所有方法返回 Promise。

### `new AuthCore({ apiKey, baseUrl? })`

创建客户端实例。`baseUrl` 默认为 `https://auth.miaogou.site/api`。

### `auth.register({ email, password, username? })`

注册新用户。返回 `{ token, refreshToken, user }`。
- `email` 必填，有效邮箱地址
- `password` 必填，至少 8 位
- `username` 选填，默认取邮箱前缀

### `auth.login({ email, password })`

登录已有用户。返回 `{ token, refreshToken, user }`。

### `auth.verify(token)`

校验 JWT Token 是否有效。返回 `{ valid, user? }`。

### `auth.refresh(refreshToken)`

用 refreshToken 换取新 Token 对。**旧 refreshToken 随即失效（轮换式）**。返回 `{ token, refreshToken }`。

**重要：并发调用必须加单飞锁**

旧 refresh token 被作废后，**任何并发的第二次 refresh 调用都会失败**（拿着已 revoked 的旧 token）。在你的应用里：

```js
// 单飞模式（避免误踢登出）
let _refreshing = null;
async function refreshOnce(rt) {
  if (_refreshing) return _refreshing;
  _refreshing = auth.refresh(rt).finally(() => { _refreshing = null; });
  return _refreshing;
}

// 多个并发请求 401 时统一调 refreshOnce()，只发一次网络请求
```

Refresh token TTL = 30 天，每次刷新自动续 30 天（滑动续期）。用户 30 天内访问过一次就一直保持登录。

### `auth.revoke(refreshToken)`

撤销一个 refreshToken，使其无法再用于刷新。

### `auth.sendCode({ email })`

向指定邮箱发送 6 位验证码。返回 `{ success, email_sent, expires_in }`。
- 需要该 API Key 开启了"邮箱验证"开关
- 同一邮箱 60 秒内只能发送一次

### `auth.verifyCode({ email, code })`

校验验证码。返回 `{ valid }`。

## 错误处理

```js
try {
  const { token, user } = await auth.login({ email, password });
} catch (e) {
  console.log(e.message); // "邮箱或密码错误"
}
```

## React 绑定

```jsx
import { AuthCoreProvider, useAuthCore, SignIn, SignUp } from 'nexus-auth-sdk/react';

function App() {
  return (
    <AuthCoreProvider apiKey="nx_xxx">
      <AuthPage />
    </AuthCoreProvider>
  );
}

function AuthPage() {
  const { user, loading } = useAuthCore();
  if (user) return <p>欢迎, {user.email}</p>;
  return <SignIn onSuccess={(data) => console.log('已登录', data.user)} />;
}
```

`useAuthCore()` 返回 `{ client, user, token, loading, isSignedIn, signOut, ... }`。

### 注册组件与邮箱验证

`<SignUp>` 默认走路径 A（直接注册）。若你的 API Key 开启了邮箱验证，传 `emailVerification`：

```jsx
// 路径 B：表单内置「发送验证码 → 输入验证码」，提交时自动校验再注册
<SignUp emailVerification onSuccess={(data) => console.log('已注册', data.user)} />
```

## 要点

- JWT 有效期 15 分钟，请在客户端使用 `refresh()` 自动续期
- 敏感端点（send-code / register / login）有速率限制
- API Key 需妥善保管，建议放在服务端环境变量中
