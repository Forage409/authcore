# AuthCore OIDC 接入示例

纯前端 SPA，通过标准 OpenID Connect 协议接入 AuthCore，用户在任意 AuthCore 应用注册后，可在你的应用一键登录。

## 快速开始

```bash
# 1. 在 https://auth.miaogou.site 控制台
#    创建应用 → 编辑 → 开启 OIDC → 添加 redirect URI:
#      http://localhost:3000/callback.html
#    复制 Client ID

# 2. 在本地
cd my-auth-app-oidc
# 编辑 config.js，把 PUT_YOUR_CLIENT_ID_HERE 改为你刚才复制的 Client ID

# 3. 启动
npm start
```

打开 http://localhost:3000

## 工作原理

```
用户点击 [用 AuthCore 登录]
   ↓ window.location → auth.miaogou.site/oauth/authorize?...&code_challenge=...
   ↓ 用户登录 / 同意授权
   ↓ 302 → http://localhost:3000/callback.html?code=...&state=...
callback.html 自动执行：
   ↓ POST auth.miaogou.site/oauth/token (code + PKCE verifier)
   ↓ 拿到 id_token (RS256) + access_token + refresh_token
   ↓ 写入 sessionStorage
   → dashboard.html 显示用户信息
```

## 文件结构

```
my-auth-app-oidc/
├── package.json
├── config.js               # Client ID / Redirect URI
├── index.html              # 登录按钮
├── callback.html           # 处理 code 交换
├── dashboard.html          # 展示 UserInfo
├── css/style.css
└── js/oidc.js              # vendored OidcClient（含 PKCE）
```

## 部署到生产

把所有静态文件上传到任意 CDN（Cloudflare Pages / Vercel / Netlify / 阿里云 OSS 静态托管）。
**注意把控制台 redirect URI 改为生产域名**，例如：
- 开发：`http://localhost:3000/callback.html`
- 生产：`https://your-app.com/callback.html`

可以同时登记多个 redirect URI（每行一条）。

## 常见问题

**点登录后报错 "invalid_redirect_uri"**
控制台白名单严格精确匹配。检查协议（https vs http）、端口、路径、是否带 `.html` 后缀。

**报错 "invalid_grant: pkce required for public clients"**
公开客户端（未配 Client Secret）必须用 PKCE。本模板默认 PKCE S256。

**id_token 验证报 "nonce_mismatch"**
浏览器关掉了 sessionStorage 或换了浏览器标签。重试登录。

**想用机密客户端（带 Client Secret）**
在控制台编辑应用 → 生成 Client Secret → 在 `config.js` 添加 `clientSecret: '...'`。**注意 Client Secret 不能直接放浏览器**（会被任何人看到），建议机密客户端只在你的服务端用。

## 参考

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE (RFC 7636)](https://www.rfc-editor.org/rfc/rfc7636)
- AuthCore 文档: https://auth.miaogou.site/docs
