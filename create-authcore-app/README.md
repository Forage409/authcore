# create-nexus-auth

一键创建 AuthCore 认证应用 — 密码注册 + OIDC 单点登录 + Express 后端转发层。零外部私有依赖，开箱即用。

## 快速开始

```bash
npx create-nexus-auth my-auth-app
cd my-auth-app
# 编辑 backend/.env，把 AUTHCORE_API_KEY 换成你的真实 Key
# 然后一键启动：
./start.sh         # Mac / Linux
# 或者
start.bat          # Windows
# 或者跨平台通用：
npm start
```

打开 http://localhost:3000

## 模式选择

| 模式 | 命令 | 说明 |
|------|------|------|
| 完整模式（推荐） | `npx create-nexus-auth my-app` 或 `--mode=full` | 密码注册 + OIDC SSO，含 Express 后端 |
| 纯 OIDC 前端 | `npx create-nexus-auth my-app --mode=oidc` | 仅"用 AuthCore 登录"按钮，纯静态 SPA，无后端 |

完整模式下，登录页已内置 OIDC 一键登录按钮：只需在控制台为应用启用 OIDC 并配置 Redirect URI，前端会自动检测并显示按钮，无需额外编码。

## 前置条件

1. Node.js 18+
2. 在 [auth.miaogou.site](https://auth.miaogou.site) 注册并创建应用获取 API Key（`nx_` 前缀）

## 项目结构

```
my-auth-app/
├── package.json        # 根工程，提供 `npm start` 一键启动
├── start.bat           # Windows 一键启动（自动检查 .env / 安装依赖 / 启动）
├── start.sh            # Mac/Linux 一键启动
├── backend/
│   ├── server.js       # Express 转发层
│   ├── .env            # 你的 API Key
│   ├── package.json
│   └── lib/
│       └── authcore.js # SDK (vendored，无需外部依赖)
└── frontend/
    ├── index.html      # 登录页
    ├── register.html   # 注册页
    ├── dashboard.html  # 仪表盘
    ├── css/style.css
    └── js/app.js
```

## 启动方式（三选一）

| 命令 | 说明 |
|---|---|
| `./start.sh` / `start.bat` | 一键脚本：检查 `.env`、按需安装依赖、启动 |
| `npm start` | 根目录运行；等价于 `npm start --prefix backend` |
| `cd backend && npm start` | 直接进 backend 跑 |

`npx create-nexus-auth` 会在创建过程中自动 `npm install backend` 依赖一次，所以默认你只需要填 `.env` 然后启动。

## 工作原理

```
用户浏览器 (frontend/*.html)
    ↓ POST /api/user/login (邮箱+密码)
你的后端 server.js
    ↓ 带 X-API-Key 转发
AuthCore 网关 (auth.miaogou.site)
    ↓ 返回 JWT + refreshToken
你的后端 → 前端 → localStorage → 进入仪表盘
```

## 常见问题

**启动报错 `authcore.js not found`**
确认目录结构正确，`backend/lib/authcore.js` 存在。

**登录提示 API Key 无效**
检查 `backend/.env` 的 `AUTHCORE_API_KEY` 是否正确（`nx_` 前缀）。

**端口被占用**
修改 `backend/.env` 的 `PORT` 为其他值。

**`start.sh: Permission denied`**
执行 `chmod +x start.sh` 后重试（macOS / Linux）。

**`./start.sh` 在 PowerShell 报错**
PowerShell 用 `./start.sh` 调用 bash 可能失败，改用 `npm start` 或 `start.bat`。

## 部署到生产环境

项目和依赖均在本地运行。部署到云服务时：

1. 设置环境变量 `AUTHCORE_API_KEY`（不要把 `.env` 提交到公开仓库）
2. 上传 `backend/` 与 `frontend/` 到服务器
3. `npm install --prefix backend && npm start`，或用 PM2 / Docker / systemd

## 模板版本

当前模板对应：
- 网关 (auth.miaogou.site) v4.5
- vendored SDK 与官方 `nexus-auth-sdk@4.5` 行为对齐（自动检测邮箱验证开关、社区邮件配额降级）
