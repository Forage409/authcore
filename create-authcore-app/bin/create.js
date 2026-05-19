#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { execSync } = require('child_process');

const args = process.argv.slice(2);
const projectName = args.find(a => !a.startsWith('-'));
const modeArg = args.find(a => a.startsWith('--mode='));

const CLI_VERSION = require('../package.json').version;
// 匿名遵测（脱敏 · 可关 · 节流） — 见 https://auth.miaogou.site/docs#telemetry
let _telemetry = null;
try { _telemetry = require('./_telemetry'); } catch {}

if (!projectName) {
  console.log('用法: npx create-nexus-auth <项目名> [--mode=full|oidc]');
  console.log('示例:');
  console.log('  npx create-nexus-auth my-auth-app              # 交互式选择');
  console.log('  npx create-nexus-auth my-auth-app --mode=full    # 完整模式（密码注册 + OIDC SSO，含 Express 后端）');
  console.log('  npx create-nexus-auth my-app --mode=oidc         # 纯 OIDC SSO（无后端纯静态 SPA）');
  process.exit(1);
}

function ask(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => { rl.close(); resolve(answer.trim().toLowerCase()); });
  });
}

async function pickMode() {
  if (modeArg) {
    const m = modeArg.split('=')[1];
    if (!['full', 'oidc'].includes(m)) {
      console.error('错误: --mode 只能是 full 或 oidc');
      process.exit(1);
    }
    return m;
  }
  console.log('');
  console.log('选择项目类型：');
  console.log('  1) 完整项目 — 邮箱密码注册 + OIDC 单点登录，含 Express 后端');
  console.log('     (适用场景：有 Node 服务器，需要完整认证流程)');
  console.log('  2) 纯 OIDC 前端 — 仅 OIDC SSO 登录按钮，无后端，纯静态 SPA');
  console.log('     (适用场景：仅需"用 AuthCore 登录"按钮，无自有服务器)');
  console.log('');
  const ans = await ask('输入 1 或 2（默认 1）：');
  if (ans === '2') return 'oidc';
  // 默认走完整模式：密码 + OIDC 一体化
  if (ans === '1' || ans === 'full' || ans === '' || ans === 'no' || ans === 'n') return 'full';
  // 输入了 yes / y / oidc —— 视为纯 OIDC
  if (ans === 'yes' || ans === 'y' || ans === 'oidc') return 'oidc';
  return 'full';
}

function copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src)) {
    const srcPath = path.join(src, entry);
    const destPath = path.join(dest, entry);
    if (fs.statSync(srcPath).isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

(async function main() {
  // Node version check
  const v = parseInt(process.version.slice(1));
  if (v < 18) {
    console.error('错误: 需要 Node.js 18 或更高版本');
    process.exit(1);
  }

  const targetDir = path.resolve(projectName);
  if (fs.existsSync(targetDir)) {
    console.error(`错误: 目录 "${projectName}" 已存在`);
    process.exit(1);
  }

  const mode = await pickMode();
  if (_telemetry) { try { _telemetry.fire(CLI_VERSION, mode); } catch {} }
  const templateDir = path.resolve(__dirname, '..', mode === 'oidc' ? 'template-oidc' : 'template');

  console.log(`创建 AuthCore 项目: ${projectName}（${mode === 'oidc' ? '纯 OIDC 前端' : '完整模式（密码 + OIDC）'}）...`);
  try {
    copyDir(templateDir, targetDir);
  } catch (e) {
    console.error('复制模板失败:', e.message);
    process.exit(1);
  }

  if (mode === 'full') {
    console.log('安装依赖...');
    try {
      execSync('npm install', { cwd: path.join(targetDir, 'backend'), stdio: 'inherit' });
    } catch (e) {
      console.error('npm install 失败，请检查网络或手动运行: cd ' + projectName + '/backend && npm install');
      process.exit(1);
    }
    try { fs.chmodSync(path.join(targetDir, 'start.sh'), 0o755); } catch (_) {}
  }

  const isWin = process.platform === 'win32';
  if (mode === 'oidc') {
  console.log(`
项目已创建：${projectName}（纯 OIDC 前端）

下一步（按顺序复制粘贴）：

   [1/3] 去控制台拿 Client ID
         打开 https://auth.miaogou.site → 注册账号 → 新建 SPA 应用
         Redirect URI 填: http://localhost:3000/callback.html
         复制生成的 Client ID（一串 UUID）

   [2/3] 编辑 ${projectName}/config.js
         把 PUT_YOUR_CLIENT_ID_HERE 替换为你刚复制的 Client ID

   [3/3] 启动
         cd ${projectName}
         npm install
         npm start

然后浏览器打开 http://localhost:3000

文件结构：
   config.js / index.html / callback.html / dashboard.html / css/style.css / js/oidc.js
`);
  } else {
    console.log(`
项目已创建：${projectName}（完整模式：密码注册 + OIDC SSO）

下一步（按顺序复制粘贴）：

   [1/3] 去控制台拿 API Key
         打开 https://auth.miaogou.site → 注册账号 → 新建后端应用
         复制生成的 API Key（一串 nx_ 开头的字符串）

   [2/3] 编辑 ${projectName}/backend/.env
         把 AUTHCORE_API_KEY=nx_your_api_key_here 改成你刚复制的 Key

   [3/3] 启动
         cd ${projectName}
         ${isWin ? 'start.bat' : './start.sh'}     （或：npm start）

然后浏览器打开 http://localhost:3000

模板已为你内置两种登录方式：
   - 邮箱密码注册/登录（开箱即用）
   - OIDC 一键登录（在控制台为应用开启 OIDC + 加 Redirect URI
                     http://localhost:3000/oidc/callback 即可自动激活按钮）
`);
  }
})();
