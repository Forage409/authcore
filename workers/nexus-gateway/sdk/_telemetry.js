/**
 * AuthCore SDK 匿名遵测（Node 端） — 仅统计活跃用户，从不收集隐私
 *
 * 收集字段：
 *   - device_id：sha256(MAC 地址列表 + hostname) 前 32 位（无 PII，跨 SDK 安装可被关联但无法反查个人）
 *   - os：darwin / linux / win32 / freebsd / ...
 *   - os_version：os.release()（如 "10.0.19045"）
 *   - runtime：node-<version>
 *   - sdk_name + sdk_version
 *   - app_hash：sha256(apiKey) 前 16 位（可选；只让我们按"哪个应用接入"聚合，不可逆）
 *
 * 不收集：
 *   - IP 地址（HTTPS 仅在路由层透传，服务端不入库）
 *   - 操作系统用户名 / home 目录
 *   - 代码路径 / 进程命令行
 *   - API Key 原文
 *
 * 三种关闭方式（任一生效即不发送）：
 *   1) 环境变量 NEXUS_AUTH_TELEMETRY_DISABLED=1
 *   2) 环境变量 DO_NOT_TRACK=1（业界标准）
 *   3) 环境变量 CI 非空（GitHub Actions / GitLab CI / CircleCI 等均会自动设置）
 *
 * 客户端节流：os.tmpdir() 下 .nexus-auth-tel 文件，24 小时内每设备只发一次。
 *
 * fire-and-forget：完全异步，不 await、不抛错，绝不影响调用方业务。
 */
const os = require('os');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ENDPOINT = 'https://auth.miaogou.site/telemetry/v1/active';
const THROTTLE_MS = 24 * 60 * 60 * 1000;
const CACHE_FILE = path.join(os.tmpdir(), '.nexus-auth-tel');

function isOptedOut() {
  if (process.env.NEXUS_AUTH_TELEMETRY_DISABLED && process.env.NEXUS_AUTH_TELEMETRY_DISABLED !== '0') return true;
  if (process.env.DO_NOT_TRACK && process.env.DO_NOT_TRACK !== '0') return true;
  if (process.env.CI && process.env.CI !== 'false' && process.env.CI !== '0') return true;
  return false;
}

function getDeviceId() {
  try {
    const ifaces = os.networkInterfaces();
    const macs = [];
    for (const arr of Object.values(ifaces || {})) {
      for (const iface of (arr || [])) {
        if (iface.mac && iface.mac !== '00:00:00:00:00:00') macs.push(iface.mac);
      }
    }
    macs.sort();
    const stable = macs.join('|') + '|' + (os.hostname() || '');
    return crypto.createHash('sha256').update(stable).digest('hex').slice(0, 32);
  } catch { return 'anonymous'; }
}

function shouldThrottle() {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      const last = parseInt(fs.readFileSync(CACHE_FILE, 'utf8'), 10);
      if (Number.isFinite(last) && Date.now() - last < THROTTLE_MS) return true;
    }
    fs.writeFileSync(CACHE_FILE, String(Date.now()));
  } catch { /* tmp 写不进去也忽略，发就发了 */ }
  return false;
}

function hashApiKey(apiKey) {
  if (!apiKey || typeof apiKey !== 'string') return '';
  try { return crypto.createHash('sha256').update(apiKey).digest('hex').slice(0, 16); }
  catch { return ''; }
}

function fireTelemetry(sdkName, sdkVersion, apiKey) {
  if (isOptedOut()) return;
  if (shouldThrottle()) return;
  // Node 18+ 自带 fetch；旧版本静默忽略（用户大概率也跑不起 ESM Worker SDK）
  if (typeof fetch !== 'function') return;
  const payload = {
    device_id: getDeviceId(),
    os: process.platform || '',
    os_version: (() => { try { return os.release(); } catch { return ''; } })(),
    runtime: 'node-' + (process.version || ''),
    sdk_name: sdkName,
    sdk_version: sdkVersion,
    app_hash: hashApiKey(apiKey),
  };
  // setImmediate 让出主线程，确保不阻塞调用方构造函数返回
  try {
    setImmediate(() => {
      try {
        fetch(ENDPOINT, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          // 4 秒超时避免长时间挂起
          signal: (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) ? AbortSignal.timeout(4000) : undefined,
        }).catch(() => {});
      } catch { /* silent */ }
    });
  } catch { /* silent */ }
}

module.exports = { fireTelemetry, hashApiKey, isOptedOut };
