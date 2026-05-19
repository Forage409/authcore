/**
 * create-nexus-auth CLI 匿名遵测
 * 与 nexus-auth-sdk/_telemetry.js 同语义、同关闭开关、同节流策略。
 * 设计原则、关闭方式（NEXUS_AUTH_TELEMETRY_DISABLED / DO_NOT_TRACK / CI）见
 * https://auth.miaogou.site/docs#telemetry
 */
const os = require('os');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ENDPOINT = 'https://auth.miaogou.site/telemetry/v1/active';
const THROTTLE_MS = 24 * 60 * 60 * 1000;
const CACHE_FILE = path.join(os.tmpdir(), '.nexus-auth-cli-tel');

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
    return crypto.createHash('sha256').update(macs.join('|') + '|' + (os.hostname() || '')).digest('hex').slice(0, 32);
  } catch { return 'anonymous'; }
}

function shouldThrottle() {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      const last = parseInt(fs.readFileSync(CACHE_FILE, 'utf8'), 10);
      if (Number.isFinite(last) && Date.now() - last < THROTTLE_MS) return true;
    }
    fs.writeFileSync(CACHE_FILE, String(Date.now()));
  } catch {}
  return false;
}

function fire(cliVersion, mode) {
  if (isOptedOut()) return;
  if (shouldThrottle()) return;
  if (typeof fetch !== 'function') return;
  const payload = {
    device_id: getDeviceId(),
    os: process.platform || '',
    os_version: (() => { try { return os.release(); } catch { return ''; } })(),
    runtime: 'node-' + (process.version || ''),
    sdk_name: 'create-nexus-auth' + (mode ? ':' + mode : ''),
    sdk_version: cliVersion,
  };
  try {
    setImmediate(() => {
      try {
        fetch(ENDPOINT, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          signal: (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) ? AbortSignal.timeout(4000) : undefined,
        }).catch(() => {});
      } catch {}
    });
  } catch {}
}

module.exports = { fire, isOptedOut };
