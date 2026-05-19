/**
 * AuthCore SDK 匿名遵测（ESM 版） — 与 _telemetry.js 完全等价的实现
 * 见 _telemetry.js 顶部注释：收集字段、不收集字段、3 种关闭方式。
 */
import os from 'node:os';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

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
  } catch {}
  return false;
}

export function hashApiKey(apiKey) {
  if (!apiKey || typeof apiKey !== 'string') return '';
  try { return crypto.createHash('sha256').update(apiKey).digest('hex').slice(0, 16); }
  catch { return ''; }
}

export function fireTelemetry(sdkName, sdkVersion, apiKey) {
  if (isOptedOut()) return;
  if (shouldThrottle()) return;
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

export { isOptedOut };
