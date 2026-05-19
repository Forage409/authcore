#!/usr/bin/env node
// 举报审核 CLI — AI 审核员的统一入口
// 用法见末尾 printHelp()
//
// 依赖：本机已 wrangler login（用于 D1 读写）
// 发邮件场景：POST 到 Worker 现成端点，Worker 用它自己的 RESEND_API_KEY 发
//             需要一个 admin JWT（从 auth.miaogou.site 登录后浏览器抠出）

import { execSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const GATEWAY_DIR = resolve(SCRIPT_DIR, '../nexus-gateway');

// 从 workers/scripts/.env 加载 RESEND_API_KEY / PLATFORM_OWNERS（gitignored）
const ENV_FILE = resolve(SCRIPT_DIR, '.env');
if (existsSync(ENV_FILE)) {
  for (const line of readFileSync(ENV_FILE, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.*)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
}

const PLATFORM_OWNERS = new Set(
  (process.env.PLATFORM_OWNERS || 'lapd0897@gmail.com')
    .split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
);

// ───── D1 工具 ─────
function d1(sql) {
  const flat = sql.replace(/\s+/g, ' ').trim();
  const cmd = `npx wrangler d1 execute nexus-db --remote --json --command ${JSON.stringify(flat)}`;
  let out;
  try {
    out = execSync(cmd, { cwd: GATEWAY_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    const stderr = e.stderr?.toString() || e.message;
    throw new Error(`wrangler 失败：${stderr.slice(0, 500)}`);
  }
  // wrangler 输出常含横幅+JSON，截取首个 [ 到末尾 ]
  const m = out.match(/\[[\s\S]*\]\s*$/);
  if (!m) throw new Error(`wrangler 输出未含 JSON：${out.slice(0, 300)}`);
  const parsed = JSON.parse(m[0]);
  const block = Array.isArray(parsed) ? parsed[0] : parsed;
  return block?.results || [];
}

function d1Exec(sql) { d1(sql); }

// SQL 字面量转义（参数化在 wrangler CLI 不可用 → 必须严格转义）
function sq(v) {
  if (v === null || v === undefined) return 'NULL';
  return `'${String(v).replace(/'/g, "''")}'`;
}

// ───── 解析 id 前缀 → 完整 id ─────
function resolveId(prefix) {
  if (!prefix) die('需要提供举报 ID 或前缀');
  const rows = d1(`SELECT id FROM abuse_reports WHERE id LIKE ${sq(prefix + '%')}`);
  if (rows.length === 0) die(`未找到匹配 "${prefix}" 的举报`);
  if (rows.length > 1) die(`前缀 "${prefix}" 匹配到 ${rows.length} 条，请提供更长前缀`);
  return rows[0].id;
}

// ───── 命令：list ─────
function cmdList() {
  const rows = d1(`
    SELECT id, category, target_type, target_id, substr(description,1,60) AS desc_short,
           reporter_email, created_at
    FROM abuse_reports WHERE status='pending'
    ORDER BY CASE category WHEN 'csam' THEN 0 WHEN 'illegal' THEN 1 WHEN 'phishing' THEN 2 ELSE 9 END,
             created_at DESC
  `);
  if (rows.length === 0) { console.log('待办队列为空'); return; }
  console.log(`待办 ${rows.length} 条：\n`);
  for (const r of rows) {
    console.log(`  ${r.id.slice(0, 8)}  [${r.category}] ${r.target_type} → ${r.target_id.slice(0, 50)}`);
    console.log(`    描述: ${r.desc_short || '(空)'}`);
    console.log(`    举报人: ${r.reporter_email}  时间: ${r.created_at}\n`);
  }
}

// ───── 命令：show ─────
function cmdShow(prefix) {
  const id = resolveId(prefix);
  const rows = d1(`SELECT * FROM abuse_reports WHERE id=${sq(id)}`);
  const r = rows[0];
  console.log('=== 举报详情 ===');
  for (const [k, v] of Object.entries(r)) console.log(`  ${k}: ${v ?? '(null)'}`);

  // 取证：按 target_type 查对应表
  console.log('\n=== 取证 ===');
  try {
    if (r.target_type === 'content_url') {
      const m = r.target_id.match(/\/(posts|guestbook)\/([0-9a-f-]+)/i);
      if (m) {
        const table = m[1] === 'posts' ? 'posts' : 'guestbook';
        const ev = d1(`SELECT * FROM ${table} WHERE id=${sq(m[2])}`);
        console.log(ev[0] ? JSON.stringify(ev[0], null, 2) : '目标内容不存在（可能已删除）');
      } else {
        console.log('URL 无法解析为本站资源：', r.target_id);
      }
    } else if (r.target_type === 'api_key') {
      const ev = d1(`SELECT id, name, user_email, status, created_at FROM api_keys WHERE id=${sq(r.target_id)}`);
      console.log(ev[0] ? JSON.stringify(ev[0], null, 2) : `api_keys 中无 id=${r.target_id} 的记录（target 非法）`);
    } else if (r.target_type === 'user') {
      const ev = d1(`SELECT 'users' AS src, id, email FROM users WHERE id=${sq(r.target_id)} OR email=${sq(r.target_id)}
        UNION ALL SELECT 'gateway_users' AS src, id, email FROM gateway_users WHERE id=${sq(r.target_id)} OR email=${sq(r.target_id)}`);
      console.log(ev.length ? JSON.stringify(ev, null, 2) : '未找到对应用户');
    } else {
      console.log(`target_type=${r.target_type} 不支持自动取证`);
    }
  } catch (e) { console.log('取证失败:', e.message); }

  // 查重：同 target 是否有别的举报
  console.log('\n=== 同 target 历史举报 ===');
  const dups = d1(`SELECT id, status, category, resolved_at FROM abuse_reports
                   WHERE target_id=${sq(r.target_id)} AND id!=${sq(id)}
                   ORDER BY created_at DESC LIMIT 5`);
  console.log(dups.length ? JSON.stringify(dups, null, 2) : '无');
}

// ───── 命令：resolve ─────
async function cmdResolve(prefix, status, note) {
  if (!['resolved', 'rejected', 'duplicate'].includes(status)) {
    die('status 必须是 resolved / rejected / duplicate');
  }
  if (!note || note.length < 5) die('note 必填且至少 5 字符（会发给举报人）');
  const id = resolveId(prefix);

  const cur = d1(`SELECT id, status, reporter_email, category, description FROM abuse_reports WHERE id=${sq(id)}`)[0];
  if (cur.status !== 'pending') die(`该举报已是 ${cur.status} 状态，不能重复处理`);

  const operator = (process.env.ABUSE_OPERATOR || 'ai-moderator').toLowerCase();
  const reporter = (cur.reporter_email || '').toLowerCase();
  const isSelf = reporter && PLATFORM_OWNERS.has(reporter);

  // 两条路径：
  //   A) 无需邮件（站长自测 / 无邮箱）→ D1 直写，零外部依赖
  //   B) 需要邮件 → POST 到 Worker 现成端点，Worker 用自己的 RESEND_API_KEY 发
  if (!reporter || isSelf) {
    const emailStatus = !reporter ? 'no_email' : 'skipped_self_test';
    d1Exec(`UPDATE abuse_reports SET
      status=${sq(status)}, resolved_by=${sq(operator)},
      resolved_at=datetime('now','+8 hours'),
      resolution_note=${sq(note.slice(0, 500))},
      email_status=${sq(emailStatus)}
      WHERE id=${sq(id)} AND status='pending'`);
    console.log(`OK  ${id.slice(0, 8)} -> ${status}  email: ${emailStatus} (本地直写)`);
    return;
  }

  // 真实用户 → 走 Worker HTTP（Worker 会自动 UPDATE 状态 + 发邮件 + 写 email_status）
  const jwt = process.env.ADMIN_JWT;
  if (!jwt) die('真实用户举报需发邮件，请先在 workers/scripts/.env 设 ADMIN_JWT（从 auth.miaogou.site 登录后浏览器开发者工具抠出 access_token）');
  const resp = await fetch(`https://auth.miaogou.site/api/admin/abuse/${id}/resolve`, {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + jwt, 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, note: note.slice(0, 500) }),
  });
  if (!resp.ok) {
    const txt = await resp.text().catch(() => '');
    die(`Worker 拒绝（HTTP ${resp.status}）：${txt.slice(0, 200)}`);
  }
  // 等 200ms 让 waitUntil 跑完，然后读 D1 看邮件结果
  await new Promise(r => setTimeout(r, 1500));
  const after = d1(`SELECT email_status, email_sent_at, email_last_error FROM abuse_reports WHERE id=${sq(id)}`)[0];
  console.log(`OK  ${id.slice(0, 8)} -> ${status}  email: ${after?.email_status || '(pending)'}${after?.email_last_error ? ' err=' + after.email_last_error : ''}`);
}

// ───── 命令：retry ─────（调 Worker 的 /api/admin/abuse/notify，复用其邮件发送逻辑）
async function cmdRetry(prefix) {
  const id = resolveId(prefix);
  const r = d1(`SELECT status, reporter_email, email_status FROM abuse_reports WHERE id=${sq(id)}`)[0];
  if (r.status === 'pending') die('该举报尚未处理，先 resolve');
  if (!r.reporter_email) die('举报人未留邮箱，无法发送');
  if (r.email_status === 'sent') die('邮件已发送过，无需重发');

  const jwt = process.env.ADMIN_JWT;
  if (!jwt) die('需要 ADMIN_JWT（见 workers/scripts/.env.example）');
  const resp = await fetch('https://auth.miaogou.site/api/admin/abuse/notify', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + jwt, 'Content-Type': 'application/json' },
    body: JSON.stringify({ report_id: id }),
  });
  if (!resp.ok) { const t = await resp.text().catch(() => ''); die(`Worker 拒绝 HTTP ${resp.status}: ${t.slice(0,200)}`); }
  const after = await resp.json().catch(() => ({}));
  console.log(`${id.slice(0,8)} email -> ${after?.email_status || '(unknown)'}${after?.email_last_error ? ' err=' + after.email_last_error : ''}`);
}

// ───── 命令：stats ─────
function cmdStats() {
  const overall = d1(`SELECT status, COUNT(*) AS n FROM abuse_reports GROUP BY status`);
  const emails = d1(`SELECT COALESCE(email_status,'(null)') AS s, COUNT(*) AS n FROM abuse_reports WHERE status!='pending' GROUP BY email_status`);
  console.log('举报状态：'); for (const r of overall) console.log(`  ${r.status.padEnd(12)} ${r.n}`);
  console.log('\n邮件状态（已处理）：'); for (const r of emails) console.log(`  ${r.s.padEnd(20)} ${r.n}`);
}

function die(msg) { console.error('错误：' + msg); process.exit(1); }

function printHelp() {
  console.log(`举报审核 CLI

  node workers/scripts/abuse.mjs list                          列出待办
  node workers/scripts/abuse.mjs show <id-prefix>              详情 + 取证 + 查重
  node workers/scripts/abuse.mjs resolve <id-prefix> <status> "<note>"
                                                               status: resolved | rejected | duplicate
                                                               note 会发给举报人（站长自测自动跳过邮件）
  node workers/scripts/abuse.mjs retry <id-prefix>             重发失败的邮件
  node workers/scripts/abuse.mjs stats                         统计

环境变量（放 workers/scripts/.env）：
  PLATFORM_OWNERS=a@x.com,b@y.com 站长邮箱，本人提交的举报自动跳过邮件
  ABUSE_OPERATOR=ai-moderator     resolved_by 写入值（审计用）
  ADMIN_JWT=eyJhbGci...           仅当处理"真实用户举报"需要发邮件时必填
                                  从 auth.miaogou.site 登录后开发者工具 LocalStorage 抠出
                                  Worker 会用它自己的 RESEND_API_KEY 发邮件，本地不存 Resend Key
`);
}

// ───── 入口 ─────
const [, , cmd, ...args] = process.argv;
try {
  if (cmd === 'list') cmdList();
  else if (cmd === 'show') cmdShow(args[0]);
  else if (cmd === 'resolve') await cmdResolve(args[0], args[1], args[2]);
  else if (cmd === 'retry') await cmdRetry(args[0]);
  else if (cmd === 'stats') cmdStats();
  else printHelp();
} catch (e) {
  console.error('执行失败：', e?.message || e);
  process.exit(1);
}
