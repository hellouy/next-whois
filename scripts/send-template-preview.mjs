/**
 * One-shot script: send all email templates to a target address.
 * Reads RESEND_API_KEY from DB (site_settings) or environment.
 * Usage: node scripts/send-template-preview.mjs [to@email.com]
 */

import { createRequire } from "module";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import pg from "pg";

const __dirname = dirname(fileURLToPath(import.meta.url));
const { Pool }  = pg;

const ADMIN_RECIPIENT = process.argv[2] || "9208522@qq.com";
const SITE_NAME       = "X.RW";

// ── DB connect ─────────────────────────────────────────────────────────────
const dbUrl = process.env.POSTGRES_URL_NON_POOLING
           || process.env.POSTGRES_URL
           || process.env.DATABASE_URL;

if (!dbUrl) {
  console.error("No DB URL found in environment");
  process.exit(1);
}

function stripSslMode(url) {
  try { const u = new URL(url); u.searchParams.delete("sslmode"); return u.toString(); }
  catch { return url; }
}
const pool = new Pool({ connectionString: stripSslMode(dbUrl), ssl: { rejectUnauthorized: false }, max: 2 });

// ── read mail config from site_settings ───────────────────────────────────
const { rows: settingRows } = await pool.query(
  `SELECT key, value FROM site_settings WHERE key IN
   ('resend_api_key','resend_from_email','smtp_enabled','smtp_host','smtp_port','smtp_user','smtp_pass','smtp_from','smtp_secure')`
).catch(() => ({ rows: [] }));

const cfg = {};
for (const r of settingRows) cfg[r.key] = r.value;

const RESEND_KEY  = cfg.resend_api_key    || process.env.RESEND_API_KEY    || "";
const RESEND_FROM = cfg.resend_from_email || process.env.RESEND_FROM_EMAIL || "onboarding@resend.dev";
const SMTP_ACTIVE = !!(cfg.smtp_enabled && cfg.smtp_host && cfg.smtp_user && cfg.smtp_pass);

if (!RESEND_KEY && !SMTP_ACTIVE) {
  console.error("❌  No email provider configured (no resend_api_key in site_settings and no SMTP)");
  await pool.end();
  process.exit(1);
}

console.log(`\n📧  Email provider: ${SMTP_ACTIVE ? "SMTP" : "Resend"}`);
console.log(`    Sending all template previews → ${ADMIN_RECIPIENT}\n`);

// ── send via Resend ────────────────────────────────────────────────────────
async function sendRaw(to, subject, html) {
  if (SMTP_ACTIVE) {
    // dynamic import of nodemailer
    const nm = (await import("nodemailer")).default;
    const transporter = nm.createTransport({
      host: cfg.smtp_host,
      port: parseInt(cfg.smtp_port || "465"),
      secure: (cfg.smtp_secure || "ssl") === "ssl",
      requireTLS: (cfg.smtp_secure || "ssl") === "starttls",
      auth: { user: cfg.smtp_user, pass: cfg.smtp_pass },
      tls: { rejectUnauthorized: false },
    });
    await transporter.sendMail({ from: cfg.smtp_from || cfg.smtp_user, to, subject, html });
    return;
  }
  // Resend
  const tryFrom = async (from) => {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${RESEND_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from, to, subject, html }),
    });
    if (res.ok) return true;
    const body = await res.text().catch(() => "");
    if (res.status === 403 && body.includes("not verified") && from !== "onboarding@resend.dev") {
      return false; // try fallback
    }
    throw new Error(`Resend ${res.status}: ${body.slice(0, 200)}`);
  };
  if (!(await tryFrom(RESEND_FROM))) {
    await tryFrom("onboarding@resend.dev");
  }
}

// ── simple HTML template builder ──────────────────────────────────────────
function tpl(headerBg, label, title, body) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<table cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;margin:0 auto">
  <tr><td style="background:${headerBg};padding:32px;border-radius:12px 12px 0 0">
    <p style="margin:0 0 6px;font-size:10px;font-weight:700;letter-spacing:2px;color:rgba(255,255,255,.6);text-transform:uppercase">${label}</p>
    <h1 style="margin:0;font-size:22px;font-weight:800;color:#fff">${title}</h1>
  </td></tr>
  <tr><td style="background:#fff;padding:32px;border-radius:0 0 12px 12px">
    ${body}
    <hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">
    <p style="margin:0;font-size:11px;color:#94a3b8">此为 ${SITE_NAME} 邮件模版预览，发送时间：${new Date().toLocaleString("zh-CN",{timeZone:"Asia/Shanghai"})}</p>
  </td></tr>
</table>
</body></html>`;
}

// ── template list ─────────────────────────────────────────────────────────
const now     = new Date();
const tsStr   = now.toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" });
const expDate = new Date(now.getTime() + 30  * 86400 * 1000).toLocaleDateString("zh-CN");
const dropDt  = new Date(now.getTime() + 7   * 86400 * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" });
const expYear = new Date(now.getTime() + 365 * 86400 * 1000).toLocaleDateString("zh-CN");

const TEMPLATES = [
  { key: "welcome",
    subject: `[预览] 欢迎加入 ${SITE_NAME}`,
    html: tpl("#0f172a","欢迎","欢迎加入 X.RW！",`
      <p style="color:#475569;line-height:1.8">亲爱的 <strong>管理员</strong>，欢迎注册 ${SITE_NAME}！</p>
      <div style="border:1px solid #e2e8f0;border-radius:12px;padding:20px;margin:16px 0">
        <p style="margin:0 0 8px;font-size:11px;font-weight:700;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">快速开始</p>
        <p style="margin:0;font-size:13px;color:#475569">① 搜索并查询域名 WHOIS 信息</p>
        <p style="margin:6px 0;font-size:13px;color:#475569">② 添加域名监控，获取到期提醒</p>
        <p style="margin:0;font-size:13px;color:#475569">③ 设置通知邮件偏好</p>
      </div>
    `)},

  { key: "subscription",
    subject: `[预览] 域名监控已开启 — example.com`,
    html: tpl("#7c3aed","订阅确认","域名监控已激活",`
      <div style="background:#f0fdf4;border:2px solid #86efac;border-radius:10px;padding:16px;text-align:center;margin-bottom:20px">
        <p style="margin:0;font-size:14px;font-weight:700;color:#15803d">✅ 监控已开启</p>
      </div>
      <p style="color:#475569;line-height:1.8">您已成功订阅 <strong>example.com</strong> 的到期提醒。</p>
      <p style="color:#475569">到期日期：<strong>${expDate}</strong> &nbsp;·&nbsp; 提醒周期：7 / 14 / 30 天前</p>
    `)},

  { key: "reminder",
    subject: `[预览] example.com 将在 30 天后到期`,
    html: tpl("#7c3aed","到期提醒","您的域名即将到期",`
      <div style="text-align:center;padding:20px 0">
        <div style="font-size:72px;font-weight:900;color:#7c3aed;line-height:1">30</div>
        <p style="margin:4px 0 0;color:#64748b;font-size:14px">天后到期</p>
      </div>
      <p style="color:#475569;text-align:center">域名 <strong>example.com</strong> 将于 <strong>${expDate}</strong> 到期，请及时续费以避免服务中断。</p>
      <div style="background:#f5f3ff;border:1px solid #ddd6fe;border-radius:8px;padding:14px;margin-top:16px">
        <p style="margin:0;color:#7c3aed;font-size:13px">💡 续费建议：建议提前至少 7 天完成续费，避免因处理时间导致域名过期。</p>
      </div>
    `)},

  { key: "phase_grace",
    subject: `[预览] example.com 已进入宽限期`,
    html: tpl("#d97706","宽限期通知","域名已进入宽限期",`
      <p style="color:#475569;line-height:1.8"><strong>example.com</strong> 已到期，现处于宽限期（约 45 天）。</p>
      <div style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:16px">
        <p style="margin:0 0 8px;font-size:12px;font-weight:700;color:#92400e">建议操作：</p>
        <p style="margin:0;color:#92400e;font-size:13px;line-height:1.8">① 立即联系注册商完成续费<br>② 确认域名所有权文件完整<br>③ 备份与该域名相关的所有数据</p>
      </div>
    `)},

  { key: "phase_redemption",
    subject: `[预览] example.com 已进入赎回期`,
    html: tpl("#dc2626","赎回期通知","域名已进入赎回期",`
      <p style="color:#475569;line-height:1.8"><strong>example.com</strong> 正处于赎回期，可通过注册商以较高费用赎回。</p>
      <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:16px">
        <p style="margin:0 0 8px;font-size:12px;font-weight:700;color:#991b1b">建议操作：</p>
        <p style="margin:0;color:#991b1b;font-size:13px;line-height:1.8">① 立即联系注册商询问赎回价格<br>② 综合评估域名商业价值<br>③ 如决定赎回，尽快提交申请</p>
      </div>
    `)},

  { key: "phase_pending",
    subject: `[预览] example.com 即将被彻底删除`,
    html: tpl("#7f1d1d","待删除通知","域名即将被删除",`
      <p style="color:#475569;line-height:1.8"><strong>example.com</strong> 已进入待删除期，约 5 天内将被彻底删除并释放。</p>
      <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:16px">
        <p style="margin:0;color:#7f1d1d;font-size:13px">此阶段域名已无法赎回。删除后将进入竞价注册或开放注册阶段。</p>
      </div>
    `)},

  { key: "drop_approaching",
    subject: `[预览] example.com 即将可抢注`,
    html: tpl("#7c3aed","即将可用","域名即将释放可注册",`
      <p style="color:#475569;line-height:1.8">您关注的 <strong>example.com</strong> 预计将于 <strong>${dropDt}</strong> 释放。</p>
      <div style="background:#f5f3ff;border:1px solid #ddd6fe;border-radius:8px;padding:14px;margin:16px 0">
        <p style="margin:0;color:#7c3aed;font-size:13px">💡 建议提前登录注册商并准备好支付信息，在释放时刻立即注册。</p>
      </div>
    `)},

  { key: "dropped",
    subject: `[预览] example.com 现已可注册！`,
    html: tpl("#059669","域名可用","域名已释放，现可注册！",`
      <div style="background:#f0fdf4;border:2px solid #6ee7b7;border-radius:10px;padding:20px;text-align:center;margin-bottom:20px">
        <p style="margin:0;font-size:18px;font-weight:700;color:#059669">🎉 example.com 当前未被注册</p>
      </div>
      <p style="color:#475569;text-align:center">快速注册渠道（点击直达）：</p>
      <p style="text-align:center;margin:12px 0">
        <a href="https://www.namecheap.com/domains/registration/results/?domain=example.com" style="color:#7c3aed;margin:0 8px">Namecheap</a>
        <a href="https://www.godaddy.com/domainsearch/find?domainToCheck=example.com" style="color:#7c3aed;margin:0 8px">GoDaddy</a>
        <a href="https://porkbun.com/checkout/search?q=example.com" style="color:#7c3aed;margin:0 8px">Porkbun</a>
        <a href="https://www.namesilo.com/domain/search-domains?query=example.com" style="color:#7c3aed;margin:0 8px">NameSilo</a>
      </p>
    `)},

  { key: "password_reset",
    subject: `[预览] 密码重置请求 — ${SITE_NAME}`,
    html: tpl("#0f172a","账号安全","重置您的密码",`
      <p style="color:#475569;line-height:1.8">我们收到了您的密码重置申请，请点击下方按钮完成重置（链接有效期 24 小时）：</p>
      <div style="text-align:center;margin:24px 0">
        <a href="#" style="display:inline-block;background:#7c3aed;color:#fff;text-decoration:none;padding:12px 32px;border-radius:8px;font-weight:700;font-size:14px">重置密码</a>
      </div>
      <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:14px">
        <p style="margin:0;color:#991b1b;font-size:12px">⚠️ 若非您本人操作，请直接忽略此邮件。您的账号密码不会被修改。</p>
      </div>
    `)},

  { key: "password_changed",
    subject: `[预览] 您的密码已修改 — ${SITE_NAME}`,
    html: tpl("#dc2626","安全通知","密码已成功修改",`
      <p style="color:#475569;line-height:1.8">您的账号密码已于 <strong>${tsStr}</strong>（北京时间）修改成功。</p>
      <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:16px;margin:16px 0">
        <p style="margin:0;color:#991b1b;font-size:13px">⚠️ 如非您本人操作，请立即 <strong>重置密码</strong> 并联系管理员以保障账号安全。</p>
      </div>
    `)},

  { key: "verify_code",
    subject: `[预览] 邮箱验证码 — ${SITE_NAME}`,
    html: tpl("#0f172a","邮箱验证","您的验证码",`
      <p style="color:#475569;text-align:center">请在 15 分钟内输入以下验证码完成验证：</p>
      <div style="text-align:center;padding:24px 0">
        <div style="display:inline-block;background:#f5f3ff;border:2px solid #7c3aed;border-radius:16px;padding:20px 48px">
          <p style="margin:0;font-size:48px;font-weight:900;color:#7c3aed;letter-spacing:10px;font-family:monospace">847291</p>
        </div>
        <p style="margin:12px 0 0;color:#94a3b8;font-size:13px">15 分钟后失效 &nbsp;·&nbsp; 请勿告知他人</p>
      </div>
    `)},

  { key: "admin_notify",
    subject: `[预览] 管理员系统通知 — ${SITE_NAME}`,
    html: tpl("#0f172a","系统通知","邮件系统工作正常",`
      <p style="color:#475569;line-height:1.8">
        <strong>发送渠道：</strong>${SMTP_ACTIVE ? "SMTP" : "Resend"}<br>
        <strong>检测时间：</strong>${tsStr}<br>
        <strong>状态：</strong><span style="color:#059669;font-weight:700">✅ 所有邮件功能正常</span>
      </p>
    `)},

  { key: "admin_broadcast",
    subject: `[预览] 平台公告 — ${SITE_NAME}`,
    html: tpl("#0f172a","平台公告","系统维护通知",`
      <p style="color:#1e293b;line-height:1.9">
        亲爱的用户，<br><br>
        我们将于近期对系统进行维护升级，届时部分查询功能可能短暂不可用，预计维护时间为 2 小时。<br><br>
        维护期间如有急需，请直接访问 WHOIS 官方查询入口。<br><br>
        感谢您的理解与支持！<br><br>
        — ${SITE_NAME} 运营团队
      </p>
    `)},

  { key: "payment_confirm",
    subject: `[预览] 支付成功 — 年度会员已开通`,
    html: tpl("#059669","支付确认","付款已成功处理",`
      <div style="text-align:center;padding:16px 0">
        <div style="display:inline-block;background:#ecfdf5;border:2px solid #6ee7b7;border-radius:50%;width:56px;height:56px;line-height:56px;font-size:28px">✅</div>
      </div>
      <p style="color:#475569;text-align:center;margin-bottom:20px">感谢您的订阅，以下是您的订单详情：</p>
      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden">
        <div style="padding:12px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;color:#94a3b8;text-transform:uppercase">套餐名称</p>
          <p style="margin:4px 0 0;font-weight:700;color:#1e293b">高级会员 · 年度套餐</p>
        </div>
        <div style="padding:12px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;color:#94a3b8;text-transform:uppercase">订单编号</p>
          <p style="margin:4px 0 0;font-family:monospace;font-size:13px;color:#475569">ORD-2026-0401-001234</p>
        </div>
        <div style="padding:12px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;color:#94a3b8;text-transform:uppercase">有效期至</p>
          <p style="margin:4px 0 0;font-weight:600;color:#1e293b">${expYear}</p>
        </div>
        <div style="padding:12px 18px;background:#ecfdf5">
          <p style="margin:0;font-size:11px;color:#94a3b8;text-transform:uppercase">支付金额</p>
          <p style="margin:4px 0 0;font-size:22px;font-weight:800;color:#059669">CNY 99.00</p>
        </div>
      </div>
    `)},

  { key: "high_value",
    subject: `[预览] 高价值域名告警 — premium.ai 评分 88`,
    html: tpl("#dc2626","💎 高价值域名","premium.ai 当前可注册！",`
      <div style="text-align:center;padding:16px 0">
        <div style="display:inline-block;background:#fef2f2;border:2px solid #dc2626;border-radius:16px;padding:14px 28px">
          <p style="margin:0;font-size:44px;font-weight:900;color:#dc2626;line-height:1">88</p>
          <p style="margin:4px 0 0;font-size:11px;font-weight:700;letter-spacing:1px;color:#991b1b;text-transform:uppercase">价值评分 / 100</p>
        </div>
      </div>
      <p style="color:#475569;line-height:1.8;text-align:center">域名 <strong>premium.ai</strong> 当前未被注册，建议尽快评估并决定是否注册。</p>
      <div style="display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin:16px 0">
        <span style="background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:4px 12px;border-radius:999px;font-size:12px">短域名</span>
        <span style="background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:4px 12px;border-radius:999px;font-size:12px">热门后缀 .ai</span>
        <span style="background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:4px 12px;border-radius:999px;font-size:12px">AI关键词</span>
      </div>
      <p style="background:#f5f3ff;border:1px solid #ddd6fe;border-radius:8px;padding:14px;color:#5b21b6;font-size:13px;margin:0">
        🤖 AI 评估：premium.ai 是极具价值的高端 AI 领域域名，在 AI 赛道持续热门的背景下，建议优先注册。
      </p>
    `)},

  { key: "stamp_timeout",
    subject: `[预览] DNS 验证文件未检测到 — example.com`,
    html: tpl("#ef4444","⚠️ 验证超时","所有权验证失败",`
      <p style="color:#475569;line-height:1.8">域名 <strong>example.com</strong> 的所有权验证已超时，请按照以下步骤重新配置：</p>
      <div style="border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;margin:16px 0">
        <div style="padding:12px 16px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase">第一步 · 创建验证文件</p>
          <p style="margin:6px 0 0;font-family:monospace;font-size:12px;color:#7c3aed;background:#f5f3ff;padding:8px;border-radius:4px">/.well-known/next-whois-verify.txt</p>
        </div>
        <div style="padding:12px 16px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase">第二步 · 写入验证码</p>
          <p style="margin:6px 0 0;font-family:monospace;font-size:12px;color:#1e293b;background:#f1f5f9;padding:8px;border-radius:4px">next-whois-verify:preview-stamp-abc123</p>
        </div>
        <div style="padding:12px 16px">
          <p style="margin:0;font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase">第三步 · 点击重新验证</p>
        </div>
      </div>
    `)},

  { key: "feedback",
    subject: `[预览] 用户反馈通知 — example.com WHOIS`,
    html: tpl("#0f172a","用户反馈","example.com · WHOIS 查询问题反馈",`
      <table style="width:100%;border-collapse:collapse">
        <tr><td style="padding:10px 0;color:#94a3b8;font-size:12px;width:80px;border-bottom:1px solid #f1f5f9;vertical-align:top">查询目标</td>
            <td style="padding:10px 0;font-size:13px;color:#1e293b;border-bottom:1px solid #f1f5f9;font-family:monospace">example.com</td></tr>
        <tr><td style="padding:10px 0;color:#94a3b8;font-size:12px;border-bottom:1px solid #f1f5f9;vertical-align:top">查询类型</td>
            <td style="padding:10px 0;font-size:13px;color:#1e293b;border-bottom:1px solid #f1f5f9">WHOIS</td></tr>
        <tr><td style="padding:10px 0;color:#94a3b8;font-size:12px;border-bottom:1px solid #f1f5f9;vertical-align:top">问题类型</td>
            <td style="padding:10px 0;font-size:13px;color:#dc2626;border-bottom:1px solid #f1f5f9;font-weight:600">数据不准确</td></tr>
        <tr><td style="padding:10px 0;color:#94a3b8;font-size:12px;vertical-align:top">补充说明</td>
            <td style="padding:10px 0;font-size:13px;color:#475569;line-height:1.7">查询结果显示的到期时间不正确，实际应为 2027 年，系统显示 2025 年。请核查 WHOIS 数据源。</td></tr>
      </table>
      <p style="margin:16px 0 0;font-size:11px;color:#94a3b8">IP：192.168.1.1 &nbsp;·&nbsp; 时间：${tsStr}（北京时间）</p>
    `)},
];

// ── send loop ─────────────────────────────────────────────────────────────
let sent = 0, failed = 0;

for (const t of TEMPLATES) {
  try {
    await sendRaw(ADMIN_RECIPIENT, t.subject, t.html);
    console.log(`  ✅  [${t.key}]  ${t.subject}`);
    sent++;
    await new Promise(r => setTimeout(r, 400)); // 400ms between sends
  } catch (err) {
    console.error(`  ❌  [${t.key}]  ${err.message}`);
    failed++;
  }
}

await pool.end();

console.log(`\n${"─".repeat(60)}`);
console.log(`  发送完成：${sent}/${TEMPLATES.length} 封成功，${failed} 封失败`);
console.log(`  收件人：${ADMIN_RECIPIENT}`);
console.log(`${"─".repeat(60)}\n`);
