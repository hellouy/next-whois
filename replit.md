# Next Whois UI — v3.35

---

## Session — 2026-04-09 (五): 生产就绪审计 (Production Readiness Audit)

### 1. CI 管道 — 补充 i18n 检查步骤

**`.github/workflows/ci.yaml`** — 在 Typecheck 步骤之后新增：
```yaml
- name: i18n key parity
  run: node scripts/check-locale-keys.mjs
```
现在 CI 流水线顺序为：`install → typecheck → i18n → test → build`。
任何提交如果导致 locale 文件不同步，都会在 PR 阶段被 CI 拦截并报错。

### 2. `.env.example` 全面补充

新增三个之前缺失的配置区块：

**Supabase 组**：
```
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_DATABASE_URL=postgresql://...
SUPABASE_SERVICE_ROLE_KEY=eyJ...
```

**Admin 配置**（之前完全缺失）：
```
ADMIN_EMAIL=admin@yourdomain.com
```
注释说明：未配置时管理后台对所有用户不可用。

**Observability 告警 Webhook**（之前完全缺失）：
```
# ALERT_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN/slack
```
注释说明：留空时 Alert Check 脚本只输出到控制台，不会静默失败。

### 3. 管理后台权限验证 — 审计通过

全部 `src/pages/api/admin/*.ts` 路由均通过 `requireAdmin()` (`src/lib/admin.ts`) 保护：
- `getServerSession` 获取当前会话
- `isAdminEmail()` 异步检查 DB 中的管理员邮箱列表（非硬编码比较）
- IP 级别速率限制 (60 req/min) 防止枚举扫描

`grep -rL "requireAdmin|..."` 对全部 admin API 路由搜索返回空集——无遗漏。

### 4. 日志自动清理 — 验证 Fire-and-Forget 正确性

`logQuery()` 在 INSERT 后通过 `DELETE FROM query_logs WHERE created_at < NOW() - INTERVAL '30 days'` 执行 30 天自动清理：
- 整个 `logQuery()` 函数由调用方以 `.catch(() => {})` 不 await 调用
- 清理运行在同一 DB client 连接上，在 INSERT 之后顺序执行，不阻塞主查询路径
- 任何清理错误被 `catch {}` 块静默吞掉

### 5. 硬编码配置审计 — cn-reserved-sld.ts 合理保留

`src/lib/whois/cn-reserved-sld.ts`（130 行）包含 CNNIC 定义的省级行政区保留 SLD 列表（bj/sh/tj 等 34 个省级 + 7 个功能性 SLD）。  
**结论：保留为静态文件是正确的**。CNNIC 每十年才可能变动一次，无需 DB 化，避免引入不必要的运维复杂度。

---

## Session — 2026-04-09 (四): 安全修复 + 查缺补漏

### 1. 删除高危 Shell 执行接口 (Critical Security)

**删除的文件：**
- `src/pages/admin/git-fix.tsx` — 管理后台 Git 同步工具页面
- `src/pages/api/admin/git-force-push.ts` — 后端 API（使用 `spawnSync` 执行任意 shell 命令：`git pull`、`git push --force` 等）
- `src/pages/admin/index.tsx` — 移除"仓库工具"导航入口

**风险说明：** 任何管理员 Auth 配置错误（环境变量泄漏、session 劫持）都可能导致攻击者通过此接口执行任意 shell 命令，直接 RCE。Git 操作应通过 GitHub Actions / Vercel 部署 Pipeline 完成，绝不通过 Web UI 暴露。

### 2. 多语言文件缺失 Key 修复

**`locales/ja.json`** — 补充缺失 key：
```json
"back_to_top": "トップに戻る"
```

**`locales/ru.json`** — 补充缺失 key：
```json
"back_to_top": "Наверх"
```

所有 8 个 locale 文件现在完全同步（各 159 个 key）。

### 3. Locale Key 一致性检查脚本

新建 `scripts/check-locale-keys.mjs`：
- 以 `en.json` 为基准，检查所有其他 locale 文件
- 缺失 key → 输出 `❌` 错误，`process.exit(1)`（CI 失败）
- 多余 key → 输出 `⚠` 警告（不阻断）
- 在同步时输出 `✓` 行

**集成到 `package.json`：**
```json
"check:i18n": "node scripts/check-locale-keys.mjs"
```

运行：`pnpm check:i18n`

### 4. 精细化 API 速率限制 (Fine-grained Rate Limiting)

**`src/pages/api/lookup.ts`** — 三档限流策略：

| 用户类型 | 每分钟限额 | Key 格式 |
|---|---|---|
| 匿名 / API Key | 40 req/min | `${ip}:anon` |
| 已登录（免费） | 120 req/min | `${ip}:auth` |
| 订阅用户 | 300 req/min | `${ip}:sub` |
| 同源请求（网站本身） | 无限制 | `${ip}:origin` |

**实现要点：**
- Session 提前于限流判断获取（`getServerSession` 是纯 JWT 解码，无 DB 开销）
- `getSetting("require_login")` 与 session 并行获取（`Promise.all`）
- 每个档位使用独立的限流 key，互不影响（订阅用户的请求不占用匿名配额）
- `X-RateLimit-Limit` 响应头反映当前用户的实际配额（而非固定值）

---

## Session — 2026-04-09 (三): 自动化告警 + 可观测性完善

### 1. 自动化告警脚本 `scripts/check-failure-rate.mjs`

新增独立 Node.js ESM 脚本，配合 **Alert Check** Workflow 每小时自动分析 `query_logs` 表，三项检测并发执行：

| 检测项 | 逻辑 | 触发条件 |
|---|---|---|
| **TLD 失败率** | 过去 1 小时按 TLD 分组，统计 success=false 占比 | 失败率 ≥ 20% 且总查询 ≥ 5 次 |
| **慢查询（缓存未命中）** | 过去 1 小时按 TLD 统计平均 duration_ms，仅 `cached=false` | 平均耗时 > 5000ms 且未命中次数 ≥ 3 |
| **耗时骤增（趋势）** | 前 30 分钟 vs 后 30 分钟平均 duration 对比 | recent/early 比值 ≥ 2.0 且每段 ≥ 5 次查询 |

**告警输出：** 同时带修复建议（慢查询 → 建议延长 TTL；骤增 → 建议熔断）

**Webhook 支持：**
- 环境变量 `ALERT_WEBHOOK_URL` — Discord（`discord.com` URL 自动选 `{ content }` 格式）或 Slack（其他 URL 用 `{ text }` 格式）
- 未配置时告警仍打印到控制台，不阻断运行

**架构要点：**
- 使用 `pool.query()` 代替手动 `client.connect()` — 三个查询并行但各自获得独立连接，无 pg "already executing" 弃用警告
- 完全复用 `keep-alive.mjs` 的 `resolveDbUrl()` / SSL 配置模式
- 在 `query_logs` 表不存在时（从未发起过查询）静默跳过，不报错

**新 Workflow — `Alert Check`：**
- 命令：`node scripts/check-failure-rate.mjs`
- 输出类型：`console`
- 与 `Keep Alive`、`Start application` 并列运行

---

## Session — 2026-04-09 (二): 查询日志可观测性系统

### 1. DB Schema — `query_logs` 表

新增时序日志表，记录每一次通过 `/api/lookup` 的查询事件（包含成功和失败）：

```sql
CREATE TABLE IF NOT EXISTS query_logs (
  id          BIGSERIAL    PRIMARY KEY,
  domain      TEXT         NOT NULL,
  tld         TEXT         NOT NULL DEFAULT '',
  success     BOOLEAN      NOT NULL,
  cached      BOOLEAN      NOT NULL DEFAULT false,
  duration_ms INTEGER      NOT NULL DEFAULT 0,
  error_code  TEXT,
  source      TEXT,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_query_logs_created ON query_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_query_logs_tld     ON query_logs (tld);
CREATE INDEX IF NOT EXISTS idx_query_logs_success ON query_logs (success);
```

自动清理：每次写入后删除 30 天前的旧记录。

### 2. `logQuery()` 辅助函数 — `src/lib/db.ts`

fire-and-forget 模式（同 `recordTldLookupFailure`），参数：

| 字段 | 类型 | 说明 |
|---|---|---|
| `domain` | string | 查询域名（截断至 253 字符） |
| `tld` | string | 顶级后缀（截断至 63 字符） |
| `success` | boolean | 是否成功 |
| `cached` | boolean | 是否从缓存返回 |
| `durationMs` | number | 总耗时（毫秒） |
| `errorCode` | string? | 失败时的错误信息前 60 字符 |
| `source` | string? | 查询来源（rdap/whois 等） |

### 3. `src/pages/api/lookup.ts` — 成功与失败路径均接入日志

- TLD 提取：`domain.split(".").pop()` 取最后一级后缀
- 失败路径：`logQuery({ success: false, cached: false, errorCode: error?.slice(0,60) })` 后立即返回 500
- 成功路径：`logQuery({ success: true, cached, source })` 与 `saveSearchRecord` 并列 fire-and-forget

### 4. Admin API — `src/pages/api/admin/query-logs.ts`

GET 端点，返回 `QueryLogResponse`：

```typescript
type QueryLogResponse = {
  rows: QueryLogRow[];          // 分页日志行（最多 200 条/页）
  stats: QueryLogStats;         // 当前筛选范围内的聚合统计
  total_count: number;          // 总行数（用于分页）
};

type QueryLogStats = {
  total: number;
  errors: number;
  cached: number;
  avg_duration_ms: number;
  error_rate: number;           // 0–100 的百分比值（保留 1 位小数）
};
```

支持参数：`?tld=com&status=all|ok|fail&hours=24&page=1&limit=100`

三个聚合 SQL 在同一 client 上顺序执行（避免 pg 并发警告）。

### 5. Admin 页面 — `src/pages/admin/query-logs.tsx`

- **统计卡片** (4 格网格)：总查询数 / 失败次数+错误率 / 缓存命中+命中率 / 平均耗时（超 5s 高亮琥珀色）
- **筛选栏**：TLD 文本输入 / 状态下拉（全部/成功/失败）/ 时间窗口（1h–7d）/ 自动刷新开关（15 秒）
- **日志表格**：序号、域名（font-mono 截断）、TLD 标签、状态徽章（成功/缓存/失败）、耗时（热力颜色）、来源、错误码（红色 font-mono badge）、相对时间
- **分页**：每页 100 条，上一页/下一页，显示总数和当前页码
- **空状态**：首次使用提示，引导进行一次查询

### 6. Admin 首页导航 — `src/pages/admin/index.tsx`

在"域名与接入"分组的"查询失败统计"条目之后添加：

```typescript
{ href: "/admin/query-logs", label: "查询日志", desc: "实时请求日志与错误率监控", icon: RiHistoryLine, color: "text-sky-500" }
```

---

## Session — 2026-04-09 (一): 缓存指示 + XSS + CI + 骨架屏

### 1. DOMPurify XSS 防护 — `src/pages/[...query].tsx`

**`ResultTextAd`** 组件的 HTML 广告模式（`dangerouslySetInnerHTML`）现在通过 `DOMPurify.sanitize()` 净化管理员配置的 HTML 内容后再渲染。

- 安装：`dompurify` + `@types/dompurify`
- SSR 保护：`typeof window !== "undefined"` 判断后才调用 DOMPurify（避免 SSR 崩溃）
- 纯文本广告不受影响

### 2. 过期缓存指示器 — `src/pages/[...query].tsx`

当缓存数据超过 10 分钟未更新时：
- 缓存年龄文字变为琥珀色（`text-amber-500`）
- 显示 `RiLoopLeftLine` 刷新图标按钮
- 点击调用现有 `handleRefresh()` 绕过缓存重新查询

### 3. CI 修复 + `cleanDomain` Bug 修复

**vitest 配置修复**（`vitest.config.ts`）：
- 添加 `esbuild: { jsx: "automatic", jsxImportSource: "react" }`
- 环境改为 `jsdom`
- 安装 `jsdom` dev 依赖
- 不兼容 `@vitejs/plugin-react` v6 — 不安装

**`stripUrlToHostname` bug 修复**（`src/lib/utils.ts`）：
- 剥离协议后错误地返回了端口号（如 `http://host:8080/path` → `"8080"` 而非 `"host"`）
- 修复：剥离协议后用 `new URL()` 正确解析 hostname

**测试结果：** 所有 174 个测试通过。

### 4. 首页即时骨架屏

**`src/components/query/query-loading-skeleton.tsx`** — 提取为共享组件 `QueryLoadingSkeleton`

**`src/pages/index.tsx`** — `isSearching=true` 时立即渲染骨架屏（桌面端 + 移动端），无需等待路由跳转完成

**`src/pages/_app.tsx`** — 回滚首页→查询页导航的顶部进度条（不再显示顶栏，避免与骨架屏重复）

---

## Session — 2026-04-08 (一): 紧急修复 + 安全加固 (T001–T011)

### T001 — ADMIN_EMAIL 硬编码移除

`src/lib/auth.ts` / `src/lib/db.ts`：移除硬编码的默认 qq 邮箱（`9208522@qq.com`）。未配置 `ADMIN_EMAIL` 环境变量时打印告警，`isAdminEmail()` 返回 `false` 而非静默匹配。

### T002 — 缺失环境变量补全

`.env.local` 添加占位注释，标注必填变量：`SUPABASE_SERVICE_ROLE_KEY`、`ADMIN_EMAIL`、`SETUP_SECRET`。

### T003 — Cron Secret 仅 Header 认证

`src/pages/api/remind/process.ts` / `src/pages/api/process-email-queue.ts`：移除 query string `?secret=` 支持，只接受 `Authorization: Bearer <token>` header。防止 secret 泄露到服务器日志和浏览器历史。

### T004 — `init-admin` 端点加强

`src/pages/api/init-admin.ts`：
- IP 速率限制：5次/15分钟（超限返回 429）
- 使用 `crypto.timingSafeEqual()` 比较 secret，防止时序攻击
- 密码长度上限：128 字符（防 bcrypt DoS）
- 操作成功/失败均写入审计日志

### T005 — 国旗图片 `flagcdn.com` 加载失败处理

`src/components/flag-icon.tsx`：添加 `onError` handler，图片加载失败时设置 `display: none` 优雅隐藏，不显示破图标。

### T006 — WHOIS 高亮逻辑修复

`src/lib/whois/highlight.ts`：
- Key 识别正则改为严格行首匹配，避免 IPv6 地址（`2001:db8::1`）中的冒号误匹配为字段分隔符
- URL 检测避免尾部标点（`.`、`,`、`)`）被误包含进可点击链接

### T007 — 批量邮件失败详细上报

`src/pages/api/admin/notify.ts`：返回 HTTP 207 Multi-Status，响应体包含：
```json
{ "sent": 95, "failedCount": 5, "failed": ["a@example.com", ...] }
```
前端同步展示失败邮箱列表（原来只返回 200 + 总数）。

### T008 — `WhoisFieldsTable` 过滤逻辑修复

`src/components/query/whois-fields-table.tsx`：移除对字符串 `"na"` 的误过滤（原本意图是过滤 N/A，但也过滤掉了正常包含 "na" 的姓名如 "Jonathan"）。改为仅过滤空字符串、`null`、`undefined`。

### T009 — WHOIS 传输层 HTML 实体解析增强

`src/lib/whois/whois-transport.ts`：
- 支持完整数字实体：`&#123;`（十进制）和 `&#x1F600;`（十六进制）
- 补充常用命名实体：`&amp;`、`&lt;`、`&gt;`、`&quot;`、`&apos;`、`&nbsp;`（原来只处理部分）

### T010 — 查询重试 Jitter Backoff

`src/lib/whois/lookup.ts`：重试等待从固定延迟改为 400–800ms 随机抖动（`Math.random() * 400 + 400`），避免多并发请求在同一时刻同步重试，降低对上游注册局的瞬时压力。

### T011 — HTML 剥离逐行实体解码

`src/lib/whois/whois-transport.ts`：HTML → 纯文本转换时，对每一行分别解码 HTML 实体后再拼接，解决跨行实体边界问题，确保 WHOIS raw text 中不出现未解码的 `&amp;`、`&#123;` 等残留。

---

## Bug Fixes & Improvements (2026-04-03)

### Admin Panel — 网站设置页面 (`/admin/settings`)
- **Root cause:** `src/pages/admin/settings.tsx` 从未创建，导致导航到 `/admin/settings` 时 404 → 跳回首页
- **Fix:** 新建完整的 `src/pages/admin/settings.tsx` 页面，涵盖所有 `SiteSettings` 字段，分 8 个标签：
  - **品牌外观**：站点标题、Logo、图标、OG/Social 信息、管理员邮箱
  - **访问控制**：注册开关、邀请码、维护模式、登录限制
  - **功能开关**：16 个功能模块的开/关（DNS、SSL、ICP、Stamps 等）
  - **首页内容**：Hero 文案、公告横幅、结果页广告条
  - **统计分析**：Google Analytics、Umami、自定义 Head 脚本
  - **验证码**：Cloudflare Turnstile / hCaptcha / MTCaptcha 动态配置
  - **邮件配置**：SMTP + Resend 双方案
  - **支付配置**：Stripe、PayPal、虎皮椒、支付宝
- 支持密码字段显示/隐藏切换；未保存更改时顶部橙色横幅提示 + 底部悬浮保存按钮

### Admin Layout — `isActive` 逻辑修复
- **Bug:** `p.endsWith(href)` 可能导致路径误匹配（如 `/super-admin` 匹配 `/admin`）
- **Fix:** 改为 `p === href || p.startsWith(href + "/")` 精确匹配

### 用户中心 (`/dashboard`) — URL Tab 参数支持
- **Bug:** `/account` 重定向到 `/dashboard?tab=account` 但 dashboard 不读取 `?tab=` 参数
- **Fix:** `useDashboard.ts` 从 `router.query.tab` 读取初始 tab 值
- **Fix:** 若 URL 明确指定了 tab，则不被 `subscriptionAccess` 的 useEffect 覆盖

---

## Task #8 — ccTLD RDAP Endpoint Audit & Cleanup (2026-04-03)

**Scope:** Full live connectivity audit of all 103 active ccTLD RDAP endpoints in `CCTLD_RDAP_OVERRIDES`. Probe script run against all entries with 7-second timeout. Results: 98 alive, 5 dead (TLS failures).

### Dead endpoints removed (5)

| TLD | URL | Reason |
|-----|-----|--------|
| `.cr` | `rdap.nic.cr` | Self-signed TLS certificate (`DEPTH_ZERO_SELF_SIGNED_CERT`); WHOIS via `whois.nic.cr` works |
| `.fj` | `www.rdap.fj` | TLS leaf signature invalid (`UNABLE_TO_VERIFY_LEAF_SIGNATURE`); WHOIS via IANA fallback |
| `.gs` | `rdap.nic.gs` | TLS cert altname mismatch — cert covers other COCCA-hosted TLDs but not `.gs` |
| `.la` | `rdap.nic.la` | TLS cert altname mismatch — cert has `whois.nic.la` but not `rdap.nic.la`; WHOIS via `whois.nic.la` works |
| `.sr` | `whois.sr/rdap/` | TLS certificate expired (`CERT_HAS_EXPIRED`); no reliable WHOIS server for Suriname |

### Newly re-added (1)

| TLD | URL | Note |
|-----|-----|------|
| `.cv` | `https://rdap.nic.cv/` | Re-confirmed working 2026-04-03 (HTTP 404 for test domain); registry fixed RDAP server that was broken throughout 2025 |

### Other changes
- `RDAP_TLD_TIMEOUT_MS`: removed `.la: 6000` entry (TLD removed from overrides)
- `getCctldRdapOverrides()` JSDoc: updated count 168 → 99 active entries
- Net result: 103 → 99 active ccTLD RDAP overrides (-5 removed, +1 re-added)
- Probe script saved at `scripts/probe-rdap-cctld.mjs` for future audits (5s timeout; 2xx/4xx = alive, 5xx = degraded, network/TLS fail = dead)
- **Count clarification:** The task planning phase estimated 128 active entries from a broad `grep "^  [a-z\"']"` that inadvertently matched non-map lines in the file (type definitions, function parameters, etc.). The actual count extracted by key-matching the `CCTLD_RDAP_OVERRIDES` object was 103 entries, which the probe confirmed by running exactly 103 TLD probes.

---

## Task #7 — Dashboard & Admin UX Improvements (2026-04-03)

### i18n — dashboard.tsx
- **17 new locale keys** added to `locales/en.json`, `locales/zh.json`, `locales/zh-tw.json` (dashboard section): `code_sent`, `send_failed`, `code_required`, `email_confirm_mismatch`, `account_deleted`, `delete_account_failed`, `sub_search_placeholder`, `code_placeholder`, `send_code`, `delete_account`, `confirm_delete_title/prefix/irreversible/suffix/email_placeholder/btn`, `activation_code_redeemable`
- **6 hardcoded Chinese toast messages** replaced with `t()` calls in dashboard.tsx
- **Delete account UI strings** fully internationalised: button label, dialog title, warning paragraph (with red span), email placeholder, confirm and cancel buttons
- **Subscription search placeholder** and **activation code label** fixed to use `t()`
- **Email change** code placeholder and "Send Code" button text fixed to use `t()`

### Duplicate contact form removed
- Removed ~80-line duplicate contact form from the Membership tab (kept only the one in Account tab)

### Unauthenticated redirect
- Changed loading state: when `status === "unauthenticated"`, return `null` immediately (redirect fires via `router.replace("/login")`); spinner only shown during `"loading"` state

### Admin system.tsx — inline confirmations
- Replaced `window.confirm()` with two state flags (`confirmTrigger`, `confirmClear`)
- **Trigger Reminders** button: first click shows inline amber confirmation row; second click executes; cancel dismisses
- **Clear Rate Limits** button: same pattern
- **DB Optimize** button: already had 2-step preview flow; removed stale `window.confirm()` guard

---

## Task #6 — UX Polish & Code Quality (2026-04-03)

### UX Improvements
- **Cache age indicator** (`src/pages/[...query].tsx`): When `cachedAt` timestamp is present, shows "cached Nm ago" or "cached Nh ago" instead of just "cached"; falls back to `t("cached")` if no timestamp. Shows exact datetime on hover title. Bilingual (EN/ZH via `isChinese`).
- **Domain copy icon button**: Added explicit `<RiFileCopyLine>` icon button alongside the clickable domain h2, wrapped in `flex items-start gap-2` container. Subtle opacity by default, full opacity on hover.
- **Retry button on error**: Already existed (`<Button onClick={handleRefresh}>{t("try_again")}</Button>`), no change needed.

### Code Extraction (1,328 lines removed from `[...query].tsx`)
**Data files** created in `src/data/query-page/`:
- `registrar-icons.ts` — `REGISTRAR_ICONS` record (~110 lines)
- `ns-brands.ts` — `NS_BRANDS` array (~560 lines)
- `globe-coords.ts` — `GLOBE_COUNTRY_COORDS` record (~50 lines)
- `mainstream-domains.ts` — `MAINSTREAM_DOMAINS` Set (~55 lines)
- `official-domain-desc.ts` — `OFFICIAL_DOMAIN_DESC` record (~100 lines)

**Component files** created in `src/components/query/`:
- `query-progress-bar.tsx` — `QueryProgressBar` component
- `css-globe.tsx` — `CssGlobe` component (imports `GLOBE_COUNTRY_COORDS`)
- `response-panel.tsx` — `ResponsePanel` + co-located `WhoisHighlight` + `RdapJsonHighlight`

Helper functions `getNsBrand` + `getRegistrarIcon` remain in the query page since they reference imported data.

Main query page reduced from **6,711 → 5,383 lines** (~20% reduction).

---

## Pre-Launch Security & Quality Audit (2026-04-02, v3.35 patch)

### Security Hardening
- **HSTS header added** (`next.config.js`): `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` — forces HTTPS on all connections; submitted for browser preload
- **GA4 ID injection hardened** (`_app.tsx`): validates format `/^G-[A-Z0-9]{4,20}$/i` before injecting into inline script; invalid values silently dropped
- **Umami src URL validated** (`_app.tsx`): only `http(s)://` URLs accepted; falls back to official CDN to block `javascript:` injection
- **Admin auth coverage**: verified all `src/pages/api/admin/*.ts` routes (40+) require `requireAdmin` — no unprotected endpoints found

### Build & TypeScript
- **Removed `typescript: { ignoreBuildErrors: true }`**: TypeScript is 100% clean (0 errors); builds now fail on new TS errors, preventing regressions
- **Verified**: `npx tsc --noEmit` → 0 errors across full codebase

### Error Resilience
- **React ErrorBoundary** (`src/components/error-boundary.tsx`): class component with `getDerivedStateFromError` + `componentDidCatch`; shows user-friendly error UI with retry button instead of blank screen
- **Integrated in `_app.tsx`**: wraps all admin pages and all regular pages inside AnimatePresence

### Vercel Configuration
- **`lookup-stream.ts` added** to `vercel.json` functions with `maxDuration: 30` (explicit, matching file-level config)
- **`[...query].tsx` maxDuration**: 10s → 15s — extra headroom for cold SSR starts with slow DB/Redis

### Version Tracking
- **`src/lib/env.ts`**: `VERSION = "3.23"` → `"3.35"` — navbar now shows correct version
- **`package.json`**: `"version": "1.0.0"` → `"3.35.0"`
- **`changelog-sync.ts`**: added 30 new entries for v3.23–v3.35 covering all recent features

### Audit Results (No Changes Needed)
- All 8 locale files: 1659 keys each, perfectly in sync ✓
- `robots.txt`: properly excludes `/api/`, `/dashboard`, `/payment/`, `/admin/` ✓
- Custom error page `_error.tsx`: handles 404/500 gracefully ✓
- Payment APIs: all use DB settings or env vars for secrets, never hardcoded ✓
- SQL injection: parameterized queries throughout, no raw string interpolation ✓
- Rate limiting: same-origin bypass in both `/api/lookup.ts` and `/api/lookup-stream.ts` ✓

---

## Speed Optimization + UX Improvements (2026-04-02, v3.35)

### Streaming Progressive Lookup API (major speed improvement)
**`src/pages/api/lookup-stream.ts`** — new NDJSON streaming endpoint:
- For RDAP-supported TLDs: sends partial RDAP result ~1-2s, then full merged result
- For cache hits: single line returned immediately (~0ms)
- `src/lib/whois/lookup.ts`: added `lookupWhoisCacheStreaming()` with `onPartialResult` callback
- `src/lib/lookup-prefetch.ts`: fires streaming endpoint on search submit (before SSR)
- `src/pages/[...query].tsx`: client useEffect consumes NDJSON stream with `refreshing` state
- Subtle "Updating..." pulsing label in result card timing row during WHOIS enrichment
- `QueryProgressBar` pulses at 90-95% during streaming partial phase

### Reduced Timeouts
- `WHOIS_TIMEOUT`: 7000ms → 5000ms
- `RDAP_WIN_WHOIS_GRACE_MS`: 800ms → 400ms

### /account Redirect Page
**`src/pages/account.tsx`** — new redirect page:
- `getServerSideProps` returns `{ redirect: { destination: "/dashboard?tab=account" } }`
- Fixes broken "Manage Account" links in email templates

### User Dashboard: Balance Transaction History
**`src/pages/api/user/balance-transactions.ts`** — new user-facing API:
- Returns last 30 balance transactions for the current user
- Balance row in membership tab is now an accordion — click to expand transaction history
- Shows credit/debit amounts with +/- color coding
- Translation key `dashboard.no_balance_history` added to all 8 locale files

---

# Next Whois UI — v3.34

## Analytics Injection + Meta Fix + UX Polish (2026-04-02, v3.34)

### Critical Fix: Analytics & Custom Head Script Injection
**`src/pages/_app.tsx`** — new `AnalyticsScripts` component:
- Reads `analytics_google` (GA4 measurement ID, e.g. `G-XXXXXXXXXX`), `analytics_umami` (website ID), `analytics_umami_src` (script URL, defaults to `https://cloud.umami.is/script.js`), and `custom_head_script` from site settings
- Injects the appropriate `<script>` tags into `<Head>` via Next.js head management
- Rendered inside `<SiteSettingsProvider>` so it reacts to live settings without page reload
- Returns `null` if all three are empty (no unnecessary DOM nodes)

### Fix: Hardcoded OG Meta in `_document.tsx`
**`src/pages/_document.tsx`** — removed two hardcoded meta tags:
- `<meta property="og:site_name" content="RDAP+WHOIS 域名查询" />` — was overriding the dynamic site name from settings
- `<meta name="twitter:site" content="@nextwhois" />` — static placeholder that should not be embedded
- `AppHead` in `_app.tsx` already handles `og:site_name` dynamically from `settings.site_title`

### Fix: Replace `window.confirm()` with inline confirmation UI
**`src/pages/admin/users.tsx`**:
- Added `confirmReset` state; first click on "重置密码" button sets it to `true`
- An inline confirmation row (with "确认" / "取消" buttons) replaces the button while confirming
- Second click calls the actual API; "取消" dismisses without side effects

**`src/pages/admin/notify.tsx`**:
- Added `pendingSend` state; first click on "发送邮件" validates inputs then enters confirmation mode
- Displays recipient count in amber text + swaps "清空" for "取消" + highlights send button amber with "确认发送" label
- Second click executes the API send; "取消" returns to normal state

---

# Next Whois UI — v3.33

## Homepage Fix + Announcement + Result Page Ad (2026-04-01, v3.33)

### Homepage Error Fix (iOS download dialog)
**Root cause**: `getServerSideProps` on homepage made a DB round-trip on every request. On cold start (empty DB pool + no Redis cache), this took 5-9 seconds. iOS Safari treated the stalled response as a binary download.

**Fix** — switched homepage from `getServerSideProps` → `getStaticProps` with ISR:
- `revalidate: 60` — page is pre-built as a static file, regenerated at most every 60 s
- DB is never hit at request time; homepage serves from CDN cache instantly
- Falls back to sensible defaults if DB is unreachable during revalidation
- `origin` prop removed; `siteUrl` derived from `settings.og_url` (live settings) with `og_url` included in `initialSiteSettings`

### Homepage Announcement Banner
**`src/pages/index.tsx`** — new `HomeAnnouncementBanner` component:
- Placed **inline** below the search box, not fixed — does not overlap navbar on mobile
- Dismissible: clicking ✕ stores a hash of the text in `localStorage`; changing the text un-dismisses it
- Types: `info` (blue), `warning` (amber), `success` (emerald), `notice` (violet)
- Optional URL: entire banner becomes a link when `home_announcement_url` is set
- Reads settings live via `useSiteSettings()` — no page reload needed after admin change

### Result Page Text Ad
**`src/pages/[...query].tsx`** — new `ResultTextAd` component:
- Rendered below the main WHOIS/RDAP result section
- Shows label badge (configurable text, default "广告"), ad content, external link icon
- Uses `rel="noopener noreferrer sponsored"` for SEO-safe external links
- Reads from `useSiteSettings()` — no SSR changes needed, live-updates from settings

### Admin Settings
**`src/pages/admin/settings.tsx`** — two new sections:
- **首页公告** (`home_announcement`): enabled toggle, text content, type dropdown (info/warning/success/notice), URL
- **结果页广告** (`result_ad`): enabled toggle, ad text, ad URL, label text
- Renamed "公告与维护" section to "全站公告与维护" to distinguish from homepage-specific announcement

### New site-settings keys
- `home_announcement_enabled`, `home_announcement_text`, `home_announcement_type`, `home_announcement_url`
- `result_ad_enabled`, `result_ad_text`, `result_ad_url`, `result_ad_label`

---

# Next Whois UI — v3.32

## Vercel Serverless + Redis Optimization (2026-04-01, v3.32)

### Upstash HTTP Client (major Vercel fix)
**`src/lib/server/redis.ts`** — complete rewrite:
- **Primary**: `@upstash/redis` HTTP client (stateless, zero persistent TCP connections, Vercel-safe). Auto-detected via `wr_KV_REST_API_URL` + `wr_KV_REST_API_TOKEN` env vars (supports `wr_`, `xrw_`, unprefixed prefixes)
- **Fallback**: ioredis TCP client for self-hosted Redis (only activated when Upstash REST env vars are absent)
- Unified interface: all existing functions (`getRedisValue`, `setRedisValue`, `getJsonRedisValue`, `incrRedisValue`, `deleteRedisKeysByPattern`, `getRemainingTtl`, `getJsonRedisValueWithTtl`) route to the active client transparently
- Added `getCachedSetting` / `setCachedSetting` / `invalidateCachedSettings` helpers for site-settings Redis cache layer (60 s TTL, key prefix `ss:`)
- Added `getWhoisDbCache` / `setWhoisDbCache` helpers for PostgreSQL L3 fallback cache
- `isRedisAvailable()` returns `true` immediately for Upstash (always ready, no "ready" event needed)
- `@upstash/redis ^1.37.0` added to package.json

### Site Settings — Redis L2 Cache
**`src/lib/server/site-settings-server.ts`**:
- Added Redis L2 cache layer between in-process L1 and PostgreSQL L3
- `getSetting()` / `getSettings()`: L1 (30 s in-process) → L2 (Redis 60 s) → L3 (DB)
- `invalidateSettingsCache()`: clears both L1 and Redis L2 (best-effort)
- Prevents repeated DB hits on Vercel cold starts where L1 is empty

### DB Pool — Serverless-Aware
**`src/lib/db.ts`**:
- `max: isServerless ? 2 : 8` — reduced pool size on Vercel to avoid exhausting Supabase connection limits
- `idleTimeoutMillis: isServerless ? 5000 : 30000` — faster idle cleanup on serverless
- `keepAlive: !isServerless` — disabled on Vercel (connections are short-lived)
- Detection via `process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME`

### Vercel Config
**`vercel.json`**:
- Added `process-email-queue` cron: `*/10 * * * *` (every 10 minutes)
- Added `maxDuration: 60` for `/api/admin/process-email-queue` and `/api/admin/notify`
- Total configured functions: 11

---

# Next Whois UI — v3.31

## Comprehensive UX Enhancement (2026-04-01, v3.30)

### HTTP Check — Full Rewrite

**`src/pages/api/http/check.ts`**:
- Switched from HEAD to GET (then immediately cancels body stream) so security headers added by middleware (HSTS, CSP etc.) are always captured
- Added 7 security headers extraction: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-XSS-Protection`
- Added `securityScore` (0-100, weighted: critical=30, high=25, medium=10, info=5) and `securityHeaders[]` array in response
- Added `contentLength`, `xPoweredBy`, `cacheControl`, `via` fields
- Fixed Chinese error messages → English

**`src/pages/http.tsx`** (complete rewrite):
- Security headers panel with per-header present/missing indicators, severity badges, click-to-expand raw value
- `ScoreRing` SVG component showing 0-100 security score with color coding
- HSTS badge for HTTPS sites (green when present, amber when missing)
- "Open link" button on response details section
- URL parameter auto-query (`?q=`) like other tool pages
- Inline refresh button beside check button when result shown
- Empty state with quick-try example buttons
- Response Details section now shows: server, content-type, cache-control, content-size, powered-by, via

### DNS Page — SPF/DMARC Analysis

**`src/pages/dns.tsx`**:
- Added `parseSpf()` function: extracts mechanisms (include:, a, mx, ip4:, ip6:), `all` directive, counts DNS lookup mechanisms, warns if >10 (RFC violation)
- Added `parseDmarc()` function: parses all DMARC tags (p=, sp=, pct=, rua=, ruf=, adkim=, aspf=)
- New SPF Analysis section inside email preset panel: shows all mechanisms as monospace badges, `all` directive with color coding (green=-all, amber=~all, red=+all), DNS lookup count warning
- New DMARC Analysis section: shows policy/subdomain policy with color coding (green=reject, amber=quarantine, red=none), alignment mode, report email addresses

### IP/ASN Page — External Lookups

**`src/pages/ip.tsx`**:
- New "External Lookups" panel below RDAP info with clickable links to: BGP.he.net (ASN + IP), ARIN RDAP, Shodan, VirusTotal, IPinfo
- Added `contact_email` and `cidr` to RDAP display rows

### Locale Updates
- Added ~20 new keys to all 8 locale files (zh, en, de, fr, ja, ko, ru, zh-tw) covering: `http.loading`, `http.section_details`, `http.section_security`, `http.hsts_*`, `http.result_content_len`, `ip.links_section`, `dns.spf_analysis`, `dns.dmarc_analysis`, and 15 more

---

# Next Whois UI — v3.29

## whoiser-Primary Lookup + Page Jump Fix (2026-04-01, v3.29)

### Problem
Vercel deployment couldn't query some TLDs (e.g. `.me`) while Replit preview worked fine.
Root cause: `whois-servers.json` (193 entries) was used as a "bootstrap" to make direct TCP connections to WHOIS servers before whoiser. Those direct TCP connections worked locally but could timeout or be blocked on Vercel's network. Two sequential TCP hops (registry + registrar referral chain) amplified this.

### Lookup Architecture — New (whoiser-primary)

| Priority | Source | Notes |
|---|---|---|
| ① | `custom_whois_servers` DB (admin-managed) | Manual supplements for broken TLDs, scrapers (.ba), special cases (.bn) |
| ② | **whoiser** (primary) | Handles TLD server discovery + referral chain following natively via `follow: 2` |
| ③ | IANA TCP fallback | `whois.iana.org → refer:` as last resort |

`whois-servers.json` is now **admin-display only** (shown in the built-in servers admin tab); it is **not used in any lookup code path**.

### Files Changed
- **`src/lib/whois/whois-generic.ts`**: Rewrote `tryGenericWhoisForDomain()`:
  - Removed: `getStaticWhoisServer`, `isTldKnownNoServer` imports
  - Removed: `extractRegistrarWhoisServer` referral chain (whoiser's `follow: 2` handles this)
  - New flow: DB custom server → whoiser → IANA TCP
- **`src/lib/whois/custom-servers.ts`**: `getAllCustomServers()` no longer merges `whois-servers.json`; uses only DB + builtin scrapers + registry-info table. `_knownNoServerCache` always empty (whoiser fails gracefully for TLDs with no server).

### Page Jump Fix (`src/pages/[...query].tsx`)
- Added `layout` prop to outer `motion.div` to animate height changes smoothly
- Wrapped loading skeleton in `AnimatePresence` with `motion.div` (fade in + fade out via `exit`)
- Wrapped result content in `motion.div` with `initial={{ opacity: 0 }}` fade-in
- Result: skeleton fades out, content fades in — no abrupt layout shift on first domain query

---

# Next Whois UI — v3.28

## i18n & UX Fixes (2026-03-29, v3.28)

### 1. Dashboard Date Locale Fix (`src/pages/dashboard.tsx`)
- **`fmt()` function was hardcoded to `zh-CN`**: Changed signature to `fmt(d: Date, locale?: string)` and updated all 5 callsites to pass `locale` from `useTranslation()`. Non-Chinese users now see dates formatted in their selected language instead of always showing Chinese-format dates.

### 2. WHOIS Lookup Page Meta Tags i18n (`src/pages/[...query].tsx`)
- **Title, description, keywords, og:locale, og:title, twitter:title and JSON-LD were all hardcoded in Chinese**. All meta strings are now locale-aware using `isZhMeta = locale.startsWith("zh")`:
  - `<title>`: `"google.com WHOIS Lookup · Registration · Expiry"` in English, `"google.com WHOIS 查询 · 注册信息 · 到期时间"` in Chinese
  - Description parts (Registered/注册, Registrar/注册商, Created/注册, Expires/到期, days old/域龄) toggle per locale
  - Keywords use English terms for non-Chinese locales
  - `og:locale` maps to correct BCP-47 locale codes (`en_US`, `zh_CN`, `zh_TW`, `ja_JP`, `ko_KR`, `de_DE`, `fr_FR`, `ru_RU`)
  - JSON-LD `inLanguage`, breadcrumb labels ("Home"/"首页", "Domain Lookup"/"域名查询") and dataset names are locale-aware

---

# Next Whois UI — v3.27

## Comprehensive Code Audit & Hardening (2026-03-29, v3.27)

### 1. WHOIS Error Pattern Hardening (`src/lib/whois/lookup.ts`)
- **Rate-limit false-positive fix**: Replaced broad `/error:/i` with `/^error:/im` (line-start only). The old pattern matched strings like `"Query error: rate limit exceeded"` and incorrectly triggered the fallback gate, burning paid API quota for a transient server throttle.
- **New `WHOIS_RATE_LIMIT_PATTERNS` + `isWhoisRateLimited()`**: Seven patterns covering `rate limit`, `too many requests`, `access denied`, `temporarily blocked`, `please try again later`, etc. When matched BEFORE the error-pattern check, the lookup returns a user-visible rate-limit message and skips `recordTldNativeFailure` — the gate stays closed, native WHOIS is tried again next request, no paid API is called.
- **`_ianaServerCache` size cap**: Added `IANA_CACHE_MAX = 2000` with FIFO eviction to prevent unbounded memory growth from repeated IANA referral lookups (previously uncapped across the full 1500+ TLD set).

### 2. Fallback Gate API Improvements (`src/pages/api/admin/tld-fallback.ts`)
- **Row limit 200 → 2000**: The batch scraper processes 1285+ TLDs; the old LIMIT 200 silently truncated the admin view. Now up to 2000 rows returned, covering the full working set.
- **Optional `?q=` search param**: Added SQL `WHERE tld LIKE $1` filter for server-side prefix search when the param is provided.
- **Response now includes `total`** field alongside `rows`.
- **PATCH syncs in-memory gate**: When admin manually sets `use_fallback=false` or lowers fail_count below threshold via the admin UI, `resetTldFallbackGateInMemory()` is now called immediately so native WHOIS is retried in the next request (previously only the DB row was updated).

### 3. SSE Disconnect Cleanup (`src/pages/api/admin/tld-registry.ts`)
- Added `let clientClosed = false` + `req.on('close', ...)` handler. The batch-scan loop and heartbeat interval check `clientClosed` before every write and at each item iteration. Prevents orphaned server-side RDAP scan processing continuing after the browser tab is closed or navigated away.

### 4. Custom WHOIS Servers GET Auth (`src/pages/api/whois-servers.ts`)
- GET was previously public, exposing the full list of custom WHOIS/RDAP servers (including internal infrastructure details). Now requires admin authentication for all methods.

### 5. Settings Batch Upsert (`src/pages/api/admin/settings.ts`)
- The PUT handler previously fired N independent `INSERT … ON CONFLICT UPDATE` queries in `Promise.all`. Replaced with a single multi-row `VALUES (…),(…),…` batch upsert — one DB round-trip regardless of how many settings keys are being saved.

### 6. Admin Fallback Table UX (`src/pages/admin/tld-fallback.tsx`)
- Added client-side search input above the fallback stats table. Instant filtering across all loaded rows (no API round-trip per keystroke).
- Shows row count: `"共 N 条记录"` normally, `"M / N 条"` when filtered.
- Empty-state row rendered when search yields no matches.
- `filteredRows` computed from `rows` based on `fallbackSearch` state; original `rows` remains unmodified for stat cards.



## Performance / UX Fixes (2026-03-29, v3.26)

### 1. Query Page Prefetch Warmup (`src/pages/index.tsx`)
Added `router.prefetch('/github.com')` to the homepage `useEffect`. This fires immediately when the user lands on the homepage, triggering the server to compile `[...query].tsx` (the results page) in the background. In dev mode this compilation takes ~8s; without prefetch the user waits 12-13s for their very first search. With prefetch, the compilation happens while the user is still typing, so the first search completes in ~31ms (same as subsequent searches).

### 2. Eliminate Skeleton "1→2" Jump — Two-part fix

**A. Instant page entry** (`src/pages/_app.tsx`): `stablePageVariants` previously faded from `opacity: 0 → 1` over 150ms. The bright CSS `text-shimmer` animation became visible at low opacity while the dimmer `查询中…` muted text remained invisible — creating a perceptual "step 1: shimmer only, step 2: both texts" jump. Fix: changed `initial.opacity` to `1` with `duration: 0` — the results page now appears INSTANTLY at full opacity. The exit animation (50ms fade-out when navigating away) is preserved.

**B. Pre-paint locale sync** (`src/lib/locale-context.tsx`): `LocaleProvider` previously used `useEffect` to sync locale from the client cookie AFTER the browser painted. For users whose server-rendered locale (detected from request) differed from their cookie locale, React would re-render AFTER paint — the shimmer text animation masked the content change (looked like it was always Chinese) but the plain muted "查询中" text appeared to visually "pop in" (locale switch was visible). Fix: switched to `useIsomorphicLayoutEffect` (= `useLayoutEffect` on client, `useEffect` on server) so the locale sync happens BEFORE the first browser paint — users never see any English→Chinese flash.

## Admin Consolidation & Cleanup (2026-03-29)

### Old Admin Pages Deleted (9 files)
All consolidated into two unified tabbed pages. Old URLs 301-redirect to new locations via `next.config.js`:

| Old URL | New Location |
|---|---|
| `/admin/access-keys` | `/admin/access-control` |
| `/admin/invite-codes` | `/admin/access-control?tab=invite` |
| `/admin/activation-codes` | `/admin/access-control?tab=activation` |
| `/admin/custom-servers` | `/admin/domains?tab=servers` |
| `/admin/repair-queue` | `/admin/domains?tab=servers` |
| `/admin/tld-lifecycle` | `/admin/domains` |
| `/admin/tld-lifecycle-feedback` | `/admin/domains` |
| `/admin/tld-probe` | `/admin/domains?tab=servers` |
| `/admin/tld-registry` | `/admin/domains?tab=iana` |

### Lifecycle Feedback Ported to domains.tsx
The admin lifecycle-feedback review UI (approve/reject/delete user-submitted period corrections) was ported as an inline section at the bottom of the 生命周期 tab in `/admin/domains`. The admin API `tld-lifecycle-feedback.ts` is retained.

### Orphaned Files Removed
- `src/pages/api/admin/tld-probe.ts` — deleted (only called by old tld-probe.tsx; probe results went to orphaned `cctld_rdap_servers` table)
- `cctld_rdap_servers` table — removed from `db.ts` schema (replaced with `DROP TABLE IF EXISTS`), removed from `db-export.ts`. Table was never read by the live query engine (real ccTLD RDAP routing uses `CCTLD_RDAP_OVERRIDES` in `rdap_client.ts`).

### Tab Arrays Updated
- `tld-fallback.tsx` and `tld-rules.tsx` — stale 8-item tab bars replaced with clean 3-item nav: TLD 管理 / TLD 规则 / 查询兜底

## Page Transition Performance Fixes (v3.25)

### Route Progress Bar
Added a CSS-animated progress bar (`hsl(var(--primary))` color) that appears at the very top of the viewport the moment any navigation begins (`routeChangeStart`), completing once the new page is ready (`routeChangeComplete`). Implemented entirely in `_app.tsx` (inlined into `App` component body) using GPU-accelerated `transform: scaleX()` to avoid layout thrash. CSS keyframes (`np-start` / `np-done`) live in `globals.css`.

This eliminates the "frozen page" sensation during `getServerSideProps` round-trips — users see immediate visual motion instead of a blank wait.

### Faster Exit Animations
Reduced `AnimatePresence` exit durations from 100 ms → 50 ms (both `pageVariants` and `stablePageVariants`). This halves the blank-screen gap between the outgoing page fading out and the incoming page fading in, especially noticeable on the first home→results navigation.

### Synchronous Search Loading State
`index.tsx` `handleSearch` now calls `setLoading(true)` **before** `router.push()`, guaranteeing the search-box spinner appears in the same JS microtask as the user action rather than waiting for the `routeChangeStart` event to propagate through React's event system.

## Performance & Code Quality Audit (2026-03-29)

### Parallelized DB Queries (Sequential → `Promise.all`)
Every admin and user-facing API that previously fired DB queries one-by-one was updated to run all independent queries concurrently:

| File | Before | After |
|---|---|---|
| `api/lookup.ts` | `getServerSession` then `getSetting` | Both in `Promise.all` |
| `api/admin/settings.ts` PUT | `for` loop (1 query/key) | `Promise.all` (all keys) |
| `api/admin/invite-codes.ts` POST | `for` loop (1 insert/code) | `Promise.all` (all codes) |
| `api/admin/activation-codes.ts` POST | `for` loop (1 insert/code) | `Promise.all` (all codes) |
| `api/admin/system.ts` GET | 9 `Promise.all` + 2 sequential | All 11 in one `Promise.all` |
| `api/admin/system.ts` db_optimize | 7 sequential DELETEs | 7 parallel DELETEs |
| `api/admin/db-export.ts` | Sequential per-table COUNT + SELECT | `Promise.all` for all tables |
| `api/admin/hot-prefixes.ts` GET | 3 sequential queries | `Promise.all` |
| `api/admin/hot-prefixes.ts` seed | `for` loop | `Promise.allSettled` |
| `api/admin/search-records.ts` | 4 sequential queries after `Promise.all` | All merged into one `Promise.all` |
| `api/admin/reminders.ts` GET | list + count + 3 filter counts sequential | All 5 in `Promise.all` |
| `api/admin/users.ts` GET | list + count + 4 filter counts sequential | All 6 in `Promise.all` |

### Cache Headers Added
- `api/dns/records.ts` — changed `no-store` → `public, s-maxage=30, stale-while-revalidate=60` (DNS results are domain-scoped, not user-scoped)
- `api/dns/txt.ts` — same improvement

### TypeScript: 0 errors throughout (verified after all changes)

## RDAP/WHOIS File Consolidation (2026-04-01)

### Objective
Reduce server list files from 3 to 2: one RDAP file and one WHOIS file. Database entries for TLD WHOIS servers fully cleared (file-based approach only).

### Final File Structure
| File | Entries | Purpose |
|---|---|---|
| `src/lib/whois/rdap_gtld_bootstrap.ts` | 1223 | All RDAP-capable TLDs (IANA + 6 Identity Digital extras) |
| `src/data/whois-servers.json` | 192 (153 with server, 39 null) | All non-RDAP TLDs — merged from former `cctld-whois-servers.json` (179) + `whois_gtld_bootstrap.ts` (119) |

### Changes Made
- **Deleted** `src/data/cctld-whois-servers.json` (ccTLD-only, 179 entries)
- **Deleted** `src/lib/whois/whois_gtld_bootstrap.ts` (gTLD-only, 119 entries)
- **Created** `src/data/whois-servers.json` (merged, 192 entries; ccTLD wins on conflicts)
- **Updated** `src/lib/whois/custom-servers.ts`: reads `whois-servers.json`; exports new `getStaticWhoisServer()` helper
- **Updated** `src/lib/whois/whois-generic.ts`: uses `getStaticWhoisServer()` instead of old `getGtldWhoisServer()`
- **Updated** `src/pages/api/admin/builtin-servers.ts`: imports `whois-servers.json`
- **Cleared** all rows from `custom_whois_servers` DB table (database no longer pre-populated; auto-discovery still writes to DB at runtime)

### Verified Results
| Domain | Source | Status |
|---|---|---|
| hello.vc | rdap | ✓ |
| github.com | rdap | ✓ |
| google.co.uk | rdap | ✓ |
| google.de | whois | ✓ |
| google.cn | whois | ✓ |
| google.ru | whois | ✓ |

---

## Replit Environment Full Sync with Vercel (2026-04-01)

### Vercel Project Identified
- **Project**: `next-whois` (prj_iUBe5v2wht9SYe1SuFKyj0vMgyLR)
- **Team**: team_jwt3T9B3Dg8JLPoGEjauWPRr
- **Region**: iad1 (Washington D.C.)

### Secrets & Env Vars Configured in Replit
- `POSTGRES_URL_NON_POOLING` — Supabase direct connection (aws-1-ap-southeast-2.pooler.supabase.com:5432, PostgreSQL 17.6)
- `VERCEL_TOKEN` / `VERCEL_API_TOKEN` — Vercel personal access token
- `VERCEL_PROJECT_ID` — prj_iUBe5v2wht9SYe1SuFKyj0vMgyLR
- `VERCEL_TEAM_ID` — team_jwt3T9B3Dg8JLPoGEjauWPRr
- `GITHUB_TOKEN` / `GH_TOKEN` — GitHub classic token
- `wr_REDIS_URL`, `wr_KV_URL`, `xrw_REDIS_URL` — Upstash Redis (synced from Vercel)
- `wr_KV_REST_API_TOKEN`, `wr_KV_REST_API_URL` — Upstash KV REST API
- `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`
- `CRON_SECRET`, `NEXTAUTH_SECRET`

### Vercel DB Vars Updated
- `POSTGRES_URL` → set to Supabase pooler URL (was empty)
- `POSTGRES_URL_NON_POOLING` → set to Supabase direct URL (was empty)
- `POSTGRES_PRISMA_URL` → set to Supabase URL (was empty)

### DB & Cache Connection Status
- **PostgreSQL (Supabase)**: Connected ✓, schema migrated ✓
- **Redis (Upstash)**: Connected and ready ✓ (`[Redis] Connected and ready`)
- **Keep Alive**: Running ✓, pings DB every 240s to prevent Supabase pool sleep

### Code Fixes Applied
- **`src/lib/db.ts` `makePool()`**: Auto-detects internal hosts (helium, localhost, 127.0.0.1) and disables SSL; external hosts (Supabase) use `ssl: { rejectUnauthorized: false }`
- **`src/lib/db.ts` `getDbReady()`**: Wraps `runMigrations()` in try/catch; on failure returns `null` instead of throwing — prevents DB migration errors from crashing WHOIS/RDAP lookup flow
- **`src/lib/db-query.ts` `isDbReady()`**: Wrapped in try/catch so a DB error returns `false` rather than propagating
- **`src/data/cctld-whois-servers.json`**: Set `"vc": null` and `"lc": null` (TCP WHOIS server `whois.identitydigital.services` rejects connections; both now use RDAP via `rdap.identitydigital.services`)
- **`scripts/keep-alive.mjs`**: Updated to accept `POSTGRES_URL_NON_POOLING`, `SUPABASE_DATABASE_URL`, or `DATABASE_URL` as fallbacks; added same SSL auto-detection logic

## Replit Environment Setup (2026-03-27)

### Secrets Configured
- `POSTGRES_URL` — Supabase pooled connection (aws-1-ap-southeast-2.pooler.supabase.com:5432)
- `VERCEL_TOKEN` — Vercel personal access token for deployment
- `GITHUB_TOKEN` — GitHub classic token for repo access

### Files Created / Fixed
- **`src/lib/whois/whois_gtld_bootstrap.ts`** — Created missing WHOIS server bootstrap (510 entries covering gTLDs + ccTLDs). Was imported in `lookup.ts` but absent from the codebase, causing a module-not-found error on WHOIS queries.
- **`src/lib/whois/lookup.ts`** — Fixed TypeScript error: `WhoisRawResult.server` changed from `server: string` (required) to `server?: string` (optional) to match the `WhoisRaw` local type used by the shadow WHOIS promise. This resolved 9 TS errors (`tsc --noEmit --skipLibCheck` now exits 0).
- **`src/lib/whois/rdap_gtld_bootstrap.ts`** — Created missing RDAP gTLD/ccTLD bootstrap (1198 entries from IANA dns.json, generated 2026-03-27). Imported by `rdap_client.ts` but absent, causing all gTLD RDAP lookups to fail the local fast path and fall through to `node-rdap` IANA auto-discovery (extra network round-trip). Now eliminates IANA round-trip for all 1198 known TLDs.

### Local Server List Architecture (Query Speed Optimization)
Three layers of local server tables avoid IANA round-trips on first query:

| Layer | File | Entries | Coverage |
|---|---|---|---|
| ccTLD RDAP overrides (hand-curated) | `rdap_client.ts` → `CCTLD_RDAP_OVERRIDES` | 168 | 168 ccTLDs → direct RDAP, no IANA |
| gTLD+ccTLD RDAP bootstrap (IANA) | `rdap_gtld_bootstrap.ts` | 1198 | All IANA-listed TLDs → direct RDAP |
| WHOIS server bootstrap | `whois_gtld_bootstrap.ts` | 510 | Key TLDs incl. .com/.net/.org/.io → direct WHOIS |

**Query flow for .com (example):**
- Before: WHOIS → whois.iana.org (discover) → whois.verisign-grs.com + RDAP → download dns.json (download) → rdap.verisign.com (2× IANA round-trips)
- After: WHOIS → whois.verisign-grs.com directly + RDAP → rdap.verisign.com/com/v1/ directly (0 IANA round-trips)

**ccTLD RDAP direct mode** (`rdapIsDirect = true` when TLD in `RDAP_DIRECT_CCTLDS`):
- RDAP query fires immediately to curated endpoint (e.g. `rdap.denic.de` for .de)
- WHOIS starts as shadow at t=2s (reduced worst-case latency for RDAP-first registries)
- RDAP wins: shadow WHOIS cancelled; RDAP slow: shadow WHOIS provides fallback data

### Config Changes
- **`next.config.js`** — Added `*.worf.replit.dev` to `allowedDevOrigins` (Replit rotates dev subdomains between `kirk`, `worf`, etc.)

### Dev Environment Variables
- `NEXTAUTH_URL` / `NEXT_PUBLIC_BASE_URL` — Updated to current Replit dev domain (must be refreshed if the dev domain changes)

## Vercel Compatibility Fixes (2026-03-27)

### Issues Fixed
- **`vercel.json`** — Added `maxDuration` for previously unconfigured Vercel functions:
  - `src/pages/[...query].tsx` → 30s (main SSR lookup page, was using Vercel default 60s; explicit 30s is safe and matches `api/lookup`)
  - `src/pages/api/admin/git-force-push.ts` → 60s
  - `src/pages/api/admin/changelog-sync.ts` → 30s
  - `src/pages/api/admin/setup.ts` → 30s
  - `src/pages/api/cron/ping.ts` → 10s
- **`src/pages/api/user/forgot-password.ts`** — Changed localhost fallback (`"http://localhost:5000"`) to `"https://x.rw"`. On Vercel, `NEXT_PUBLIC_BASE_URL` / `NEXTAUTH_URL` always takes precedence; fallback is never reached, but the correct value is now in place.
- **`src/pages/api/admin/settings.ts`** — Changed `Cache-Control: public, max-age=15` → `private, no-store`. The settings endpoint can return sensitive server-only keys (`smtp_pass`, `captcha_secret_key`) for admin users. Using `public` caused Vercel's Edge Cache to potentially serve admin-scoped responses to subsequent non-admin requests. Now `private, no-store` prevents any CDN/proxy caching.
- **`src/pages/api/admin/git-force-push.ts`** — Added early Vercel environment check: if `process.env.VERCEL` is set, returns a 400 with an informative Chinese-language message explaining the tool is not available on read-only Vercel deployments. Previously would silently fail with confusing git errors.

### Confirmed Non-Issues (Vercel-safe)
- **`admin/tld-rules.ts`** filesystem ops — already wrapped in try/catch with `console.warn`; silently degrades on Vercel's read-only FS, uses Redis/DB as primary storage.
- **`api/lookup.ts` rate limiting** — in-process Map for brute-force tracking is ephemeral per Lambda instance; Redis-based rate limiter is the primary mechanism and persists correctly.
- **Main lookup page** — `getServerSideProps` calls `lookupWhoisWithCache` directly (not via `/api/lookup`), bypassing all rate limits. This is intentional per design.
- **`.co`/`.io` slow lookups** — were Replit network blocks. On Vercel both are in `CCTLD_RDAP_OVERRIDES` and use direct RDAP endpoints.

## TLD Probe, Git Fix & Performance Optimization (2026-03-27)

### TLD Fast-Path Optimization (STATIC_ALWAYS_FALLBACK expansion)
Expanded `STATIC_ALWAYS_FALLBACK` in `tld-fallback-gate.ts` from 9 → 25 TLDs:
- **Added**: `an`, `tp`, `aq`, `bv`, `sj`, `um`, `bl`, `bq`, `eh`, `fk`, `gb`, `gm`, `gu`, `mf`, `mh`, `va`
- All are confirmed to have no public WHOIS server (cctld-whois-servers.json = null) AND no accessible RDAP endpoint
- **Key optimization in `lookup.ts`**: Added `isStaticAlwaysFallback()` fast-path that **completely skips RDAP+WHOIS** and goes straight to yisi/tianhu for these TLDs, saving 4-9 seconds of timeout overhead per query
- Exported new `isStaticAlwaysFallback(domain)` function from `tld-fallback-gate.ts`

### Module-Level Pre-Warming (Cold Start Reduction)
In `lookup.ts` (at module load time, runs once per Lambda instance):
- Pre-seeds `initRdapSkipCache()` — RDAP skip list loaded from DB before first query
- Pre-seeds `isTldFallbackEnabled()` — fallback gate DB data loaded before first query
- Combined with existing `getWhoiser()` pre-warm, all 3 caches are ready before any user query arrives

### Git Push Fix (PUSH_REJECTED)
Updated `git-force-push.ts` to support two modes:
- **`pull_push`** (default): `git fetch` → `git merge origin/<branch>` → `git push` — safe, preserves remote commits
- **`force`**: `git push --force` — overwrites remote, use when there's no valid data on remote
- Both modes: auto-remove `index.lock`, abort pending merges/rebases, show last 3 commits before push

Updated `git-fix.tsx` admin page (rewritten with AdminLayout, Tailwind/components):
- Mode selector UI (Sync Push recommended / Force Push) — consistent design system
- Show/hide token button using RiEyeLine/RiEyeOffLine icons
- Colored log output with Tailwind bg/text classes
- Contextual hint when push fails (suggest switching mode)

### Balance Recharge via Payment (Gap 1 resolved, 2026-03-28)
- `payment_plans.balance_grant_cents` column added (ALTER TABLE migration in `src/lib/db.ts`)
- `src/lib/payment.ts`:
  - `PaymentPlan` type + `getActivePlans()` now include `balance_grant_cents`
  - `createOrder()` stores `balance_grant_cents` from plan onto the order
  - `markOrderPaid()` credits `users.balance_cents` and inserts `balance_transactions` record when `balance_grant_cents > 0`
- `src/pages/api/admin/payment/plans.ts`: GET/POST/PUT all include `balance_grant_cents`
- `src/pages/admin/payment/plans.tsx`: form field for balance_grant_cents (in cents), badge in plan card
- `src/pages/dashboard.tsx` plan cards: shows `+¥X 余额` badge and coin icon for balance plans
- `src/pages/payment/checkout.tsx`: Plan type + card badge + order summary row for balance grants

### Balance Transaction History in Admin (Gap 2 resolved)
- `src/pages/api/admin/balance-transactions.ts`: GET endpoint returns last 100 transactions for a user
- `src/pages/admin/users.tsx` EditModal: "查看余额记录" toggle shows inline scrollable transaction list

### TLD Probe Admin Page (Gap 4 resolved)
- `src/pages/admin/tld-probe.tsx`: full admin UI — stat cards (static fallback count, RDAP/WHOIS known counts), TLD input with presets, probe execution, filterable results table with result badges and latency column

### New Admin API: TLD Probe (`/api/admin/tld-probe`)
- **GET**: Returns `static_always_fallback`, `rdap_overrides_known`, `whois_known` lists
- **POST `{tlds: string[], timeout: number}`**: Probes up to 30 TLDs for direct connectivity
  - Per TLD: tries RDAP (if known override URL), then TCP WHOIS (port 43)
  - Returns `result`: `"rdap"` | `"whois"` | `"static_fallback"` | `"none"`, latency, method used
  - Summary: count per result type
- Useful for verifying which TLDs can be queried natively from Vercel vs which need fallback

## Multi-Model AI System for TLD Scraping (Added 2026-03-26)

### Architecture
- **`src/lib/server/ai-providers.ts`** — 13 models across 7 providers, priority-ordered fallback
  - Zhipu (ZHIPU_API_KEY): GLM-4-FlashX (p10), GLM-4-Flash (p11), GLM-4-Air (p20)
  - Groq (GROQ_API_KEY): Llama-3.3-70B (p15), Gemma2-9B (p25)
  - Google (GEMINI_API_KEY): Gemini-2.0-Flash (p12), Gemini-1.5-Flash (p22)
  - DeepSeek (DEEPSEEK_API_KEY): DeepSeek-V3 (p13)
  - DashScope/Qwen (DASHSCOPE_API_KEY): Qwen-Turbo (p18), Qwen-Long (p28)
  - Moonshot/Kimi (MOONSHOT_API_KEY): moonshot-v1-8k (p19)
  - SiliconFlow (SILICONFLOW_API_KEY): Qwen2.5-7B (p30), Llama-3.1-8B (p31)
- **`callProviderWithFallback(messages, preferredId?, errors?)`** — tries providers in priority order, returns `{ content, provider }`
- **`/api/admin/ai-models`** — GET endpoint listing all providers + configured status
- **DB change**: `model_used TEXT` column added to `tld_rules` via ALTER TABLE IF NOT EXISTS

### Smart URL Discovery
When IANA page has no lifecycle keywords, the scraper:
1. Extracts registry URL from "URL for registration services:" field
2. Tries 13 common lifecycle path suffixes on the registry domain
3. If lifecycle info found → uses that page; caches discovery in Redis 7 days
4. Falls back to IANA page if registry lifecycle page not found
5. Combines IANA + registry text when both have relevant info

### Smart URL Discovery (3-strategy cascade)
1. **Homepage check**: Fetch registry homepage → check for lifecycle keywords
2. **Path probing**: Try 21 common lifecycle URL patterns (`/lifecycle`, `/domain-lifecycle`, `/policies`, etc.)
3. **Link crawling**: Parse homepage + linked pages for lifecycle-looking links → follow them (depth=2)
   - Detected .jp JPRS: found `ライフサイクル` page via homepage
   - Detected .au auDA: found via policy links
   - JS-rendered sites (.de DENIC, .fr, .uk nic.uk): fall back to ICANN defaults
4. Discovery cache: Redis 7 days; combined text = IANA header (1.5k) + lifecycle page (7.5k)

### Keywords for lifecycle detection (multilingual)
- **English**: grace, redemption, pending delete, lifecycle, renewal period, rgp, etc.
- **Chinese**: 宽限期, 赎回期, 待删除, 续费, 到期, etc.
- **Japanese**: ライフサイクル, 猶予期間, 回復期間, 削除待ち, 更新期間, 削除
- **Korean**: 갱신유예, 복구기간, 삭제대기, 라이프사이클
- **German**: löschfrist, kündigungsfrist, löschung
- **French**: période de grâce, rédemption
- Link keywords: same languages + URL path keywords (lifecycle, renewal, expir, policy, delete)
Text extraction prioritizes keyword-containing lines (70/30 split) within 10k char limit.

### DB Schema additions
- `manually_edited BOOLEAN DEFAULT FALSE` — marks admin-manually-edited records; auto-scraper skips these unless `force=true`

### API endpoints (PATCH added)
- **GET** `/api/admin/tld-rules` — includes `manually_edited` field
- **POST** `/api/admin/tld-rules` — scrape+AI extract; skips if `manually_edited=true` OR data fresh
- **PATCH** `/api/admin/tld-rules` — manual edit: saves values + sets `manually_edited=TRUE`, `confidence='high'`
- **DELETE** `/api/admin/tld-rules` — removes rule

### Admin UI
- Model status badges in single-scrape form (✓/✗ per configured model)
- Model selector dropdown in single-scrape form
- Batch panel model selector (AI 自动选择 / specific model)
- Results show `model_used` and `has_lifecycle_info` warning when page has no data
- Auto-discovered source URL displayed when different from requested URL

## Payment System (Added 2026-03-24)

### Architecture
- **DB tables**: `payment_plans` + `payment_orders` (in `src/lib/db.ts`)
- **Core library**: `src/lib/payment.ts` — order lifecycle, provider signing/verification
- **API routes**:
  - `GET /api/payment/plans` — public plan listing
  - `POST /api/payment/create` — create order + redirect URL
  - `GET /api/payment/status?order=ID` — order status polling
  - `POST /api/payment/webhook/stripe` — Stripe payment confirmation
  - `POST /api/payment/webhook/xunhupay` — Xunhupay (虎皮椒) confirmation
  - `POST /api/payment/webhook/alipay` — Alipay confirmation
  - `GET/POST /api/admin/payment/plans` — admin CRUD
  - `GET/POST /api/admin/payment/orders` — admin order management + mark-paid/refund
- **User pages**:
  - `/payment/checkout` — plan selection + provider selection + checkout
  - `/payment/result?order=ID` — payment result with auto-polling
- **Admin pages**:
  - `/admin/payment/plans` — plan CRUD (price, duration, currency, active toggle)
  - `/admin/payment/orders` — order listing with stats, filters, manual mark-paid/refund
  - Settings → 支付网关 — enable/disable providers, set public keys

### Providers
| Provider | Enable Flag | Public Key Setting | Private Key ENV |
|---|---|---|---|
| Stripe | `payment_stripe_enabled` | `payment_stripe_pk` | `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` |
| Xunhupay (虎皮椒) | `payment_xunhupay_enabled` | `payment_xunhupay_appid` | `XUNHUPAY_APP_SECRET` |
| Alipay (官方) | `payment_alipay_enabled` | `payment_alipay_appid`, `payment_alipay_notify_url` | `ALIPAY_PRIVATE_KEY`, `ALIPAY_PUBLIC_KEY` |

### Flow
1. Admin creates plans in `/admin/payment/plans`
2. Admin enables providers in Settings → 支付网关
3. User visits `/payment/checkout`, selects plan + provider
4. Provider redirect → webhook fires → `markOrderPaid()` sets `subscription_access=TRUE` + creates sponsor record
5. User lands on `/payment/result?order=ID` (auto-polls until paid)
6. Dashboard shows "购买套餐解锁" button when any provider is enabled

---

A fast, modern WHOIS and RDAP lookup tool supporting domains, IPv4/IPv6, ASN, and CIDR. Also includes built-in DNS, SSL certificate, and IP/ASN geolocation tools.

---

## Changelog

### v3.23.1 — Stamp Popup Redesign: 3 Layouts × 3 Colors = 9 New Themes (2026-03-26)

**Files:** `src/pages/[...query].tsx`, `src/components/stamp-preview-card.tsx`

**New layout types added to `CardThemeDef.layout`:** `"classic"` | `"hero"` | `"minimal"`

**9 new themes in `CARD_THEMES` / `STAMP_CARD_THEMES`:**
- **Classic (Style A — gradient hero strip + floating white card):** `blue-classic`, `purple-classic`, `green-classic`
  - Gradient hero area at top (64×64 glass icon, dot texture, white × close), floating `-mt-10` white card below with badge + title + description, full-width CTA button
- **Hero (Style B — full-screen immersive gradient):** `blue-hero`, `purple-hero`, `green-hero`
  - Full gradient fills the dialog, centered icon + title + badge + description, frosted-glass CTA button at bottom, text "Close" link
- **Minimal (Style C — compact centered card):** `blue-minimal`, `purple-minimal`, `green-minimal`
  - Pure white card, 56×56 colored icon, title 20px bold, description 13px, small tag badge, full-width rounded CTA, domain hint at bottom

**Design spec met:**
- Logo 64×64 (56×56 minimal) rounded-[18px] glass/colored
- Title 20–22px font-black, centered
- Description 13px, text-gray-500, line-height 1.6
- Badge: rounded-full (classic/hero) or rounded-md (minimal), accent-tinted
- CTA: rounded-xl, 48px touch height, accent color + white text
- Close: top-right 32×32 translucent circle (classic/hero) or small gray × (minimal)
- No "Esc to close" hint text in any new layout
- Dark mode compatible (gray-900/zinc-900 backgrounds)

**Admin preview:** `StampPreviewCard` also updated with all 9 themes + 3 mini-layout renderers. New themes auto-appear in `/admin/stamp-styles` standard group.

---

### System Audit Fixes (2026-03-26)

**Scope:** Bug fixes and performance improvements from comprehensive system audit.

#### Bug Fixes
- **Title element React warning** — 6 pages had multiple children inside `<title>` (JSX expression + string literal) which caused a React hydration warning and potentially wrong tab text. All fixed to use template literals: `payment/result.tsx`, `payment/checkout.tsx`, `stamp.tsx`, `remind/index.tsx`, `remind/cancel.tsx`, `dashboard.tsx`.
- **DB index references nonexistent column** — `idx_password_reset_email` on `password_reset_tokens` referenced column `user_email` which doesn't exist (table has `user_id`). Fixed to `idx_password_reset_user ON password_reset_tokens (user_id)`.
- **batch-scrape.mjs ignores DB fallback chain** — Script only read `POSTGRES_URL` and silently failed if only `SUPABASE_DATABASE_URL` was set. Now reads the full fallback chain: `POSTGRES_URL → POSTGRES_URL_NON_POOLING → SUPABASE_DATABASE_URL → DATABASE_URL`. Exits with clear error if none is found.
- **Redis double-connect in dev** — HMR re-imports in Next.js dev mode caused `createRedisConn()` to be called twice, logging `[Redis] Connected and ready` twice. Fixed by caching client and availability state on `global.__redisClient` / `global.__redisAvailable`.

#### Performance Improvements
- **FALLBACK_START_MS reduced** — Default reduced from 2000ms to 1200ms. Third-party fallbacks (Yisi/Tianhu) now start racing native lookups sooner for slow domains, reducing worst-case response time by ~800ms.
- **DB pool tuned** — `connectionTimeoutMillis` reduced from 10000ms to 5000ms (prevent 10s hangs on failed connections); `max` increased from 3 to 5 connections.
- **STATIC_NO_RDAP conflict note added** — Reverted an erroneous expansion that would have broken RDAP for 17 TLDs already covered by `CCTLD_RDAP_OVERRIDES` (kn, ag, lc, vc, gd, dm, tt, bb, ws, tv, pw, fm, ht, cu, sd, so, ye). These TLDs all have working RDAP servers. Added a comprehensive "DO NOT re-add" comment block to prevent the same mistake in future sessions. The `.kn` slow-query issue is due to `rdap.nic.kn` being unreliable — the runtime `markRdapSkipped()` mechanism will handle it after a few failures.

---

### Security & Feature Hardening (2026-03-26)

**Scope:** Comprehensive security audit and feature completeness pass across all API and page layers.

#### Critical Security Fixes
- **Session manipulation closed** — NextAuth JWT callback no longer trusts client-provided subscriptionAccess. Uses DB-validated refreshSubscription signal instead.
- **stamp/submit.ts** — Enforces member restrictions server-side (DB re-validated): free = 5-char tags, personal style, app theme only; members = 20-char, all styles/themes.
- **remind/submit.ts** — Validates membership from DB (not JWT) before enforcing the free-tier 5-domain limit.
- **Login brute-force** — Per-IP (20/10min) and per-email (10 failures = 30-min lockout) in NextAuth authorize callback.

#### Rate Limiting Added to All Sensitive APIs
- /api/payment/create: 5/min per IP
- /api/user/change-password: 5/15min per IP
- /api/user/apply-invite-code: 10/hr per IP (prevents code enumeration)
- /api/user/redeem-code: 10/hr per IP
- /api/user/contact: 3/hr per IP
- /api/sponsors/submit: 3/hr per IP
- /api/user/profile PATCH: 10/min per IP
- requireAdmin() on all admin APIs: 60/min per IP

#### Security Headers (next.config.js)
- X-Frame-Options: SAMEORIGIN
- X-Content-Type-Options: nosniff
- X-XSS-Protection: 1; mode=block
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()

#### Payment Flow Improvements
- Payment result page now auto-heals session subscription after confirmed payment
- Added order ID display on success; "Go to Dashboard" link on timeout
- sponsors/submit.ts: added rate limiting, currency/amount validation

#### Subscription Expiry Correctness
- apply-invite-code.ts: expired subscribers can now apply new codes correctly
- Login sets initial JWT subscriptionAccess respecting subscription_expires_at

### i18n Completion Pass (2026-03-26)

**Scope:** Full i18n audit and fix across all pages. All hardcoded Chinese UI text has been converted to use the translation system.

**Changes:**
- `admin-layout.tsx` fully converted to `useTranslation()` — "No Access" screen, nav items, tab labels all i18n'd; 39 new `admin.*` keys added to all 8 locale files
- `stamp.tsx` — `CARD_THEME_OPTIONS` gained `enLabel` field; 5 new `stamp.*` keys added; all remaining hardcoded Chinese JSX strings replaced with `s()` helpers
- `dashboard.tsx` — TypeScript errors fixed (`AVATAR_COLORS` missing `label`, `days ?? 0` fallback for number interpolation)
- `remind/index.tsx` — `t` callback cast fixed for TypeScript
- `common.*` locale section added: `common.retry` and `common.cancel` in all 8 locale files
- Intentionally retained: `zhLabel`/`enLabel` data fields, `isChinese ? "zh" : "en"` inline bilingual patterns in tlds.tsx/links.tsx/sponsor.tsx/tools.tsx (these already handle both languages correctly)
- TypeScript: clean compile (`tsc --noEmit --skipLibCheck` exits 0)


### v3.23.0 — ccTLD Connectivity Audit + RDAP/WHOIS Accuracy Pass (2026-03-28)

**Scope:** Full connectivity audit of all 166 RDAP overrides and 65 WHOIS-only ccTLD servers using live probing + Cloudflare DoH verification. Removed 46 dead/wrong RDAP entries that were causing unnecessary overhead and wasted timeout delays. Fixed `.jp` RDAP URL. Corrected 7 wrong WHOIS server entries. Added 9 permanently unreachable TLDs to `STATIC_ALWAYS_FALLBACK`. Net improvement: RDAP pass rate 55% → 75%, zero wasted round-trips to non-existent servers.

| File | Change | Detail |
|------|--------|--------|
| `src/lib/whois/rdap_client.ts` | **Removed 46 dead RDAP overrides** | All ENOTFOUND or SSL-error in both system DNS and Cloudflare DoH, none listed in IANA RDAP bootstrap. Commented in-place with reasons. Removed: su, tj (CIS); gl, xk (Europe); ao, bw, cd, dj, et, gh, mw, sc, ug, zw (Africa); bh, iq, jo, om, ps, sy (Middle East); bt, hk, kh, kr, mm, mn, mv, np, nu, nz, ph, pk, vu, ws (Asia/Pacific); ag, bb, co, cu, dm, jm, kn, lc, mx, pe, tt, vc (Americas). Active overrides reduced from 166 → 121. |
| `src/lib/whois/rdap_client.ts` | **Fixed `.jp` RDAP URL** | `rdap.jprs.jp` ENOTFOUND in all DNS resolvers; correct endpoint is `jprs.jp/rdap/` — confirmed HTTP 404 (RDAP alive). |
| `src/lib/whois/rdap_client.ts` | **`RDAP_TLD_TIMEOUT_MS` cleaned up** | Added `ar: 10000` (IANA-confirmed endpoint, slow from US cloud). Removed stale entries for deleted TLDs (su, gh, ug, zw, cm, cd, iq, sy, ps, pk, np, mm, kh, bt, mv). |
| `src/data/cctld-whois-servers.json` | **Fixed 7 wrong WHOIS servers** | `.ao` whois.dns.pt → null (Portugal DNS, not Angola registry); `.bt` whois.netnames.net → null (NXDOMAIN); `.gi` whois2.afilias-grs.net → null (NXDOMAIN); `.iq` whois.cmc.iq → null (NXDOMAIN); `.jo` whois.ripe.net → null (RIPE serves IP/ASN data, not .jo domains); `.sc` whois2.afilias-grs.net → `whois.nic.sc` (confirmed working via TCP test); `.tj` whois.nic.tj → null (NXDOMAIN in DoH). |
| `src/lib/whois/tld-fallback-gate.ts` | **9 new STATIC_ALWAYS_FALLBACK entries** | bb, co, dj, iq, jm, lc, tj, tt, vc — all confirmed RDAP ENOTFOUND/SERVFAIL + WHOIS NXDOMAIN via Cloudflare DoH. Immediately skip to yisi/tianhu without 3-failure learning cycle. |
| `scripts/audit-cctld-connectivity.mjs` | **Full connectivity audit script** | Tests all 166 RDAP overrides + 65 WHOIS servers concurrently (configurable concurrency), groups by pass/fail/error type, outputs actionable suggestions. |
| `scripts/test-rdap-whois.mjs` | **Alt-URL + WHOIS fallback tester** | Tests alternate RDAP base URLs and WHOIS TCP fallback for removed-RDAP TLDs. Confirms WHOIS works before RDAP removal. |

### v3.22.2 — RDAP Coverage Expansion: 168 ccTLDs + Conflict Fixes + Per-TLD Timeouts (2026-03-24)

**Scope:** Largest single RDAP coverage expansion yet. Fixed 15 blocking conflicts in `STATIC_NO_RDAP`, added 40+ new ccTLD RDAP servers confirmed by live probing, introduced per-TLD timeout map for slow registries, and set up automated monthly bootstrap refresh via GitHub Actions.

| File | Change | Detail |
|------|--------|--------|
| `src/lib/whois/tld-rdap-skip.ts` | **Fixed 15 critical STATIC_NO_RDAP conflicts** | `ru`, `by`, `kz`, `lb`, `ve`, `ec`, `tl`, `cd`, `af`, `gh`, `ug`, `et`, `ci`, `dj`, `ss` were in STATIC_NO_RDAP but also in CCTLD_RDAP_OVERRIDES, causing RDAP to be blocked entirely for these TLDs. All removed. STATIC_NO_RDAP reduced from ~25 → 21 genuinely RDAP-less TLDs. |
| `src/lib/whois/rdap_client.ts` | **CCTLD_RDAP_OVERRIDES expanded to 168 ccTLDs** | Added 40+ new entries: Western Europe (`at`, `be`, `ch`, `de`, `dk`, `ee`, `es`, `gr`, `hr`, `hu`, `ie`, `it`, `li`, `lt`, `lu`, `lv`, `me`, `pt`, `ro`, `rs`, `se`, `sk`), CIS (`by`, `kz`, `ru`, `su`), Other (`im`, `io`, `mn`, `my`, `nu`, `ph`, `hk`, `jp`, `kr`, `co`, `mx`, `pe`, `ve`, `za`). Entries reorganized by region. |
| `src/lib/whois/rdap_client.ts` | **`RDAP_TLD_TIMEOUT_MS` per-TLD timeout map** | 32-entry map with extended timeouts (6–8 s) for known-slow registries in Africa (`ng`, `ke`, `tz`, `gh`, `ug`), CIS (`ru`, `su`, `by`, `kz`), Middle East (`iq`, `sy`, `ye`), and Asia (`pk`, `np`, `mm`, `la`, `kh`). Default remains 4 s. |
| `src/lib/whois/rdap_client.ts` | **`lookupRdap` uses per-TLD timeout** | `RDAP_TLD_TIMEOUT_MS[tld] ?? 4000` passed to `tryRdapWithUrl` instead of hardcoded 4000. |
| `package.json` | **npm script** | `update:rdap-bootstrap` → `node scripts/update-rdap-bootstrap.js` for manual refresh. |
| `.github/workflows/update-rdap-bootstrap.yaml` | **GitHub Actions cron** | Runs `scripts/update-rdap-bootstrap.js` on the 1st of every month at 02:00 UTC, commits updated `rdap_gtld_bootstrap.ts` if changed. |

### v3.22.1 — Bug Fix Batch (2026-03-24)

**Scope:** Six targeted bug fixes across lookup recording, subscription session sync, query-only mode, admin pages, and announcement bar positioning.

**Changes:**

| File | Fix | Detail |
|---|---|---|
| `src/pages/api/lookup.ts` | Search history for logged-in users | Added `getServerSession` call; `saveSearchRecord` now accepts optional `userId` — logged-in users get their own `user_id`-linked records (upsert via delete+insert), anonymous users retain existing trim-to-50 logic. |
| `src/pages/dashboard.tsx` | Subscription session sync | When `apply-invite-code` returns "你已拥有订阅权限" (DB has access, JWT doesn't), client now calls `updateSession({ subscriptionAccess: true })` and switches to subscriptions tab instead of showing an error. |
| `src/components/navbar.tsx` | query_only_mode hides HistoryDrawer | `HistoryDrawer` reads `query_only_mode` from site settings via `useSiteSettings()` and returns `null` for non-admin users when the mode is enabled. Early return placed after all hooks to comply with React rules. |
| `src/pages/_app.tsx` | Announcement bar overlap fix | `AnnouncementBanner` sets CSS custom property `--ann-h` (36px when visible, 0px when dismissed) on the document root. Main element padding updated to `calc(4rem + var(--ann-h, 0px))`. |
| `src/components/navbar.tsx` | Navbar clears announcement overlap | Outer div uses `style={{ top: 'var(--ann-h, 0px)', transition: 'top 0.2s ease' }}` instead of hard-coded `top-0`, smoothly sliding below the announcement bar. |
| `src/pages/admin/tld-lifecycle.tsx` | Built-in lifecycle reference table | Added collapsible section showing all LIFECYCLE_TABLE entries. Each row has "添加覆盖" that pre-fills the form; already-overridden TLDs show a "已覆盖" badge. |
| `src/pages/admin/reminders.tsx` | Edit + Send Email for reminders | Added inline edit panel per record (domain, email, expiration_date, days_before); added send-email button (plane icon). |
| `src/pages/api/admin/reminders.ts` | Extended PATCH + POST send-email | PATCH now updates any combination of domain/email/expiration_date/days_before/active. New POST `?action=send-email` fetches reminder, computes daysLeft, sends `reminderHtml` via Resend. |

---

### v3.22 — Comprehensive Multilingual WHOIS Status Detection (2026-03-24)

**Scope:** Full multilingual expansion of domain status detection (reserved / prohibited / suspended). Both `common_parser.ts` (server-side) and `[...query].tsx` (client-side safety net) are now synced with identical pattern coverage for 25+ languages/registries.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/whois/common_parser.ts` | `syntheticReserved` expansion | Added field:value regex patterns for Italian `riservato`, Swedish `reserverad`, Norwegian `reservert`, Danish `reserveret`, Polish `zarezerwowany`, Dutch `gereserveerd`, Finnish `varattu`, Hungarian `fenntartott`, Romanian `rezervat`, Turkish `rezerve`, Greek `δεσμευμένο`; direct includes for Russian `зарезервирован`/`зарезервировано`/`зарезервирована`, Ukrainian `зарезервовано`, Japanese `予約済み`/`登録停止`, Korean `예약됨`/`예약된`, Arabic `محجوز`, Hebrew `שמור`, Traditional Chinese `保留網域`. |
| `src/lib/whois/common_parser.ts` | `syntheticProhibited` expansion | Added Russian `запрещена регистрация`/`регистрация запрещена`, Ukrainian `реєстрація заборонена`, Italian `registrazione vietata`/`status: vietato`, Japanese `登録不可`/`登録制限`, Korean `등록불가`/`등록 금지`, Arabic `محظور`, Chinese `不可注册`/`禁止使用`. |
| `src/lib/whois/common_parser.ts` | `syntheticSuspended` expansion | Added Portuguese `suspenso`, Italian `status: sospeso`/`dominio sospeso`, Dutch `opgeschort`, Polish `zawieszony`, Finnish `keskeytetty`, Russian `приостановлен`/`приостановлено`, Ukrainian `призупинено`, Japanese `停止中`/`利用停止`, Korean `정지됨`/`사용 정지`, Arabic `موقوف`/`معلق`, Chinese `已停用`/`暂停使用`. |
| `src/pages/[...query].tsx` | `rawHasReserved` / `rawHasProhibited` / `rawHasSuspended` | Synced with identical expanded pattern lists from `common_parser.ts`. Latin-script patterns use field:value regex to avoid false positives from domain names containing those words. Non-Latin scripts use direct includes (safe: domain names are punycode in WHOIS). |
| `src/lib/env.ts` | VERSION bumped to "3.22" | |

**Design rationale:**
- Latin-script single words (e.g. `reserviert`, `riservato`) use `/\bstatus\s*:\s*<word>\b/` regex OR require phrase context, preventing false positives when a domain name itself contains that word (e.g. `riservato.it`).
- Non-Latin scripts (Cyrillic, CJK, Arabic, Hebrew) safely use `includes()` — domain labels appear as punycode (`xn--…`) in WHOIS, never as raw Unicode characters.

---

### v3.21 — Reserved/Premium Domain Detection + Multilingual Patterns (2026-03-24)

**Scope:** Introduced `registry-premium` status tag; added 30+ English reserved phrases; initial multilingual reserved/prohibited/suspended patterns.

---

### v3.20 — Invite Code System Overhaul + UX Fixes (2026-03-24)

**Scope:** Complete rebuild of invite code expiry, validation, and activation flow; fixed critical bug where optional invite codes were silently ignored during registration.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/db.ts` | Schema: `expires_at` | Added `ALTER TABLE invite_codes ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ` migration. |
| `src/pages/api/admin/invite-codes.ts` | Expiry support | POST now accepts `expires_in` (1d / 7d / 30d / 365d / permanent); GET returns `expires_at`; `parseExpiresAt()` helper converts preset to absolute timestamp. |
| `src/pages/api/user/apply-invite-code.ts` | Expiry + updated_at | Validates `expires_at` (rejects if past); updates `updated_at` on user row. |
| `src/pages/api/user/register.ts` | Critical bug fix | Previously, if `require_invite_code = "0"`, any invite code filled in by the user was silently ignored and `subscription_access` stayed `false`. Now: optional codes are still validated + applied, granting `subscription_access = true` on registration. Also adds expiry check. |
| `src/pages/admin/invite-codes.tsx` | UI overhaul | Stats grid → 5 columns (adds 已过期/red); filter tabs → 5 tabs (adds 已过期); create modal → expiry pill picker (永久/1天/1周/1月/1年); table → 有效期 column with relative display; purge button now targets both exhausted AND expired codes. |
| `src/pages/dashboard.tsx` | Better UX after activation | After successful code redemption: clears the input, switches to the subscriptions tab immediately, so users see their newly unlocked feature at once. |
| `src/lib/env.ts` | VERSION bumped to "3.20" | |

---

### v3.19 — Fix Search Spinner on Nav Link Clicks (2026-03-24)

**Scope:** Bug fix — the search button spinner was incorrectly showing when clicking ordinary nav links (e.g. About, Links, Admin pages) from the home page or a results page.

**Root cause:** Both `index.tsx` and `[...query].tsx` defined their own inline `isSearchRoute()` helper with a `STATIC_PATHS` allow-list. The list in `[...query].tsx` was incomplete (missing `/dns`, `/ssl`, `/ip`, `/icp`, `/about`, `/sponsor`, `/links`, `/changelog`, `/admin`, `/feedback`, etc.), so navigating to those paths from a results page would call `setLoading(true)` and spin the button indefinitely until the route completed.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/utils.ts` | `isSearchRoute()` shared export | Single canonical implementation with a complete `STATIC_PAGE_PREFIXES` allow-list; strips locale prefix before matching. |
| `src/pages/index.tsx` | Use shared `isSearchRoute` | Removed inline copy; imports from `@/lib/utils`. |
| `src/pages/[...query].tsx` | Use shared `isSearchRoute` | Removed inline copy (which had the incomplete prefix list); imports from `@/lib/utils`. |
| `src/lib/env.ts` | VERSION bumped to "3.19" | |

---

### v3.18 — Admin Access Keys Enrichment (2026-03-24)

**Scope:** Enriched the API 密钥 (access-keys) admin page with stats, dual filter rows, and bulk expired-key cleanup — matching the quality bar set for invite-codes in v3.17.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/admin/access-keys.tsx` | Stats grid | Added 4-stat grid: 全部 / 启用中 / 已停用 / 已过期 (red). |
| `src/pages/admin/access-keys.tsx` | Dual filter rows | Row 1: status filter pills (全部/启用/停用/已过期); Row 2: scope filter pills (全部范围/API/域名订阅/全部权限). Both compose together. Fixed "all" naming ambiguity by using `__any__` as the scope-filter sentinel. |
| `src/pages/admin/access-keys.tsx` | Relative last-used time | "最近使用" column now shows relative time (刚刚 / N分钟前 / N小时前 / N天前) with clock icon, and "从未使用" when `last_used_at` is null. |
| `src/pages/admin/access-keys.tsx` | Bulk purge + header count | "清理过期 (N)" button in header batch-deletes all expired keys; cumulative call count shown in subtitle. |
| `src/lib/env.ts` | VERSION bumped to "3.18" | |

---

### v3.17 — Admin Page Enrichment: Feedback, Invite Codes & Links (2026-03-24)

**Scope:** Enriched three admin management pages with richer filtering, stats, and bulk operations.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/api/admin/feedback.ts` | Issue-type filter + typeCounts | `GET` now accepts `issue_type` query param to filter by a single issue type; response includes `typeCounts` map (aggregated via `jsonb_array_elements_text`). |
| `src/pages/admin/feedback.tsx` | Stats bar + filter tabs | Added 5-card issue-type stats bar (不准确/不完整/过期/解析错误/其他) with percentage, each card clickable as a filter shortcut; pill-style filter tabs with per-type count badges; search and type filter compose together. |
| `src/pages/admin/invite-codes.tsx` | Stats grid + filter tabs + usage progress + bulk-delete | Added 4-stat grid (全部/可用/停用/耗尽); pill filter tabs (全部/可用/已停用/已耗尽); each code row now shows a colour-coded progress bar (green→amber at ≥80%); "清理耗尽" button batch-deletes all exhausted codes. |
| `src/pages/admin/links.tsx` | Category filter tabs + visibility toggle + stats | Added 3-stat grid (总数/已显示/分类数); dynamic per-category pill tabs derived from existing category values; "未分类" tab when uncategorised links exist; "隐藏已隐藏/显示已隐藏" toggle button shows count of hidden links. |
| `src/lib/env.ts` | VERSION bumped to "3.17" | |

---

### v3.16 — UX Animations Overhaul + No-Server TLD Fast-Fail (2026-03-24)

**Scope:** Mobile UX polish and WHOIS lookup hot-path optimization.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/_app.tsx` | Removed `RouteLoadingBar` | Deleted the 2 px top loading bar and its 50-line component. Text skeleton + shimmer already provide query feedback; the bar was visually redundant. |
| `src/pages/_app.tsx` | Smoother page transition | `pageTransition` duration 0.13 s → 0.20 s; easing `"easeOut"` → cubic-bezier `[0.22, 1, 0.36, 1]` (iOS-style spring feel). |
| `src/pages/[...query].tsx` | Improved card stagger | `CARD_CONTAINER_VARIANTS` stagger 0.025 s → 0.09 s; `CARD_ITEM_VARIANTS` now includes `y: 10 → 0` slide-up with `[0.22, 1, 0.36, 1]` easing, creating a natural "main content first, secondary sidebar after" reveal on mobile. |
| `src/pages/[...query].tsx` | WHOIS/RDAP tab fade | `ResponsePanel` tab content wrapped in `AnimatePresence mode="wait"` — switching between WHOIS and RDAP now cross-fades (0.15 s) instead of hard-cutting. |
| `src/lib/whois/lookup.ts` | `isTldKnownNoServer` hot-path check | Imported from `custom-servers.ts` and checked immediately before the whoiser TCP call. When a TLD is explicitly listed as `null` in `cctld-whois-servers.json`, throws instantly (0 ms) instead of waiting for a TCP timeout, letting the tianhu/yisi fallback race immediately. |
| `src/lib/env.ts` | VERSION bumped to "3.16" | |

---

### v3.15 — DB Cache Fix: In-Memory TLD Gate + Expanded RDAP/WHOIS Skip Lists (2026-03-24)

**Scope:** Eliminated the biggest remaining latency source — a Supabase DB query on every single WHOIS request — and expanded both the RDAP-skip and ccTLD-server lists.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/whois/tld-fallback-gate.ts` | Rewrote with in-memory startup cache | `isTldFallbackEnabled()` was hitting Supabase on every call. Now loads the entire `tld_fallback_overrides` table once at startup into a `Map`; subsequent calls are pure memory lookups (0 ms). Cache invalidated via `invalidateFallbackCache()`. Result: `ab.cd` query time 12 s → 1.26 s. |
| `src/lib/whois/tld-rdap-skip.ts` | Expanded `STATIC_NO_RDAP` | Added 17 confirmed no-RDAP ccTLDs: `.ac .aw .ax .bj .bv .cc .cg .cx .gg .hm .im .je .ms .pm .re .sh .yt`. Prevents wasted RDAP round-trips for these TLDs. |
| `src/data/cctld-whois-servers.json` | Comprehensive ccTLD server list | Grew from 206 → 255 entries covering all IANA ccTLDs. Added working servers for `.ad` (nic.ad), `.bh` (nic.bh), `.fm` (nic.fm), `.gf/.gp/.mq` (whois.nic.mq), `.gn` (ande.gov.gn), `.ls/.mc/.mr/.sl/.sm/.ss/.td` (nic.{tld}), `.mt` (whois.ripe.net), `.sr` (whois.sr), `.ye` (y.net.ye). `null` entries for TLDs with no reachable public server (`.cu`, `.kp`, `.gb`, etc.). |
| `src/lib/whois/custom-servers.ts` | `isTldKnownNoServer()` added | Exposes which TLDs are explicitly `null` in the cctld file. Builds a `Set<string>` (`_knownNoServerCache`) during `getAllCustomServers()` load; `isTldKnownNoServer(tld)` is a fast O(1) lookup. |
| `src/lib/env.ts` | VERSION bumped to "3.15" | |

---

### v3.14 — Query Speed: Timeout Tuning + Parallel Fallback Racing (2026-03-24)

**Scope:** Reduced all network timeouts and started the third-party fallback in parallel with native lookups instead of waiting for full TCP failure.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/whois/lookup.ts` | Timeout reductions | `RDAP_TIMEOUT` 7 s → 2 s; `WHOIS_TIMEOUT` 7 s → 4 s; `FALLBACK_START_MS` added at 2 s — fallback races natively after this delay instead of waiting for TCP timeout. |
| `src/lib/whois/tianhu-fallback.ts` | `TIANHU_TIMEOUT` | Set to 4 s (was unbounded). |
| `src/lib/whois/yisi-fallback.ts` | `YISI_TIMEOUT` | Set to 4 s (was unbounded). |
| `src/lib/pricing/client.ts` | Pricing timeout | Reduced to 4 s. |
| `src/lib/env.ts` | VERSION bumped to "3.14" | |

---

### v3.13 — Remove MOZ DA/PA/Spam Feature (2026-03-24)

**Scope:** Removed the MOZ Domain Authority / Page Authority / Spam Score feature entirely from the domain result page.

**Changes:**

- Removed all MOZ API calls, UI components, and related code from `src/pages/[...query].tsx`
- Removed MOZ-related environment variable references
- Cleaned up unused imports and state variables
- `src/lib/env.ts` VERSION bumped to "3.13"

---

### v3.12 — X.RW Full Rebranding + WeChat OG Image Fix (2026-03-24)

**Scope:** Complete visual rebranding to X.RW identity, with brand image assets and social sharing fixes.

**Changes:**

- Replaced all NEXT WHOIS branding with X.RW across navbar, OG images, meta tags, and site settings defaults
- Added X.RW brand images (`/public/brand/`) for OG cards and apple-touch-icon
- Fixed WeChat `og:image` — now always resolves to an absolute URL using canonical site origin
- Updated `apple-touch-icon`, `manifest.json` icons, and PWA manifest to X.RW assets
- `src/lib/env.ts` VERSION bumped to "3.12"

---

### v3.11 — Brand Stamp Certification: tian.hu / nazhumi.com / yisi.yun (2026-03-24)

**Scope:** Certified three technology-partner domains as official brand stamps in the X.RW stamp registry.

**Changes:**

- Added verified brand stamps for `tian.hu` (tianhu WHOIS data provider), `nazhumi.com` (domain pricing data), and `yisi.yun` (WHOIS fallback API)
- Stamp records created with `brand` style and appropriate card themes
- `src/lib/env.ts` VERSION bumped to "3.11"

---

### v3.10 — OG Image Text Editor, Changelog Sync & UX Cleanup (2026-03-24)

**Scope:** Admin panel enhancements and UX improvements.

**New features / fixes:**

- **OG image text editor (`/admin/og-styles`):** Brand name and tagline are now fully editable in the admin panel. Settings stored in `site_settings` (`og_brand_name`, `og_tagline`) with 5-minute server-side cache invalidation. Both fields are immediately reflected across all 8 OG card styles without code changes.
- **`api/og.tsx` — dynamic text:** All 10 hardcoded `"RDAP+WHOIS"` brand label occurrences across the 8 OG styles now read from the config API. Taglines similarly use the configurable tagline field. Default values remain `"RDAP+WHOIS"` and `"WHOIS / RDAP · Domain Lookup Tool"` when not overridden.
- **`api/og-config.ts` — extended config:** Config API now returns `brand_name` and `tagline` alongside `enabled_styles`, and accepts `PUT` requests to update them.
- **Changelog sync button (`/admin/changelog`):** "同步版本历史" button batch-imports predefined version entries (v3.6–v3.10) from the `changelog-sync` API, skipping duplicates. Useful for seeding a fresh DB.
- **User dashboard — value-tier badges hidden:** High-value / valuable domain badges in the search history list are no longer shown to users (data is still recorded server-side for admin analytics). Removed `tierCfg` badge render; `TIER_CFG` definition and `value_tier` recording untouched.

---

### v3.9 — API Key Authentication System (2026-03-24)

**Scope:** Complete API Key management system. Admins can create, revoke, and scope access keys, and optionally enforce key authentication across all public API endpoints.

**New features:**

- **`access_keys` DB table:** Stores keys with fields: `id`, `key` (`rwh_` + 40 hex), `label`, `scope` (`api` / `subscription` / `all`), `is_active`, `created_at`, `expires_at`, `last_used_at`, `use_count`. Auto-provisioned via `initDb()`.
- **`src/lib/access-key.ts` library:** `generateKey()` (rwh_ prefix + 40 hex chars), `validateApiKey()` (checks active, expired, scope), `extractApiKey()` (reads `X-API-Key` header or `?key=` query param), `enforceApiKey(req, res, scope)` (returns `boolean` — returns early if invalid), `isApiKeyRequired()` (reads `site_settings.require_api_key` with 30 s in-memory cache).
- **`/api/admin/access-keys` endpoint (GET/POST/PATCH/DELETE):** Full CRUD + a `POST { action: "toggle_require", enabled: bool }` to flip global enforcement; cache invalidated on toggle.
- **`/admin/access-keys` page:** Lists all keys (masked), shows scope badge, use count, last-used date; global enforcement toggle; "Generate Key" modal with label/scope/expiry fields; newly-created key revealed once in a dismissible alert; per-row enable/disable and delete actions.
- **Admin nav:** Added "密钥" entry pointing to `/admin/access-keys`.
- **API enforcement:** `enforceApiKey()` inserted (after rate limit, before business logic) in `api/lookup.ts`, `api/dns/records.ts`, `api/dns/txt.ts`, `api/ssl/cert.ts`, `api/ip/lookup.ts`. When `require_api_key = 0` (default), enforcement is a no-op (zero overhead).
- **Docs page:** New "API Key 鉴权" section with `#api-key` anchor; nav pill added; covers: header vs query-param usage, scope table, error response codes (401 / 403). `SectionHeader` updated to accept optional `id` prop.

---

### v3.8 — Page Transition Fixes, URL Param Loading & API Rate Limiting (2026-03-23)

**Scope:** Fixed multiple UX and security bugs accumulated since v3.6. Transitions now reliably fire between domain searches; tool pages correctly load query params from the URL on first render; DNS/IP/SSL APIs are now rate-limited.

**Bug fixes:**

- **`_app.tsx` — animationKey logic was inverted:** Pages under `/[...query]` all shared the same animation key (`router.pathname` = `/[...query]`), so navigating between domain searches produced no transition. Fixed by swapping the key strategy: shallow tool pages (`/dns`, `/ssl`, `/ip`, `/icp`, `/stamp`) use `router.pathname` (so they don't re-animate when the query string changes), and all other pages (including `/[...query]`) use `router.asPath` (so each unique domain URL gets its own transition).
- **`_app.tsx` — Restored `AnimatePresence mode="wait" initial={false}`** with a `motion.div` using pure-opacity `pageVariants` (0 → 1, 0.13 s). The previous v3.6 CSS-only approach was removed in favour of this corrected Framer Motion approach.
- **`[...query].tsx` — Card stagger restored (opacity-only):** The over-aggressive v3.6 removal of all stagger is reverted. Cards now stagger at 0.025 s intervals with opacity-only variants (no y-axis movement), keeping the feel smooth without the earlier jitter.
- **`dns.tsx` / `ssl.tsx` / `ip.tsx` — `router.isReady` missing from `useEffect`:** All three tool pages were reading `router.query` in a `useEffect(fn, [])` that ran before Next.js had populated the query object on first render, causing URL `?q=` params to be silently ignored. Changed dependency arrays to `[router.isReady]` with an early-return guard.
- **DNS/IP/SSL APIs — no rate limiting:** `api/dns/records`, `api/dns/txt`, `api/ip/lookup`, and `api/ssl/cert` had no request throttling, leaving them open to abuse. Added in-memory `rateLimit()` checks (60/min for DNS, 30/min for IP, 20/min for SSL) with `429` responses.

---

### v3.7 — Smart Redis Cache with Adaptive TTL (2026-03-23)

**Scope:** Replaced the flat-TTL Redis cache with a domain-type-aware intelligent cache layer. All lookups now avoid redundant WHOIS/RDAP server calls, with cache expiry tuned to how quickly each domain type's data actually changes.

**Cache TTL strategy:**

| Domain type | TTL | Rationale |
|---|---|---|
| IP / ASN / CIDR query | 24 h | IP allocations change extremely rarely |
| Registry-reserved / pending | 12 h | Slow-moving administrative status |
| Available / unregistered | 5 min | Could be registered at any moment |
| Registered, expired (≤0 d) | 10 min | May be re-registered imminently |
| Registered, expiring ≤7 d | 30 min | Could change hands soon |
| Registered, remaining ≤60 d | 1 h | Watch for changes |
| Registered, remaining >60 d | 6 h | Very stable — safe to cache long |
| Error / failed lookup | 0 | Never cache failures |

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/whois/types.ts` | Added `cachedAt?: number` and `cacheTtl?: number` to `WhoisResult` | `cachedAt` = Unix ms timestamp when result was cached; `cacheTtl` = remaining TTL seconds (from Redis `TTL` command when serving from cache, or initial TTL when freshly computed). |
| `src/lib/server/redis.ts` | Production-grade Redis client rewrite | Added `lazyConnect: true`, `enableOfflineQueue: false` (commands fail immediately when disconnected instead of queuing), `retryStrategy` capped at 3 retries, per-event `_available` flag tracked via `ready`/`close`/`reconnecting`/`end` events. Added `getRemainingTtl(key)` and `getJsonRedisValueWithTtl(key)` helpers (pipeline GET + TTL in one round-trip). |
| `src/lib/whois/lookup.ts` | `computeSmartTtl(result)` function | Exported function that classifies a `WhoisResult` and returns the appropriate cache TTL in seconds. Zero means "do not cache". |
| `src/lib/whois/lookup.ts` | `lookupWhoisWithCache` upgraded | L1 (memory, 30 s) → L2 (Redis, smart TTL). Cache hits return `cachedAt` + `cacheTtl` from stored metadata + live Redis TTL. Cache misses: compute smart TTL, store `{ cachedAt, cacheTtl }` in the stored object, write to Redis with that TTL. Failures (status=false) are never cached. |
| `src/pages/api/lookup.ts` | Dynamic `Cache-Control` header | `s-maxage` is now set to the actual smart TTL (e.g. 21600 for stable domains, 300 for available). `stale-while-revalidate` = min(TTL × 4, 86400). Vercel edge cache now matches Redis expiry. Also passes `cachedAt` and `cacheTtl` through in the JSON response. |
| `src/pages/[...query].tsx` | Cache TTL displayed in result footer | When a result is served from cache, the time strip shows e.g. `0.00s · cached (6h)` — the parenthesised value is the remaining TTL from Redis, formatted as Xh / Xm / Xs. |
| `src/lib/env.ts` | VERSION bumped to "3.7" | |

**Environment variables (Redis connection — any one set activates Redis):**

| Variable | Description |
|---|---|
| `KV_URL` or `REDIS_URL` | Full Redis connection URL (e.g. `redis://...` or `rediss://...`). Vercel KV uses `KV_URL`. Upstash uses `REDIS_URL`. |
| `REDIS_HOST` | Redis hostname (used if URL not set) |
| `REDIS_PORT` | Redis port (default 6379) |
| `REDIS_PASSWORD` | Redis password |
| `REDIS_DB` | Redis database index (default 0) |

### v3.6 — Mobile Animation Fix: No More Flash/Jitter (2026-03-23)

**Scope:** Eliminated all sources of mobile page-transition flash and result-card jitter.

**Root causes fixed:**
1. `AnimatePresence mode="sync"` in `_app.tsx` caused old and new pages to overlap during navigation, making the background "bleed through" and flash white/dark between pages.
2. `CARD_ITEM_VARIANTS` with `y: 12` + `staggerChildren: 0.06` in `[...query].tsx` made result cards appear to jump upward one-by-one, visually jittery on mobile.
3. "Available domain" hero section in `[...query].tsx` had `delay: 0.15 / 0.2 / 0.35` on motion elements, causing content to pop in piece-by-piece.
4. `dns.tsx` result cards had `y: 4` + `delay: index * 0.03` stagger, causing visible card cascade on mobile.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/styles/globals.css` | Added `.page-enter` CSS class | Pure opacity fade-in (0.12 s ease-out) using `@keyframes page-enter`. No transform, no `will-change`. |
| `src/pages/_app.tsx` | Removed `AnimatePresence` + `motion.div` page wrapper | Replaced with a plain `<div key={animationKey} className="page-enter">`. React unmounts old div, mounts new div with CSS animation — zero overlap, zero background flash. Also removed unused `pageVariants`, `pageTransition` constants and framer-motion import from this file. |
| `src/pages/[...query].tsx` | `CARD_CONTAINER_VARIANTS`: removed stagger | Changed from `staggerChildren: 0.06, delayChildren: 0.02` to a simple `duration: 0.15` fade-in for the entire container. |
| `src/pages/[...query].tsx` | `CARD_ITEM_VARIANTS`: removed y-axis movement | Items are now `opacity: 1` in both hidden and visible states — the container fade handles the appearance. No per-item stagger or y-offset. |
| `src/pages/[...query].tsx` | "Available domain" hero: removed delayed animations | Replaced `motion.div` (scale: 0.8→1, delay 0.15) for status badge, `motion.div` (delay 0.2) for domain name, and `motion.a` (scale: 0.95→1, delay 0.35) for CTA button with static `div`/`a` elements. Content appears instantly. |
| `src/pages/[...query].tsx` | Translation pill: removed y-axis offset | Changed `initial={{ opacity: 0, y: -4 }}` to `initial={{ opacity: 0 }}` only. |
| `src/pages/dns.tsx` | Removed `y: 4` stagger from result cards | Both `found` and `not-found` result cards now animate opacity-only (`initial={{ opacity: 0 }}`) with no per-index delay. |
| `src/lib/env.ts` | VERSION bumped to "3.6" | |

### v3.5 — Anonymous History Cap + Enriched Admin Backend (2026-03-23)

**Scope:** Anonymous query history capped at 50 (new replaces old). Admin backend fully enriched: user management gains subscription_access/email_verified toggles and per-user stats; search records gains individual-row delete, anonymous filter, and DB-tier badges; dashboard gains today's counters and richer stats; admin stats API expanded.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/api/lookup.ts` | Anonymous history: 50-cap + replace semantics | `saveAnonymousSearchRecord()` now: DELETE existing record for same query (user_id IS NULL), INSERT new record, then trim to `MAX_ANON_HISTORY = 50` (keep newest 50). Replaces the old 24-hour dedup approach. |
| `src/pages/api/admin/users.ts` | Added `subscription_access`, `email_verified` to SELECT/PATCH | All GET responses now include `subscription_access`, `email_verified`, `search_count`, `stamp_count`, `reminder_count` per user. PATCH accepts `subscription_access` and `email_verified`. New `subscribedCount` and `verifiedCount` summary counts in GET response. |
| `src/pages/api/admin/users.ts` | Added `subscribed` and `verified` filter options | Filter by `?filter=subscribed` or `?filter=verified` to show only users with subscription access or verified email. |
| `src/pages/api/admin/search-records.ts` | Individual record DELETE via `?id=xxx` | `DELETE /api/admin/search-records?id={id}` removes a single record. Also added `period=anonymous` and `user_id=null` bulk-delete options. |
| `src/pages/api/admin/search-records.ts` | Anonymous filter + anon/logged stats | `?filter=anonymous` returns only `user_id IS NULL` records. Stats response now includes `anonymous` and `logged` counts. Daily stats include `anon` column. Value tier now read from DB column (no recompute). |
| `src/pages/api/admin/stats.ts` | Added `anonSearches`, `todaySearches`, `todayUsers`, `subscribedUsers` | Dashboard overview can show today's activity pulse and subscription user count. |
| `src/pages/admin/index.tsx` | Today's activity bar + subscription stat card | Shows "今日动态" bar with new users / queries / anon count. Added "订阅用户" stat card. Recent searches show ghost icon for anonymous. |
| `src/pages/admin/users.tsx` | Full user management enrichment | Edit modal: subscription_access toggle (amber), email_verified toggle (emerald), disabled toggle (red), per-user stat mini-cards (searches / stamps / subscriptions). User list: VIP crown icon for subscription users, verified badge, stat chips, subscription quick-toggle button. Filter tabs: added "已订阅" and "已验证". |
| `src/pages/admin/search-records.tsx` | Individual delete + anonymous filter + DB tier badge | Each row has a delete button (appears on hover). New "匿名查询" filter tab. Stats strip expanded to 8 cards (anon + logged). Bulk delete adds "清空匿名记录". Value tier badge now reads from DB (no client-side score recompute). User/anon breakdown bar chart added to stats panel. |
| `src/lib/env.ts` | VERSION bumped to "3.5" | |

### v3.4 — Mobile UX: Instant Nav Feedback + Tiered History Retention + Pagination (2026-03-23)

**Scope:** Three parallel improvements: (1) immediate tap feedback on navigation via top loading bar; (2) smoother page transitions (pure opacity, no y-axis jank); (3) search history now has tiered expiry, 100-record cap, per-page pagination, value-tier badges, and confirmed delete-all.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/_app.tsx` | Added `RouteLoadingBar` component | 2 px primary-colour bar at top of screen. Appears immediately on `routeChangeStart` (15 % → 50 % → 75 % → 100 % on complete), giving instant click feedback on mobile. Uses router events, no external dependency. |
| `src/pages/_app.tsx` | Simplified page transition animation | Removed y-axis offset (`y: 6`/`y: -3`). Now pure opacity fade only (`0 → 1 → 0`), duration reduced to 0.15 s. Eliminates vertical jank that was especially noticeable on mobile. |
| `src/pages/_app.tsx` | Removed `willChange` hint | `willChange: "opacity, transform"` removed; `transform` is no longer needed since y-axis motion is gone. |
| `src/lib/db.ts` | Added `value_tier` column to `search_history` | `ALTER TABLE … ADD COLUMN IF NOT EXISTS value_tier TEXT NOT NULL DEFAULT 'normal'`. Stores computed domain value tier alongside each record for retention-rule enforcement. |
| `src/pages/api/user/search-history.ts` | Tiered retention cleanup (`pruneExpired`) | Runs after every POST. SQL removes records older than: 10 d (normal), 20 d (valuable, score ≥ 35), 50 d (high, score ≥ 55). |
| `src/pages/api/user/search-history.ts` | `MAX_HISTORY` 500 → 100 | Normal users now capped at 100 records. Oldest records trimmed after every write via `trimToLimit`. |
| `src/pages/api/user/search-history.ts` | Computes and stores `value_tier` on insert | `computeValueTier()` uses `scoreDomain()`: high (≥55) / valuable (≥35) / normal. Only for `domain` queries with `unregistered` status; all others default to `normal`. |
| `src/pages/api/user/search-history.ts` | GET now supports pagination | Accepts `?page=N`, returns `{ history, total, page, pages }`. Page size = 20. |
| `src/pages/dashboard.tsx` | History pagination state + controls | New states: `historyPage`, `historyTotal`, `historyPages`. `fetchHistory(page)` function. Prev / Next buttons shown when `pages > 1`. |
| `src/pages/dashboard.tsx` | Value-tier badges in history list | Each domain row shows a coloured "高价值" (amber) or "有价值" (violet) badge when `valueTier` is set, alongside the existing reg-status badge. |
| `src/pages/dashboard.tsx` | "全部删除" confirmation | `window.confirm` shows total count before deletion. Resets all pagination state on success. |
| `src/pages/dashboard.tsx` | Tab & stat card use `historyTotal` | History tab badge and overview card now show the server-side total instead of the current page length. |
| `src/pages/dashboard.tsx` | Retention hint footer | When only one page exists, shows "普通 10 天 · 有价值 20 天 · 高价值 50 天" instead of old "最近 50 条记录". |

### v3.3 — Fully Branded Email Templates with Dynamic Site Name (2026-03-23)

**Scope:** All outgoing system emails now read the site name from the database (`site_settings.site_logo_text`) and render it in logos, subjects, and footers. No more hardcoded "Next Whois" in any email. Covers every email route in the project.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/email.ts` | `getSiteLabel()` added with 60 s DB cache | Reads `site_logo_text` from `site_settings`; falls back to "NEXT WHOIS". Exported so any API route can call it once and pass the result down. |
| `src/lib/email.ts` | `emailLayout()` accepts `siteName` param | Logo renders site name split on last space, last word coloured with PRIMARY violet; logo is a clickable link to `BASE_URL`. Footer copyright line also uses `siteName`. |
| `src/lib/email.ts` | All builder functions accept `siteName?: string` | `welcomeHtml`, `subscriptionConfirmHtml`, `reminderHtml`, `phaseEventHtml`, `dropApproachingHtml`, `domainDroppedHtml`, `passwordResetHtml`, `adminNotifyHtml`, `feedbackHtml`, `highValueAlertHtml`, `verifyCodeHtml` all default to "NEXT WHOIS" when `siteName` is omitted. |
| `src/lib/email.ts` | `stampVerifyTimeoutHtml()` added | New styled email for DNS verification timeout on stamp/brand-claim flow. Matches app visual style; accepts `domain`, `fileContent`, `verifyUrl`, `siteName`. |
| `src/pages/api/user/register.ts` | Welcome email branded | Calls `getSiteLabel()`, uses `siteName` in subject and `welcomeHtml`. |
| `src/pages/api/user/forgot-password.ts` | Reset email branded | Calls `getSiteLabel()`, uses `siteName` in subject and `passwordResetHtml`. |
| `src/pages/api/user/send-verify-code.ts` | Verify-code email branded | Calls `getSiteLabel()`, uses `siteName` in subject and `verifyCodeHtml`. |
| `src/pages/api/admin/test-email.ts` | Test email branded | Calls `getSiteLabel()`, uses `siteName` in subject and `adminNotifyHtml`. |
| `src/pages/api/stamp/giveup-notify.ts` | Rewritten to use `stampVerifyTimeoutHtml` | Replaced raw Arial-only HTML builder with the new styled template function. Calls `getSiteLabel()`. |
| `src/pages/api/feedback.ts` | Feedback notification branded | Calls `getSiteLabel()`, passes `siteName` to `feedbackHtml`. |
| `src/pages/api/remind/submit.ts` | Subscription confirm email branded | Calls `getSiteLabel()`, passes `siteName` to `subscriptionConfirmHtml`. |
| `src/pages/api/remind/process.ts` | All reminder/phase/drop emails branded | Calls `getSiteLabel()` once per cron invocation; passes `siteName` to all 5 email builder calls (`reminderHtml`, `phaseEventHtml` ×3, `dropApproachingHtml`, `domainDroppedHtml`). |
| `src/pages/api/user/search-history.ts` | High-value domain alert branded | Calls `getSiteLabel()`, passes `siteName` to `highValueAlertHtml`. |

### v3.2 — UX Polish, Branding Consistency & Permission Flow Fixes (2026-03-23)

**Scope:** Session-wide settings caching, page transition stabilization, consistent site branding across all sub-pages, and corrected auth/permission flows in the dashboard and query pages.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/site-settings.tsx` | Added `sessionStorage` cache for site settings | Reads cached settings as initial state on first render, eliminating the title flash caused by `DEFAULT_SETTINGS` showing before the API responds. Cache is written/updated on every successful API fetch. |
| `src/pages/_app.tsx` | Fixed `AnimatePresence` key for client-search pages | Pages in `CLIENT_SEARCH_PAGES` (`/dns`, `/ip`, `/ssl`, `/icp`, `/tools`, `/feedback`) now use `router.pathname` as the animation key instead of `router.asPath`, preventing jarring exit/re-enter transitions when query params change. |
| `src/pages/dns.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | `DNS 查询 — NEXT WHOIS` now uses `settings.site_logo_text` dynamically. |
| `src/pages/ssl.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | `SSL 证书查询 — NEXT WHOIS` now uses `settings.site_logo_text` dynamically. |
| `src/pages/ip.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | `IP / ASN 查询 — NEXT WHOIS` now uses `settings.site_logo_text` dynamically. |
| `src/pages/tools.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | Tools page title now uses `settings.site_logo_text` dynamically. |
| `src/pages/icp.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | ICP page title now uses `settings.site_logo_text` dynamically. |
| `src/pages/docs.tsx` | Added `useSiteSettings` hook; fixed hardcoded title + og/twitter meta | All 3 title occurrences (title, og:title, twitter:title) now use `settings.site_logo_text` dynamically. |
| `src/pages/feedback.tsx` | Fixed hardcoded title | Was already importing `useSiteSettings`; title now uses `settings.site_logo_text`. |
| `src/pages/dashboard.tsx` | Default tab changed to `stamps`; adds smart switch to `subscriptions` when user has `subscriptionAccess` | Users without subscription access now land on the Stamps tab first. Users with access auto-switch to Subscriptions tab after session loads. |
| `src/pages/dashboard.tsx` line 447 | `SubscribeGuideModal` redirect changed from `/remind` to `/stamp` | The "查看订阅管理页" button now correctly sends users to the brand-claim page (`/stamp`), not the subscription reminder page. Label updated to "前往品牌认领页". |
| `src/pages/[...query].tsx` | No-access subscribe toast now includes actionable `/stamp` redirect | Both subscribe button instances now show a toast with an "Apply / 前往申请" action button linking to `/stamp` when user lacks `subscriptionAccess`, instead of a dead-end info message. |

### v3.1 — Enom TLD Reference Chart Full Integration (2026-03-23)

**Scope:** Complete second pass of `src/lib/lifecycle.ts` corrections using the authoritative Enom TLD Reference Chart (2026-03, 922 lines). All grace/redemption/pendingDelete values for supported TLDs corrected to match Enom registrar data. New TLD entries added.

**Source:** Enom TLD Reference Chart 2026-03 (PDF, 922 lines) — authoritative for gTLDs, nTLDs, and ccTLDs where Enom offers registration.

**Comment block updates (LIFECYCLE_TABLE header):**

| TLD | Before | After | Source |
|---|---|---|---|
| `.be` note | grace 0-20d, RGP=40d | no grace, RGP=30d, 3d pre-expiry deletion | Enom 2026-03 |
| `.ch/.li` note | grace=5d, RGP=40d | no grace, RGP=14d, 10d pre-expiry | Enom 2026-03 |
| `.eu` note | no grace, RGP=40d | no grace, RGP=30d, 3d pre-expiry | Enom 2026-03 |
| `.nl` note | no grace, RGP=40d | no grace, RGP=30d, 3d pre-expiry | Enom 2026-03 |
| `.es` note | RGP=10d | RGP=14d, 12d pre-expiry | Enom 2026-03 |
| `.nz` note | grace=40d, RGP=90d | no grace, RGP=90d, 3d pre-expiry | Enom 2026-03 |
| `.au` note | grace=30d, no RGP | no grace, RGP=31d, 10d pre-expiry | Enom 2026-03 |

**Europe ccTLD corrections:**

| TLD | grace Before→After | rdmp Before→After | Source |
|---|---|---|---|
| `.de` | 10→**0** | 30→30 | Enom 2026-03: N/30 |
| `.nl` | 0→0 | 40→**30** | Enom 2026-03: N/30 |
| `.eu` | 0→0 | 40→**30** | Enom 2026-03: N/30 |
| `.es` | 0→0 | 10→**14** | Enom 2026-03: N/14 |
| `.be` | 10→**0** | 40→**30** | Enom 2026-03: N/30 |
| `.ch` | 5→**0** | 40→**14** | Enom 2026-03: N/14 |
| `.li` | 5→**0** | 40→**14** | Enom 2026-03: N/14 |
| `.am` | grace=30, rdmp=30 | **IMMEDIATE** | Enom 2026-03: N/N |

**Asia-Pacific ccTLD corrections:**

| TLD | grace Before→After | rdmp Before→After | Source |
|---|---|---|---|
| `.sg` | 30→**0** | 30→**14** | Enom 2026-03: N/14 |
| `com/net/org/edu.sg` | 30→**0** | 30→**14** | Enom 2026-03: N/14 |
| `.nz` | 40→**0** | 90→90 | Enom 2026-03: N/90 |
| `co/net/org/school.nz` | 40→**0** | 90→90 | Enom 2026-03: N/90 |
| `.in` | 40→**30** | 30→30 | Enom 2026-03: 30/30 |
| `co/net/org.in` | 40→**30** | 30→30 | Enom 2026-03: 30/30 |
| `.au` (bare TLD) | 30→**0** | 0→**31** | Enom 2026-03: N/31 |
| `.mu` | 30→**40** | 0→**30** | Enom 2026-03: 40/30 |
| `.tm` | grace=30, rdmp=0 | **IMMEDIATE** | Enom 2026-03: N/N |

**Americas ccTLD corrections:**

| TLD | grace Before→After | rdmp Before→After | Source |
|---|---|---|---|
| `.ca` | 40→**30** | 30→30 | Enom 2026-03: 30/30 |
| `.pe` | 30→**0** | 30→**10** | Enom 2026-03: N/10 |
| `com.pe` | 30→**0** | 30→**10** | Enom 2026-03: N/10 |
| `com.mx` | 30→**40** | 30→**0** | Enom 2026-03: 40/N |
| `.hn` | rdmp 0→**30** | — | Enom 2026-03: 30/30 |

**Batch 1 corrections (applied earlier in v3.1):**

| TLD | Change | Source |
|---|---|---|
| `.io` | grace 30→**32** | Enom 2026-03 |
| `.ai` | grace 30→**45** | Enom 2026-03 |
| `.la` | grace 28→**30** | Enom 2026-03 |
| `.tv` | grace 30→**42** | Enom 2026-03 |
| `.ac` / `.sh` | grace 30→**32** | Enom 2026-03 |
| `.vg` | grace 30→**32**, rdmp 30→30 | Enom 2026-03 |
| `.tc` | grace 30→**32**, rdmp 0→**30** | Enom 2026-03 |
| `.sc` / `.mn` / `.fm` / `.ms` / `.gs` / `.tk` / `.bz` | **IMMEDIATE** | Enom 2026-03 |
| `.de` | grace 10→**0** | Enom 2026-03 |
| `.nl` | rdmp 40→**30** | Enom 2026-03 |
| `.eu` | rdmp 40→**30** | Enom 2026-03 |
| `.es` | rdmp 10→**14** | Enom 2026-03 |

**New entries added:**

| TLD | Data | Registry |
|---|---|---|
| `.eus` | grace=45, rdmp=30, pd=5 | PUNTUEUS (Basque Country) |
| `.free` / `.fast` / `.hot` / `.spot` / `.talk` / `.you` | grace=40, rdmp=30, pd=5 | Amazon Registry Services |
| `com/net/org.mu` | grace=40, rdmp=30, pd=5 | ICTA (Mauritius) |

**Other changes:**
- `.inc`: grace corrected 30→42 (Enom 2026-03: 42/30)
- Duplicate `.tc` entry (line 676, old est-confidence entry) removed

---

### v3.0 — TLD Lifecycle Data Accuracy Overhaul (2026-03-23)

**Scope:** Major accuracy corrections to `src/lib/lifecycle.ts` based on cross-referencing Namecheap KB (updated 2025-09-10) and Dynadot TLD pages (verified 2026-03) against the Enom TLD Reference Chart.

**Sources:**
- Namecheap KB: https://www.namecheap.com/support/knowledgebase/article.aspx/9916/2207/tlds-grace-periods
- Dynadot TLD pages: https://www.dynadot.com/domain/[tld]
- Enom TLD Reference Chart: https://docs.google.com/spreadsheets/d/1oVNszsvqhxh3hlT1LYMfcwq3lw_e6J7DeBePvN4t2aw

**Named preset updates:**

| Preset | Before | After | Reason |
|---|---|---|---|
| `STD` (default gTLD) | grace=45, rdmp=30, pd=5 | grace=**30**, rdmp=30, pd=5 | Dynadot: 30d in practice, not 45d max |
| `AFNIC` (.fr etc.) | grace=0, rdmp=30, pd=**10** | grace=0, rdmp=30, pd=**5** | Dynadot verified: .pm/.wf delete=5 |
| `NOMINET` (.uk etc.) | grace=**92**, rdmp=0, pd=**0** | grace=**90**, rdmp=0, pd=**5** | Dynadot: grace=85/5; Namecheap: 90d total |
| `CNNIC` (.cn etc.) | grace=0, rdmp=**14**, pd=5 | grace=0, rdmp=**15**, pd=5 | Dynadot restore=15d |
| `HKIRC` (.hk etc.) | grace=**90**, rdmp=**0**, pd=0 | grace=**30**, rdmp=**60**, pd=0 | Dynadot: grace=30, restore=60 |

**Major TLD corrections:**

| TLD | Before | After | Source |
|---|---|---|---|
| `.de` | IMMEDIATE (0/0/0) | grace=10, rdmp=30, pd=25 | Dynadot: variable grace 0-20d; NOT immediate |
| `.it` | IMMEDIATE | grace=10, rdmp=30, pd=0 | Dynadot: grace=10, restore=30 |
| `.pl` | IMMEDIATE | grace=0, rdmp=30, pd=0 | Dynadot: restore=30 |
| `.no` | IMMEDIATE | grace=89, rdmp=0, pd=0 | Dynadot: 89-day grace |
| `.ie` | IMMEDIATE | grace=30, rdmp=30, pd=14 | Dynadot: grace=30, restore=30, delete=14 |
| `.be` | IMMEDIATE | grace=10, rdmp=40, pd=0 | Dynadot: variable 0-20d grace, restore=40 |
| `.cl` | IMMEDIATE | grace=10, rdmp=30, pd=10 | Dynadot: grace=10, restore=30, delete=10 |
| `.es` | IMMEDIATE | grace=0, rdmp=10, pd=0 | Namecheap: 10-day RGP only, no pendingDelete |
| `.eu` | grace=40, rdmp=0 | grace=0, rdmp=40, pd=0 | Dynadot: no grace, restore=40 |
| `.nl` | grace=40, rdmp=0 | grace=0, rdmp=40, pd=0 | Dynadot: no grace, restore=40 |
| `.ch` | grace=30, rdmp=0, pd=5 | grace=5, rdmp=40, pd=0 | Dynadot: grace=5, restore=40 |
| `.li` | grace=30, rdmp=0, pd=5 | grace=5, rdmp=40, pd=0 | Dynadot: grace=5, restore=40 |
| `.pt` | grace=30, rdmp=0 | grace=29, rdmp=0 | Dynadot: grace=29 |
| `.cz` | grace=30, rdmp=0 | grace=59, rdmp=0 | Dynadot: grace=59 |
| `.ro` | grace=30, rdmp=0 | grace=80, rdmp=0 | Dynadot: grace=80 |
| `.lt` | grace=30, rdmp=30, pd=5 | grace=0, rdmp=30, pd=0 | Dynadot: no grace, restore=30 |
| `.lv` | grace=30, rdmp=30, pd=5 | grace=0, rdmp=30, pd=0 | Dynadot: no grace, restore=30 |
| `.tw` | grace=0, rdmp=30, pd=5 | grace=32, rdmp=0, pd=10 | Dynadot: grace=32, delete=10, no restore |
| `.nz` | IMMEDIATE | grace=40, rdmp=90, pd=5 | Dynadot: grace=40, restore=90 |
| `.hk` | HKIRC (grace=90) | HKIRC (grace=30, rdmp=60) | Preset updated |
| `.in` | grace=30, rdmp=30 | grace=40, rdmp=30 | Dynadot: grace=40 |
| `.id` | grace=30, rdmp=30 | grace=40, rdmp=30 | Dynadot: grace=40 |
| `.ph` | grace=30, rdmp=0, pd=5 | grace=50, rdmp=0, pd=0 | Dynadot: grace=50, delete=0 |
| `.ae` | grace=30, rdmp=30, pd=5 | grace=20, rdmp=0, pd=0 | Dynadot: grace=20, no restore |
| `.cm` | grace=30, rdmp=0, pd=0 | IMMEDIATE | Namecheap: expires = deleted same day |
| `.nu` | grace=45, rdmp=30, pd=5 | grace=7, rdmp=60, pd=0 | Namecheap: 7d then 60d RGP |
| `.gg` | grace=45, rdmp=30, pd=5 | grace=28, rdmp=12, pd=0 | Dynadot: grace=28, restore=12 |
| `.la` | grace=45, rdmp=30, pd=5 | grace=28, rdmp=30, pd=0 | Dynadot: grace=28, no delete |
| `.to` | grace=45, rdmp=30, pd=5 | grace=40, rdmp=30, pd=5 | Dynadot: grace=40 |
| `.fm` | grace=45, rdmp=30, pd=5 | grace=30, rdmp=30, pd=4 | Dynadot: delete=4 |
| `.vg` | grace=45, rdmp=30, pd=5 | grace=30, rdmp=30, pd=4 | Dynadot: delete=4 |
| (all 45d island TLDs) | grace=45 | grace=30 | Dynadot shows 30d for all VeriSign-managed |

**SLD corrections:**
- `.co.nz` / `.net.nz` / `.org.nz` / `.school.nz`: IMMEDIATE → grace=40, rdmp=90, pd=5
- `.com.hk` and all `*.hk`: auto-updated via HKIRC preset
- `.com.ph` / `.net.ph` / `.org.ph`: grace=30/pd=5 → grace=50/pd=0
- `co.in` / `net.in` / `org.in`: grace=30 → grace=40 (matching .in TLD)

---

### v2.9 — Comprehensive TLD Lifecycle Rules Expansion (2026-03-23)

**Scope:** `src/lib/lifecycle.ts` completely rewritten. Table grew from ~150 entries to **634 total entries** (547 TLD-level + 87 SLD-level), covering the vast majority of the global domain namespace.

**Sources consulted:**
- ICANN RAA (standard gTLD: 45d grace / 30d RGP / 5d pendingDelete)
- Namecheap KB: https://www.namecheap.com/support/knowledgebase/article.aspx/9916/2207/tlds-grace-periods
- Dynadot TLD pages: https://www.dynadot.com/domain/tlds.html
- Individual registry policy pages (CNNIC, HKIRC, Nominet, AFNIC, DENIC, auDA, etc.)
- IANA root-zone database

**Accuracy corrections:**

| TLD | Before | After | Source |
|---|---|---|---|
| `.cn` | grace=0, redemption=30, pendingDelete=5 | grace=0, **redemption=14**, pendingDelete=5 | Namecheap KB / CNNIC registry-level RGP |
| `.hk` | grace=0, redemption=30, pendingDelete=5 | grace=**90**, redemption=**0**, pendingDelete=**0** | HKIRC policy (90-day renewal window, no separate RGP) |
| `.ph` | grace=30, redemption=30, pendingDelete=5 | grace=30, redemption=**0**, pendingDelete=5 | PH Domains Foundation — no redemption period |
| `.ly` | grace=30, redemption=0, pendingDelete=0 | **IMMEDIATE** (0/0/0) | LYNIC policy |
| `.au` | grace=0, redemption=0, pendingDelete=5 | grace=**30**, redemption=0, pendingDelete=5 | auDA new top-level TLD (launched 2022) |
| `com.hk` | grace=0, redemption=30, pendingDelete=5 | **HKIRC** (90/0/0) | HKIRC — consistent with .hk |

**New named presets (reusable policy families):**
- `CNNIC` — `.cn` and all `*.cn` sub-TLDs: `{ grace: 0, redemption: 14, pendingDelete: 5 }`
- `HKIRC` — `.hk` and all `*.hk` sub-TLDs: `{ grace: 90, redemption: 0, pendingDelete: 0 }`
- `NOMINET` — `.uk` and all `*.uk` sub-TLDs: `{ grace: 92, redemption: 0, pendingDelete: 0 }`
- `JPRS` — `.jp` and all `*.jp` sub-TLDs: immediate delete `{ grace: 0, redemption: 0, pendingDelete: 0 }`
- `REGISTROBR` — `.br` and all `*.br` sub-TLDs: immediate delete
- `NICAR` — `.ar` and all `*.ar` sub-TLDs: immediate delete

**New TLD categories added:**

1. **Popular new gTLDs (~60)**: `xyz`, `club`, `fun`, `icu`, `top`, `vip`, `wiki`, `ink`, `buzz`, `website`, `uno`, `bio`, `ski`, `ltd`, `llc`, `srl`, `gmbh`, `inc`, `bar`, `fit`, `fan`, `bet`, `best`, `cash`
2. **Business/professional new gTLDs (~150)**: `academy`, `accountant`, `auction`, `bargains`, `bike`, `boutique`, `cafe`, `camera`, `careers`, `casino`, `chat`, `clinic`, `coach`, `codes`, `coffee`, `community`, `condos`, `construction`, `consulting`, `coupons`, `dance`, `dating`, `dental`, `diamonds`, `doctor`, `energy`, `engineering`, `estate`, `financial`, `fitness`, `flights`, `furniture`, `games`, `glass`, `golf`, `graphics`, `guru`, `healthcare`, `hockey`, `homes`, `industries`, `insure`, `investments`, `kitchen`, `legal`, `lighting`, `limited`, `limo`, `loans`, `management`, `marketing`, `mba`, `memorial`, `mortgage`, `movie`, `ninja`, `partners`, `pet`, `photography`, `pizza`, `plumbing`, `productions`, `properties`, `pub`, `racing`, `realty`, `recipes`, `rehab`, `rentals`, `repair`, `restaurant`, `rocks`, `rugby`, `school`, `security`, `sexy`, `shoes`, `singles`, `solar`, `surgery`, `tax`, `taxi`, `technology`, `tennis`, `tips`, `today`, `tours`, `town`, `toys`, `trade`, `training`, `university`, `vacations`, `ventures`, `villas`, `vision`, `voyage`, `wine`, `works`, `wtf`, `zone` (all STD 45/30/5)
3. **Geographic / city new gTLDs (~30)**: `amsterdam`, `barcelona`, `berlin`, `brussels`, `capetown`, `cologne`, `dubai`, `istanbul`, `london`, `miami`, `nagoya`, `nyc`, `okinawa`, `osaka`, `paris`, `quebec`, `rio`, `ryukyu`, `saarland`, `tirol`, `tokyo`, `vegas`, `wien`, `yokohama`, `zuerich`, `boston`, `wales`, `scot`, `irish`, `africa`, `arab`, `nrw` (all STD)
4. **Pacific ccTLDs**: `tl` (Timor-Leste), `fj`, `pg`, `sb`, `vu`, `ki`, `nr`, `ck`, `as`, `pf`, `nc`, `gp`, `mq`
5. **African ccTLDs (~25)**: `mz`, `zw`, `zm`, `ao`, `bi`, `bj`, `bf`, `td`, `cg`, `cd`, `gq`, `gw`, `mr`, `ne`, `tg`, `bw`, `na`, `ls`, `sz`, `mw`, `mg`, `mu`, `km`, `so`, `dj`, `er`, `st`, `cv`, `gn`, `sl`, `lr`
6. **European ccTLDs**: `fo` (Faroe), `mc` (Monaco), `sm` (San Marino), `ad` (Andorra), `gi` (Gibraltar), `im` (Isle of Man), `xk` (Kosovo)
7. **Caribbean/Americas ccTLDs**: `gd`, `dm`, `bb`, `ky`, `bm`, `bs`, `tc`, `kn`, `fk`, `sr`, `aw`, `cw`, `sx`
8. **AFNIC extensions**: `pf`, `nc`, `gp`, `mq` (all managed by AFNIC, same policy as `.fr`)

**New SLD entries (87 total):**

| Country | New SLDs |
|---|---|
| Australia (auDA) | `id.au`, `asn.au`, `edu.au`, `gov.au` (existing `com/net/org.au` kept at 30/30/5) |
| Taiwan (TWNIC) | `com.tw`, `net.tw`, `org.tw`, `idv.tw`, `edu.tw`, `gov.tw` |
| Hong Kong (HKIRC) | `net.hk`, `org.hk`, `idv.hk`, `edu.hk`, `gov.hk` (all 90/0/0) |
| New Zealand (InternetNZ) | `net.nz`, `org.nz`, `school.nz`, `govt.nz` (all IMMEDIATE) |
| Japan (JPRS) | `gr.jp`, `ac.jp`, `go.jp` (all IMMEDIATE) |
| Korea (KISA) | `or.kr` |
| Singapore (SGNIC) | `net.sg`, `org.sg`, `edu.sg`, `gov.sg` |
| Malaysia (MYNIC) | `net.my`, `org.my`, `edu.my` |
| Philippines (PH Domains) | `net.ph`, `org.ph` (no redemption) |
| India (NIXI) | `co.in`, `net.in`, `org.in` |
| Israel (ISOC-IL) | `org.il`, `net.il` |
| South Africa (ZADNA) | `org.za`, `net.za`, `web.za` (all IMMEDIATE) |
| Kenya (KENIC) | `or.ke`, `ne.ke` |
| Nigeria (NIRA) | `org.ng`, `net.ng` |
| Brazil (Registro.br) | `edu.br`, `gov.br` (all IMMEDIATE) |
| Mexico (NIC México) | `org.mx`, `net.mx` |
| Argentina (NIC Argentina) | `net.ar`, `org.ar` (all IMMEDIATE) |
| Ukraine | `com.ua` |
| Turkey (NIC TR) | `org.tr`, `net.tr` (all IMMEDIATE) |
| Venezuela | `com.ve` |
| Colombia | `com.co` |
| Peru | `com.pe` |

---

### v2.8 — CN Reserved Second-Level Domain Detection (2026-03-23)

**Problem:** CNNIC reserves 43 second-level domain labels under `.cn` for official use — 34 provincial administrative codes (bj.cn, sh.cn…), 7 functional suffixes (gov.cn, edu.cn…), and 2 system domains (nic.cn, cnnic.cn). Previously, these were either showing as "已注册" (incorrect) or as a misleading "该域名已注册但注册机构未提供公开的WHOIS/RDAP服务" fallback. The WHOIS lookup took 2.4s+ and returned no useful information.

**New file: `src/lib/whois/cn-reserved-sld.ts`**

Comprehensive database of all 43 reserved CN SLDs with bilingual descriptions, organized into three maps:

| Category | Count | Example |
|---|---|---|
| `CN_PROVINCE_SLDS` — 34 provincial codes | 34 | `bj` → 北京市, `gd` → 广东省 |
| `CN_FUNCTIONAL_SLDS` — sector suffixes | 7 | `gov` → 政府机构, `edu` → 教育机构 |
| `CN_SYSTEM_RESERVED` — exact domains | 2 | `nic.cn`, `cnnic.cn` |

`getCnReservedSldInfo(domain)` checks these in priority order and returns a typed `CnReservedInfo` object (or `null` for non-reserved domains).

**Three-layer interception — in priority order:**

1. **`getServerSideProps` pre-check** (`src/pages/[...query].tsx` line ~1315) — intercepts the raw URL query BEFORE `cleanDomain()` runs. Critical because the lib's `specialDomains` map rewrites functional SLDs (e.g. `gov.cn → www.gov.cn`) to make WHOIS lookups work — without this early check, SSR would look up `www.gov.cn` (a real registered domain) instead of showing "保留域名".

2. **`lookupWhoisWithCache` pre-check** (`src/lib/whois/lookup.ts` line ~504) — the first thing called in the function, before any L1/L2 cache lookup. Ensures no stale Redis-cached result for these domains ever overrides the correct synthetic result.

3. **`/api/lookup` pre-check** (`src/pages/api/lookup.ts` line ~115) — catches client-side searches (typed into the search bar after page load) that hit the API directly.

**Synthetic result format:**

All three interception points return the same structure:
```typescript
{
  time: 0, status: true, cached: false, source: "whois",
  result: {
    domain: "gov.cn",
    status: [{ status: "registry-reserved", url: "" }],
    rawWhoisContent: "[CN Reserved] GOV.CN 是 CNNIC 保留的功能性二级域名...",
    // all other fields: Unknown / null (from initialWhoisAnalyzeResult)
  }
}
```

**UI updates:**

- `DomainStatusInfoCard` now accepts `customDesc?: { zh: string; en: string }` to override the generic "保留域名" description with the domain-specific CNNIC explanation (e.g. "BJ.CN 是 CNNIC 为北京市保留的省级行政区划域名（共34个）...")
- The call site passes `cnInfo` to the card when `regStatus.type === "reserved"`
- Cache header for CN reserved responses: `s-maxage=86400, stale-while-revalidate=604800` (24h/7d)

**Verified results:**

| Domain | Before | After |
|---|---|---|
| `bj.cn` (Beijing province) | ● 已注册 + "no WHOIS" fallback, 2.4s | ● 保留域名 + "BJ.CN 是 CNNIC 为北京市保留…" **0ms** |
| `sh.cn` (Shanghai) | ● 已注册 + "no WHOIS" fallback | ● 保留域名 + specific description **0ms** |
| `gov.cn` (Government) | ● 正常 (showing www.gov.cn data!) | ● 保留域名 + "GOV.CN 是 CNNIC 保留的功能性二级域名…" **0ms** |
| `edu.cn` (Education) | ● 正常 (showing www.edu.cn data!) | ● 保留域名 + "EDU.CN 是 CNNIC 保留的功能性二级域名…" **0ms** |
| `nic.cn` (CNNIC system) | ● 已注册 + "no WHOIS" fallback | ● 保留域名 + "nic.cn 为 CNNIC 系统保留域名…" **0ms** |
| `google.cn` (normal domain) | ● 正常 ✓ | ● 正常 ✓ (no false positive) |

All 43 reserved SLDs now return the correct badge and description in **0ms** with no WHOIS/RDAP network query.

---

### v2.7 — Enhanced Domain Status Detection: Reserved / Prohibited / Suspended (2026-03-23)

**Problem:** Many ccTLD and gTLD registries express special domain states (reserved, prohibited, blocked, suspended) as free-form text in WHOIS responses rather than EPP status codes. The parser only understood structured `Domain Status:` fields, so domains like `com.tw` (WHOIS says "reserved name") were incorrectly shown as **已注册 (Registered)**.

**Two-layer fix:**

**1. `src/lib/whois/common_parser.ts` — Synthetic status injection**

After the normal EPP status deduplication pass, scans the raw WHOIS text for non-EPP state keywords and injects synthetic status entries:

| Pattern matched in raw text | Synthetic status injected | UI result |
|---|---|---|
| `reserved name`, `this name is reserved`, `domain is reserved`, `reserved by the registry`, standalone `reserved` line | `registry-reserved` | 保留域名 (amber) |
| `registration prohibited`, `cannot be registered`, `registration not available`, `not eligible for registration`, `prohibited string`, `registry banned`, `registration blocked` | `registrationProhibited` | 禁止注册 (red) |
| `suspended by registry/registrar`, `registry-suspended`, `domain is suspended` | `suspended` | 暂停 (orange) |

These patterns are conservative — specific enough to avoid false positives in WHOIS legal footer text (e.g. "all rights reserved" does NOT match "reserved name").

**2. `src/pages/[...query].tsx` — `getDomainRegistrationStatus` enhanced**

Added a raw content scan as a safety net, checking both `result.rawWhoisContent` and `result.rawRdapContent` (serialized to string) for the same patterns. This covers RDAP-sourced data where `common_parser.ts` doesn't run.

Also added `suspended` EPP code detection to the hold check: `hasSuspended = allStatusText.includes("suspended") || rawHasSuspended`.

**3. `src/lib/whois/epp_status.ts` — Two new entries**

- `registryreserved` → displayName `registry-reserved`, category `server`  
- `registrationprohibited` → displayName `registrationProhibited`, category `server`

These ensure the EPP status badge in the 状态 section shows correct Chinese/English descriptions instead of the generic "暂无标准释义" fallback.

**4. `src/pages/[...query].tsx` — EPP lock filter robustness fix**

Pre-existing bug: Some WHOIS servers (e.g. TWNIC for `.tw`) emit EPP lock statuses with **spaces** (`"client delete prohibited"`) rather than camelCase or hyphens. The original filter took only `s.split(/\s+/)[0]` ("client") which is not in the EPP lock set, letting the string pass through — and `prohibitCheckText.includes("prohibited")` was then true, incorrectly triggering the **禁止注册** badge for all Google-owned `.tw` domains.

**Fix:** The filter now checks the code against the lock set in TWO additional forms — the raw first-word AND the space/hyphen-stripped concatenated form:
```
"client delete prohibited"
  → noSep = "clientdeleteprohibited" → IN set → filtered ✓
"client-transfer-prohibited"  
  → noSep = "clienttransferprohibited" → IN set → filtered ✓
"clientUpdateProhibited" → toLowerCase → "clientupdateprohibited"
  → noSep = "clientupdateprohibited" → IN set → filtered ✓
```

**Verified results:**

| Domain | Before | After |
|---|---|---|
| `com.tw` | ● 已注册 (WRONG — WHOIS says "reserved name") | ● 保留域名 ✓ |
| `google.tw` | ● 禁止注册 (WRONG — only has EPP lock codes) | ● 正常 ✓ |
| `google.com` | ● 已注册 ✓ | ● 已注册 ✓ (no false positive) |

---

### v2.6 — RDAP-First Optimization: Massive Speed Improvement for 30+ ccTLDs (2026-03-23)

**Root cause identified and fixed:** `STATIC_NO_RDAP` in `src/lib/whois/tld-rdap-skip.ts` was incorrectly listing ~40 ccTLDs that actually have public RDAP endpoints (either via the IANA RDAP bootstrap or via `CCTLD_RDAP_OVERRIDES`). This forced all of them through the slower WHOIS path (2–6s) instead of the fast RDAP path (1–2s).

**1. `src/lib/whois/tld-rdap-skip.ts` — STATIC_NO_RDAP reduced from ~40 → 19 TLDs**

Previously listed as "no RDAP" (incorrectly — all have working RDAP):
- European ccTLDs: `.de`, `.it`, `.pl`, `.hu`, `.ro`, `.bg`, `.gr`, `.sk`, `.no`, `.fi`, `.lt`, `.lv`, `.ua`
- East/SE Asia: `.jp`, `.kr`, `.tw`, `.hk`, `.vn`, `.th`, `.sg`, `.my`, `.id`, `.ph`, `.in`
- ccTLDs with RDAP overrides: `.mm`, `.kh`, `.la`, `.np`, `.ke`, `.gh`, `.tz`, `.ug`, `.et`, `.sn`, `.iq`, `.ly`, `.tr`, `.ae`, `.il`, `.pe`, `.ph`, `.uy`
- Latin America: `.mx`, `.ar`, `.co`, `.cl`, `.pe`, `.za`

Now STATIC_NO_RDAP contains **only genuinely RDAP-less TLDs** (19 total):
`cn, mo, ru, by, kz, ir, sa, lb, eg, ma, dz, tn, bd, lk, ve, ec, bo, py, tl`

**Self-healing safety net:** If a TLD is wrongly absent from the list and RDAP fails at runtime, `markRdapSkipped()` is called automatically — it adds the TLD to the DB-backed runtime skip set, so all future requests go straight to WHOIS. No manual correction needed.

**2. `src/lib/whois/lookup.ts` — Timeout adjustments**

| Constant | Before | After | Reason |
|---|---|---|---|
| `RDAP_TIMEOUT` | 4 000 ms | 3 000 ms | HTTP/JSON servers respond in ≤2 s on Vercel; 3 s is generous |
| `WHOIS_TIMEOUT` | 8 000 ms | 7 000 ms | Reduce max wait time; legitimate slow servers still get 7 s |

**3. `src/lib/whois/rdap_client.ts` — `tryRdapOverride` internal timeout**

`AbortSignal.timeout(12000)` → `AbortSignal.timeout(2500)`. The outer `withTimeout(RDAP_TIMEOUT=3000)` already caps the entire RDAP flow; the internal 12-second signal was redundant and left dangling fetch connections alive for 12 s after the outer timeout fired.

**4. `src/lib/env.ts` — `LOOKUP_TIMEOUT` default aligned**

`8_000` → `7_000` ms — keeps the internal whoiser TCP timeout consistent with the new `WHOIS_TIMEOUT` outer cap.

**Measured results on Vercel-equivalent network (parallel RDAP + WHOIS):**

| TLD | Before | After | Source |
|---|---|---|---|
| `.sg` | ~3–4s (WHOIS) | **1.85s** | RDAP ✓ |
| `.tw` | ~3–4s (WHOIS) | **1.68s** | RDAP ✓ |
| `.jp` | ~3–4s (WHOIS) | **1.07s** (cached) | RDAP ✓ |
| `.de` | ~4.5s (WHOIS) | same | RDAP restricted by DENIC GDPR → auto-marked as rdap_skip |
| `.cn` | ~5–6s (WHOIS) | same | Kept in STATIC_NO_RDAP (no public RDAP) |

---

### v2.5 — Local-First Architecture: Bug Fixes + After-Native Fallback (2026-03-23)

**Three fixes in `src/lib/whois/lookup.ts`:**

1. **Critical bug: `UnhandledPromiseRejection` crash on RDAP-skipped TLDs (`.cn`, `.bf`, `.lu`, `.ye`, etc.)**
   - **Root cause:** `rdapPromise = Promise.reject(...)` when `skipRdap=true`, but no `.catch()` was ever attached. Node.js 15+ crashes the process on any unhandled rejection.
   - **Fix:** Changed to `Promise.resolve(null)` — safe because `rdapPromise` is excluded from `taggedRacers` and never read when `skipRdap=true`.

2. **Architecture overhaul: True "local-first" — third-party only fires after native fails**
   - **Old (broken) behavior:** A 3-second timer would fire `lookupTianhu()`/`lookupYisi()` even while WHOIS was still running (WHOIS timeout = 6s). If WHOIS takes 3–5s (common for legitimate WHOIS servers), third-party would race against it and win. Then `forceTldFallback()` would be called, permanently opening the early gate for that TLD — creating a feedback loop where the system increasingly bypassed native WHOIS in favour of third-party.
   - **New behavior:** `progressiveFallbackRacer` now uses `await Promise.allSettled([rdapPromise, whoisPromise])` — waits for ALL native lookups to genuinely settle (succeed, fail, or timeout) before calling `lookupTianhu()`/`lookupYisi()`. Third-party is truly a last resort.
   - **Bonus:** For TLDs with no WHOIS server, `getLookupWhois` rejects almost instantly ("No WHOIS server responded") so the fallback fires immediately without waiting — actually faster than the old 3s timer for quickly-failing TLDs.
   - **`nativeWon` flag:** Set to `true` when `firstNonNull()` resolves with a native result. The progressive async function checks this after `allSettled` and skips third-party calls if native already won.
   - **`forceTldFallback` preserved:** Still called when progressive wins, since with the new architecture this truly means native completely failed — justified to open the early gate for next time.

3. **WHOIS timeout increased: 6000ms → 8000ms**
   - Many legitimate WHOIS servers (especially for ccTLDs) need 5-7s to respond. Increasing the cap reduces false timeouts and unnecessary fallback gate triggers. RDAP timeout unchanged at 4000ms (HTTP/JSON is faster).

**Architecture summary:**
- `lookupTianhu`: only if `tianhu_enabled=true` in admin config (25/min, 300/day)
- `lookupYisi`: only if `yisi_enabled=true AND yisi_key` set in admin config
- Progressive path: after native settles (not on a timer)
- Early gate: after ≥3 recorded native failures for a TLD (`tld_fallback_stats` table)

---

### v2.4 — Premium Domain Pricing: Accurate API-Based Detection (2026-03-23)

**Two distinct concepts now properly separated:**
- `isPremium` (on pricing) = registry/API confirmed premium-priced TLD (price > $100 USD/EUR/CAD, OR `currencytype === "premium"` from API response)
- `negotiable` = domain name has high resale value (from domain value scoring engine — independent of TLD pricing)

**Changes:**

1. **`src/lib/pricing/client.ts` — `calcIsPremium` improved:**
   - Now also checks `r.currencytype.toLowerCase().includes("premium")` — detects registry-marked premium pricing from the Nazhumi API response field before the price-threshold fallback
   - Ensures both server-side (`getDomainPricing`) and client-side (`getTopRegistrars`) correctly propagate API-reported premium status

2. **`src/pages/[...query].tsx` — `rawPrices` client mapping updated:**
   - Now checks `r.currencytype.toLowerCase().includes("premium")` in addition to price threshold
   - Removed incorrect `result.negotiable === true` conflation from rawPrices

3. **UI — Register/Renew price badges (desktop + mobile):**
   - Normal domains: grey `text-muted-foreground` (unchanged)
   - Registry-premium TLD (isPremium = true): **amber** `text-amber-500` with amber icon
   - Renew price badge now also respects `isPremium` for amber coloring (previously had no isPremium styling)

4. **DomainReminderDialog mini card:**
   - Colors updated: `text-red-500` → `text-amber-500` for consistency with main badge row
   - 溢价 cell background: `bg-red-500/8` → `bg-amber-500/8`
   - 溢价 value: `text-red-500` → `text-amber-500`

**Result:** `ai.dev` — shows grey $4.99 register / $11.62 renew (correct: `.dev` is not a premium-priced TLD), amber "Negotiable: Yes" (correct: high-value domain name). A domain like `.ai` with $100+ registration price would show all pricing in amber.

---

### v2.3 — Full 8-Locale i18n Coverage (2026-03-23)

**Added missing translation keys to all 6 remaining locales (de, ja, ko, ru, fr, zh-tw):**
- `"search"` top-level key added to all 6 locales (was only in en + zh)
- All new nav keys added: `nav_tagline`, `nav_version_menu`, `nav_search_history`, `nav_toolbox`, `nav_login`, `nav_api_docs` + `_desc`, `nav_tlds` + `_desc`, `nav_domain_lookup` + `_desc`, `nav_dns` + `_desc`, `nav_ssl` + `_desc`, `nav_ip` + `_desc`, `nav_icp` + `_desc`, `nav_about` + `_desc`, `nav_sponsor` + `_desc` — all in native language (de/ja/ko/ru/fr/zh-tw)
- Complete `"icp"` section added to all 6 locales (32 keys each) with fully native-language translations: German, Japanese, Korean, Russian, French, Traditional Chinese
- All 8 locales (en, zh, de, ja, ko, ru, fr, zh-tw) now have 100% key coverage for navbar, ICP page, and search functionality — no more English fallbacks for known new keys

**Key count per locale:** each grew from ~402 to ~470 lines (68+ new keys per file)

---

### v2.2 — i18n Complete (2026-03-23)

**Navbar i18n (HistoryDrawer, NavDrawer, UserButton, Navbar):**
- `HistoryDrawer`: DrawerTitle, trigger `aria-label`, status label map (registered/unregistered/reserved/error/unknown), and empty-state title + description all use `t()` — no hardcoded Chinese
- `NavDrawer`: Removed `label`/`labelEn`/`description` fields; replaced with `labelKey`/`descKey` (TranslationKey) referencing `nav_api_docs`, `nav_tlds`, `nav_domain_lookup`, `nav_dns`, `nav_ssl`, `nav_ip`, `nav_icp`, `nav_about`, `nav_sponsor` and their `_desc` variants; version subtitle uses `t("nav_version_menu", {version})`; footer uses `t("nav_tagline")`
- `UserButton`: `aria-label` uses `t("nav_login")`
- `Navbar`: toolbox `aria-label` uses `t("nav_toolbox")`

**ICP page i18n (`src/pages/icp.tsx`):**
- `ICP_TYPES` array: replaced `label` with `tabKey` (`"icp.tab_web"` etc.) — rendered with `t(typeItem.tabKey)`
- `CopyButton`: `title` uses `t("icp.copy")`
- `BlackListBadge`: uses `t("icp.threat_none")` and `t("icp.threat_level", {level})`
- `RecordCard`: all `InfoRow` labels use `t("icp.field_*")` keys; "限制接入" badge uses `t("icp.field_limit")`
- `Pagination`: counter uses `t("icp.results_count", {count})`; page indicator uses `t("icp.page_of", {current, total})`
- `ApiStatusBadge`: all status text uses `t("icp.offline")` / `t("icp.check_status")`
- `IcpPage`: `<title>`, header h1/subtitle, offline banner, type-selector blacklist hint, search placeholder, search button (`t("search")`), loading overlay, error/empty states, results summary badge — all translated
- Added `t` dependency to `handleSearch` useCallback; renamed local `t`/`type` vars to `tp` to avoid shadowing

**Locale additions:**
- `locales/en.json` + `locales/zh.json`: Added `"search"` key at top level (`"Search"` / `"查询"`)

---

## Recent Changes (v2.0 → v2.1)

- **Page transitions**: y-axis slide (y:8→0 enter, y:0→-4 exit) with custom cubic-bezier [0.22,1,0.36,1] at 0.22s for silky-smooth feel
- **Result card stagger**: Main grid uses `CARD_CONTAINER_VARIANTS` (staggerChildren:0.06s) — left and right columns animate in sequence with `CARD_ITEM_VARIANTS` (y:12→0, duration:0.32s)
- **NS row animations**: Each nameserver row is a `motion.div` with spring tap (scale:0.97) and hover nudge (x:2px)
- **Domain title animation**: `motion.h2` with spring tap (scale:0.97) on click-to-copy
- **Search button**: Spring tap (scale:0.9) via `motion.div` wrapper around submit button
- **Hydration fix**: `ResultSkeleton` replaced `Math.random()` widths with deterministic fixed array `[85,72,90,65,80,70]`
- **Glass panel polish**: Added `box-shadow` for depth; dark mode shadow uses black/30
- **CSS utilities added**: `animate-fade-in-up`, `animate-fade-in`, `animate-scale-in`, `stagger-1` through `stagger-5` delay classes
- **DNS tool** (`dns.tsx`): CAA record type added; AnimatePresence for all states; MX priority badges; SOA structured display; 4×DoH resolvers; preset shortcuts (基础解析/邮件安全/域名服务器/证书授权)
- **SSL tool** (`ssl.tsx`): ValidityBar progress component; AnimatePresence for all states; quick examples (google.com/github.com/cloudflare.com); refresh button
- **IP/ASN tool** (`ip.tsx`): AnimatePresence for all states; Yandex static map preview; IPv6 + ASN examples
- **Sponsor page** (`sponsor.tsx`): Full redesign — animated heart hero with floating hearts; Alipay/WeChat QR cards; PayPal button; BTC/ETH/USDT/OKX crypto addresses (CopyButton); "已完成赞助" post-payment form with AnimatePresence; bouncing emoji thank-you section
- **Sponsor submit API** (`/api/sponsors/submit.ts`): Public endpoint — inserts with `is_visible=false` for admin approval
- **Admin settings**: Added PayPal URL + 4 crypto address fields to sponsor section
- **DNS API** (`/api/dns/records.ts`): CAA (type 257) added to RECORD_TYPES, TYPE_NUM, and parseDoHData
- **Docs page** (`docs.tsx`): Three new API sections — `/api/dns/records`, `/api/ssl/cert`, `/api/ip/lookup`

## Tech Stack

- **Framework**: Next.js 14 (Pages Router)
- **Styling**: Tailwind CSS + Shadcn UI + Framer Motion
- **WHOIS**: whoiser library + node-rdap for RDAP queries
- **Caching**: ioredis (Redis)
- **i18n**: next-i18next (EN, ZH, DE, RU, JA, FR, KO)
- **Fonts**: Geist

## Build / Deployment

- **Config**: `next.config.js` (CommonJS, `require`/`module.exports`) — converted from `.mjs` to be compatible with Vercel's `sed`-based build command which patches `next.config.js`
- **TypeScript errors**: `typescript: { ignoreBuildErrors: true }` is pre-applied in the config, so Vercel's sed patch is a harmless no-op
- **Vercel build command**: `sed -i '...' next.config.js && node scripts/migrate.js && pnpm run build`

## Key Files

- `src/lib/whois/lookup.ts` — WHOIS/RDAP orchestration, caching, error detection
- `src/lib/whois/common_parser.ts` — Raw WHOIS text parser, field extraction, data cleaning
- `src/lib/whois/epp_status.ts` — EPP status code mapping with Chinese translations
- `src/lib/whois/rdap_client.ts` — RDAP query client
- `src/pages/api/lookup.ts` — API endpoint
- `src/pages/[...query].tsx` — Result display page
- `src/lib/lifecycle.ts` — Shared TLD lifecycle table (65+ gTLD/ccTLD); used by both frontend and backend for grace/redemption/pendingDelete period computation
- `src/pages/api/remind/submit.ts` — Subscription submission API
- `src/pages/api/remind/process.ts` — Cron processor that fires pre-expiry AND phase-event reminders
- `src/lib/email.ts` — All email templates (welcome, subscription confirm, pre-expiry reminder, phase event)
- `src/lib/admin-shared.ts` — Client-safe admin helpers: `ADMIN_EMAIL` constant and `isAdmin()` function (no Node.js imports)
- `src/lib/admin-server.ts` — Server-only admin helpers: `getAdminEmail()` (reads DB `site_settings.admin_email`, falls back to `ADMIN_EMAIL`), `isAdminEmail()` (async DB-checked comparison)
- `src/lib/admin.ts` — Server-only admin middleware: `requireAdmin()` for API route protection (uses `admin-server.ts` for dynamic email check)
- `src/lib/site-settings.tsx` — Site settings context: `SiteSettingsProvider`, `useSiteSettings()` hook, `DEFAULT_SETTINGS`
- `src/components/admin-layout.tsx` — Shared admin backend layout with sidebar navigation and auth guard
- `src/pages/admin/index.tsx` — Admin dashboard with real-time stats (users, stamps, reminders, searches)
- `src/pages/admin/settings.tsx` — Site settings editor (title, logo, subtitle, description, footer, icon, announcement)
- `src/pages/admin/users.tsx` — User management (search, list, delete)
- `src/pages/admin/stamps.tsx` — Stamp management (search, verify/unverify, delete)
- `src/pages/admin/reminders.tsx` — Reminder management (search, deactivate)
- `src/pages/api/admin/settings.ts` — GET (public) / PUT (admin-only) site settings
- `src/pages/api/admin/stats.ts` — Admin stats endpoint
- `src/pages/api/admin/users.ts` — Admin user management API
- `src/pages/api/admin/stamps.ts` — Admin stamp management API
- `src/pages/api/admin/reminders.ts` — Admin reminder management API
- `src/pages/api/admin/feedback.ts` — Admin feedback management API (GET list, DELETE)
- `src/pages/admin/feedback.tsx` — Feedback viewer: expandable cards with issue type badges, search, delete
- `src/pages/admin/sponsors.tsx` — Sponsor management: add/edit/delete records, visibility toggle, stats, payment QR settings
- `src/pages/api/admin/sponsors.ts` — Sponsor CRUD API (GET public with visible_only, POST/PUT/DELETE admin-only)
- `src/pages/sponsor.tsx` — Public sponsor page: payment QR codes, sponsor list, cumulative stats
- `src/lib/server/rate-limit.ts` — In-process sliding-window rate limiter: `rateLimit(key, limit, windowMs)` + `getClientIp(req)`

## Architecture

The lookup flow: API request → try RDAP → fallback to WHOIS → merge results → if still empty try yisi.yun fallback → cache in Redis → return to client.

### Lookup fallback chain

1. **RDAP** (`node-rdap` + bootstrap) — primary, returns structured JSON
2. **WHOIS** (`whoiser` + custom servers) — secondary, raw text parsed by `common_parser.ts`
3. **yisi.yun API** (`src/lib/whois/yisi-fallback.ts`) — tertiary; only invoked when both RDAP and WHOIS fail or return empty/error data for a domain query. Supports unusual TLDs with no public RDAP/WHOIS server. Zero overhead when native lookups succeed.

## Version History (current: 1.9)

- **v1.9** — Page smoothness: page transition 0.28 s → 0.22 s + ease-out-expo curve, `will-change` GPU hint, `prefers-reduced-motion` full support, smooth scroll, preconnect hints for exchange-rate API / IANA RDAP in `_document.tsx`
- **v1.8** — Lookup speed: WHOIS merge-wait 600 → 350 ms, progressive-fallback trigger 3 500 → 3 000 ms, whoiser eager warm-up at module init, TLD DB calls halved for 2-part domains (tld === tldSuffix deduplication)
- **v1.7** — API security: IP sliding-window rate limiting 40 req/min, GET-only method check, query length ≤ 300 chars, control-char rejection, standard X-RateLimit-* headers; four access-control toggles (disable_login / maintenance_mode / query_only_mode / hide_raw_whois) enforced in navbar + login + _app.tsx + query page

## Data Cleaning Enhancements (2026-03)

Enhanced `common_parser.ts` with:
- **HTML entity decoding**: Handles ccTLD WHOIS servers that return HTML entities in field values (e.g., `Activ&eacute;` → `Activé`)
- **Dot-pattern cleaning**: Strips leading dot sequences used by some ccTLD WHOIS servers as privacy redaction markers (e.g., `............value` → `value`)
- **Redacted value filtering**: Skips contact fields (email, phone, org, country) that are privacy-redacted (high dot ratio, REDACTED/WITHHELD keywords)
- **Universal field cleaning**: Applied to all parsed values via `cleanFieldValue()`

Enhanced `epp_status.ts` with:
- **Expanded status map**: 50+ status codes covering standard EPP + ccTLD-specific variants
- **Multi-language status support**: French (Activé, Enregistré, Supprimé, Expiré), German (registriert, aktiv, gesperrt, gelöscht), Spanish/Portuguese (registrado, activo, ativo), Dutch (actief, geregistreerd), Italian (registrato), Turkish (kaydedildi), etc.
- **Robust normalization**: Two-pass lookup — first tries with accented characters preserved, then falls back to ASCII-folded form
- **New categories**: Added `unknown` category for unregistered/available status codes
- **More EPP statuses**: quarantine, dispute, abuse, withheld, pendingPurge, verificationFailed, courtOrder, etc.

## Custom WHOIS Server Management (2026-03)

Added local WHOIS server management without touching rdap/whoiser libraries:

- **`src/lib/whois/custom-servers.ts`** — Extended server entry types:
  - `string` → TCP hostname (legacy, port 43)
  - `{ type: "tcp", host, port? }` → TCP with optional custom port
  - `{ type: "http", url, method?, body? }` → HTTP GET/POST with `{{domain}}` placeholder
- **`src/lib/whois/lookup.ts`** — Added:
  - `queryWhoisTcp()` — raw Node.js `net` TCP connection for non-43 ports
  - `queryWhoisHttp()` — fetch-based HTTP WHOIS query with URL template substitution
  - Updated `getLookupWhois()` to dispatch based on entry type
- **`src/pages/api/whois-servers.ts`** — GET/POST/DELETE API for managing custom servers (no auth required)
- **`src/pages/whois-servers.tsx`** — Full UI management page accessible via navbar "Servers" link
- **`src/data/custom-tld-servers.json`** — User-editable server map (persisted on disk)

Priority order: user custom servers → built-in servers → ccTLD servers → whoiser default discovery.

### ScraperEntry type (2026-03)

Added `{ type: "scraper", name, registryUrl }` entry type for TLDs that require multi-step HTTP scraping (e.g. CSRF tokens + cookies):
- **`src/lib/whois/http-scrapers/nic-ba.ts`** — Dedicated scraper for .ba (Bosnia) via nic.ba. Performs GET+POST form submission; fails gracefully when reCAPTCHA v2 blocks automated access.
- **`ScraperRequiredError`** — Custom error class in `lookup.ts` that carries `registryUrl` for propagation to the API response.
- **`WhoisResult.registryUrl`** — New optional field on `WhoisResult` type passed through to the API `Data` type.
- **Frontend** — Shows "Look up at Registry" button (with external-link icon) in both the "registered but no WHOIS" panel and the generic error fallback panel whenever `registryUrl` is present.
- **`.ba` fix** — Removed wrong `"ba": "whois.ripe.net"` mapping from `cctld-whois-servers.json` (set to `null`). Now .ba domains correctly show DNS-probe–based registration status + registry link.
- **Null filter** — `getAllCustomServers()` now filters out null values from cctld-whois-servers.json so BUILTIN_SERVERS entries can take precedence.

## Vercel / Edge Platform Deployment

The app is production-ready for Vercel and similar serverless platforms.

### Key configuration files:
- **`vercel.json`** — Function maxDuration per route (30s for lookup, 10s for others)
- **`.env.example`** — All required environment variables documented

### Environment variables for production:
| Variable | Required | Default | Description |
|---|---|---|---|
| `POSTGRES_URL` | **Yes** | — | Supabase/Neon PostgreSQL pooling URL |
| `POSTGRES_URL_NON_POOLING` | **Yes** | — | Direct connection for migrations |
| `NEXTAUTH_SECRET` | **Yes** | — | Random secret for JWT signing (`openssl rand -base64 32`) |
| `NEXTAUTH_URL` | **Yes** | — | Production URL e.g. `https://your-app.vercel.app` |
| `RESEND_API_KEY` | **Yes** | — | Resend API key for sending emails |
| `RESEND_FROM_EMAIL` | **Yes** | `noreply@x.rw` | Verified sender address on Resend |
| `NEXT_PUBLIC_BASE_URL` | Recommended | NEXTAUTH_URL | Base URL used in email links |
| `CRON_SECRET` | Recommended | — | Protects cron jobs; Vercel sends as `Authorization: Bearer` |
| `WHOIS_TIMEOUT_MS` | No | 4000 | WHOIS query timeout in ms (keep ≤ 7000 on Hobby plan) |
| `RDAP_TIMEOUT_MS` | No | 5000 | RDAP query timeout in ms |
| `FALLBACK_START_MS` | No | 1200 | ms delay before 3rd-party fallback starts racing native lookups |
| `NEXT_PUBLIC_MAX_WHOIS_FOLLOW` | No | 0 | WHOIS follow depth (0 = fastest) |
| `REDIS_URL` | No | — | Redis connection URL (optional caching) |
| `REDIS_CACHE_TTL` | No | 3600 | Result cache TTL in seconds |

See `.env.example` for complete reference with comments.

### Redis storage:
- Lookup results cached at key `whois:{query}` with TTL from `REDIS_CACHE_TTL`
- User-managed custom WHOIS servers stored at key `whois:user-servers` (no TTL — persistent)
- Without Redis, custom servers fall back to `src/data/custom-tld-servers.json` (local only)

### Vercel plan considerations:
- **Hobby plan (10s limit)**: Default `WHOIS_TIMEOUT_MS=4000` + `RDAP_TIMEOUT_MS=5000` keeps total request time well under 10s.
- **Pro plan (300s limit)**: Can safely increase `WHOIS_TIMEOUT_MS=7000` for maximum ccTLD WHOIS coverage.

## Brand Claim (品牌认领) & Domain Subscription (域名订阅)

### New Pages
- `src/pages/stamp.tsx` — Brand Claim page with DNS TXT ownership verification (3-step flow: form → verify → done)
- `src/pages/remind/cancel.tsx` — Subscription cancellation page (reads `?token=` param, calls cancel API)

### New API Routes
- `src/pages/api/stamp/submit.ts` — Submit a stamp claim; returns `txtRecord` and `txtValue` for DNS TXT verification
- `src/pages/api/stamp/check.ts` — Query verified stamps for a domain
- `src/pages/api/stamp/verify.ts` — DNS TXT + HTTP file verification (multi-resolver, DoH fallback, fuzzy match)
- `src/pages/api/vercel/add-domain.ts` — Register domain with Vercel project; returns `_vercel` TXT record for ownership proof
- `src/pages/api/vercel/check-domain.ts` — Poll Vercel verify endpoint; updates stamp as verified if DNS propagated
- `src/pages/api/remind/submit.ts` — Subscribe to domain expiry reminders
- `src/pages/api/remind/cancel.ts` — Cancel a subscription via cancel token (returns JSON)
- `src/pages/api/remind/process.ts` — Cron job: sends reminder emails via Resend, marks sent records

### Libraries
- `src/lib/supabase.ts` — Supabase JS client singleton (REST-based, works from any network)
- `src/lib/db.ts` — Retained for pg Pool schema definitions (TABLES array); pg Pool only used on Vercel where TCP is allowed
- `src/lib/rate-limit.ts` — In-memory IP rate limiter (5 req/min per IP, auto-cleanup)

### Database Architecture
All API routes use `@supabase/supabase-js` (HTTP/REST) via `src/lib/supabase.ts`.
This allows the app to connect to Supabase from **any network** (Replit dev, Vercel production) 
without requiring direct TCP access to PostgreSQL port 5432/6543.

Required Supabase tables — **created automatically by `scripts/migrate.js` on each Vercel build**:
- `users` — user accounts for auth
- `password_reset_tokens` — password reset tokens (60-min expiry, single-use)
- `stamps` — brand claiming records
- `reminders` — domain expiry reminder subscriptions (`phase_flags TEXT` column required — run migration below)
- `reminder_logs` — tracking which reminder thresholds have been sent
- `tool_clicks` — global aggregate click counts per tool URL
- `user_tool_clicks` — per-user click counts for personalized sorting
- `search_history` — per-user search history (last 50 queries)

### Environment Variables Required
| Variable | Required | Description |
|---|---|---|
| `SUPABASE_URL` | Yes | Supabase project URL (e.g. `https://xxxx.supabase.co`) |
| `SUPABASE_SERVICE_KEY` | Yes | Supabase service role key (from project Settings → API) |
| `NEXTAUTH_SECRET` | Yes | Random secret for NextAuth JWT signing |
| `RESEND_API_KEY` | Yes | Resend API key for sending reminder/reset emails |
| `RESEND_FROM_EMAIL` | No | Sender address for emails (defaults to `noreply@x.rw`) |
| `NEXT_PUBLIC_BASE_URL` | Yes | Public URL for cancel/reset links in emails |
| `CRON_SECRET` | Recommended | Secret token to protect `POST /api/remind/process` |
| `VERCEL_API_TOKEN` | Yes (Vercel verify) | Vercel API token for domain verification |
| `VERCEL_PROJECT_ID` | Yes (Vercel verify) | Vercel project ID (`prj_...`) |
| `POSTGRES_URL_NON_POOLING` | Vercel only | Direct Supabase connection for pg Pool migrations |

### Pending DB Migrations
Run in **Supabase Dashboard → SQL Editor**:
```sql
-- Add phase_flags column to reminders table (phase event notification preferences)
ALTER TABLE reminders ADD COLUMN IF NOT EXISTS phase_flags text DEFAULT NULL;
```
The column is optional — the code defaults all phase flags to `true` if the column is missing or null, so existing subscriptions are unaffected until users re-subscribe.

### Cron Setup
To trigger reminder emails automatically, set up a cron job (e.g. daily) to call:
```
GET /api/remind/process?secret=<CRON_SECRET>
```
Or with a header:
```
GET /api/remind/process
x-cron-secret: <CRON_SECRET>
```

## IDN / Chinese Domain Handling

- **WHOIS punycode conversion**: `getLookupWhois` converts non-ASCII domains (e.g., `亲爱的.中国`) to their punycode equivalents (e.g., `xn--7lq487f54c.xn--fiqs8s`) via `domainToASCII()` before querying the WHOIS server
- **DNS probe punycode**: `probeDomain` similarly converts IDN inputs to punycode before DNS lookups
- **"No matching record" = available**: When WHOIS returns a "no match / not found" type response (pattern set `WHOIS_NOT_REGISTERED_PATTERNS`), the code treats this as "domain available" rather than a lookup failure — skipping the DNS fallback probe (which gives false positives for TLDs with wildcard A records like `.中国`). Yisi.yun is still tried first; if it fails, the domain is returned with `dnsProbe.registrationStatus: "unregistered", confidence: "high"` so the AvailableDomainCard is shown correctly.

## Dev Server

Runs on port 5000 via `pnpm run dev` (next dev -p 5000 -H 0.0.0.0).

## Tian.hu (田虎) Integration

Free public API (25 req/min, 300 req/day), no auth required.

### Integrated Features

| Feature | Endpoint | Usage |
|---------|----------|-------|
| WHOIS fallback | `/whois/{domain}` | `src/lib/whois/tianhu-fallback.ts` (tried before yisi.yun) |
| Domain pricing | `/tlds/pricing/{tld}` | `src/lib/pricing/client.ts` (3rd source, merged) |
| Translation | `/translate/{stem}` | `src/pages/api/tianhu/translate.ts` → shown on result page |
| DNS records | `/dns/{domain}` | `src/pages/api/tianhu/dns.ts` → shown on result page |

### Result Page Display

**Translation strip** (`[...query].tsx`):  
- Fetched client-side via `useEffect` when domain changes
- Displayed horizontally between "time·source" row and dates section
- Shows: "含义 **{zh translation}** {pos tag} {meaning}" in violet
- Only shown when `dst !== null` (omits pure-numeric domains, IPs)

**DNS Records card** (`[...query].tsx`):
- Shown after the WHOIS Name Servers card
- Displays A, NS, MX, SOA, TXT, AAAA records with TTL
- Skeleton loading animation while fetching
- Records animate in staggered with opacity

### Anti-Flicker Improvements

- ResultSkeleton now wrapped in `AnimatePresence` with opacity 0→1/0 transitions (no abrupt switch)
- Main result cards use pure `opacity` animation (no scale → no "pop" effect)
- Async-loaded sections (translation, DNS) animate in smoothly without layout shift

## Database Schema (Full Table List)

All persistent state lives in PostgreSQL (`src/lib/db.ts`). Tables auto-created on startup via `runMigrations()`.

| Table | Purpose |
|-------|---------|
| `users` | Registered accounts — email, password_hash, disabled, avatar_color, email_verified, etc. |
| `password_reset_tokens` | Secure time-limited reset links |
| `stamps` | Domain brand claims, awaiting admin verification |
| `reminders` | Domain expiry alert subscriptions |
| `reminder_logs` | Tracks which reminder phases have been sent (dedup) |
| `tool_clicks` | Aggregate link-click counts for Tools/Links pages |
| `user_tool_clicks` | Per-user link-click history |
| `search_history` | All queries (user_id nullable — anonymous queries also recorded) |
| `feedback` | User-submitted issue reports |
| `site_settings` | Key-value admin settings (title, OG, API keys, announcements) |
| `tld_fallback_stats` | Per-TLD failure tracking; enables 3rd-party fallback after 3 consecutive failures |
| `custom_whois_servers` | Admin-managed custom WHOIS server overrides (JSONB per TLD) |
| `rate_limit_records` | DB-backed rate limiting (key = IP, count + reset_at per 60s window) |

**Concurrent migration guard**: `getDbReady()` uses a shared Promise lock (`global.__pgMigrating`) so parallel Next.js requests on cold start never trigger duplicate migrations.

## Rate Limiting

`src/lib/rate-limit.ts` — DB-backed with in-memory fast-path:
- Hot path: in-memory Map for IPs seen within current server process window
- Cold path: atomic `INSERT … ON CONFLICT DO UPDATE` into `rate_limit_records`
- Fallback: pure in-memory if DB unavailable
- `checkRateLimit(ip, maxRequests)` is now `async` — all call sites use `await`

## TLD Smart Fallback Gate

`src/lib/whois/tld-fallback-gate.ts` — prevents over-reliance on paid 3rd-party APIs:
- Tracks per-TLD failure count in `tld_fallback_stats`
- Native RDAP/WHOIS failures increment count; success resets to 0
- Third-party APIs (tianhu / yisi) only invoked when `fail_count >= 3` AND `use_fallback = true`
- Admin UI: `/admin/tld-fallback` — view stats, toggle fallback per TLD, bulk clear

## v2.0 — UI Micro-Interactions

- **Button press feedback**: `Button` base class gains `active:scale-[0.96] touch-manipulation select-none` — all buttons scale slightly on press
- **Spring physics clicks**: `src/components/motion/clickable.tsx` — `<Clickable>` wraps any child with a Framer Motion spring (stiffness 600 / damping 32 / mass 0.6) for a natural squish-and-release feel
- **TLD page tab animation**: `AnimatePresence mode="wait"` with x-slide + fade between "TLD List" and "WHOIS Servers" tabs (0.22s ease-out-expo)
- **Server row edit expansion**: Inline edit form animates open/closed with `height: 0 → auto` via `motion.div`; row → form swap is wrapped in per-row `AnimatePresence mode="wait"`
- **Add-server form**: Same height animation via `AnimatePresence` wrapping the `showAdd` conditional
- **Global tap delay elimination**: `globals.css` adds `touch-action: manipulation` to all `button`, `a`, `[role="button"]`, `select` elements — removes 300 ms iOS tap delay everywhere

## Admin Backend Pages

| Page | Route |
|------|-------|
| Dashboard | `/admin` |
| Users | `/admin/users` |
| Brand Claims | `/admin/stamps` |
| Reminders | `/admin/reminders` |
| Search Records | `/admin/search-records` |
| User Feedback | `/admin/feedback` |
| TLD Fallback Stats | `/admin/tld-fallback` |
| System Status | `/admin/system` |
| API Keys | `/admin/api` |
| Site Settings | `/admin/settings` |
| Invite Codes | `/admin/invite-codes` |
| Friendly Links | `/admin/links` |

## Admin-Managed Content (v2.0)

### Friendly Links (`/links`)
- Fully DB-backed: `friendly_links` table (id, name, url, description, category, sort_order, active)
- Public API: `/api/links` (GET active links, sorted by sort_order then id)
- Admin CRUD: `/api/admin/links` (GET/POST/PUT/DELETE)
- Admin page: `/admin/links` — create/edit/delete/toggle visibility, optional category grouping
- Links page groups by category, shows empty state when no links added
- Subtitle and title customizable via `links_title` / `links_content` in site settings

### About Page (`/about`)
- Chinese intro (`about_content`), English intro (`about_intro_en`) — both editable in admin settings
- Contact email (`about_contact_email`) — shown as a mailto link on about + links pages
- GitHub URL (`about_github_url`) — shown in tech stack section
- Thanks/acknowledgements (`about_thanks`) — JSON array `[{name, url, desc, descEn}]`, falls back to hardcoded defaults
- All fields editable via Admin Settings → 关于页面 section

## Domain Subscription Enhancement (v2.0)

### DB-Configurable TLD Lifecycle Rules
- `tld_lifecycle_overrides` table: admin-set grace/redemption/pendingDelete days per TLD
- `src/lib/server/lifecycle-overrides.ts`: 5-minute in-memory cache; `loadLifecycleOverrides()` + `invalidateLifecycleOverridesCache()`
- `getTldLifecycle()` and `computeLifecycle()` in `lifecycle.ts` accept optional `overrides` dict; DB values take priority over hardcoded table
- Admin API: `/api/admin/tld-lifecycle` — GET list, POST create (id auto-gen), PATCH update, DELETE; all writes call `invalidateLifecycleOverridesCache()`
- Admin page: `/admin/tld-lifecycle` — searchable table, add/edit/delete dialog, shows TLD + days + registry + built-in comparison

### Drop Notifications (v2.0)
- `dropApproachingHtml` + `domainDroppedHtml` templates added to `src/lib/email.ts`
- `DROP_SOON_KEY = -4`: sent when `phase === pendingDelete` AND `daysToDropDate <= 7` (not already sent)
- `DROPPED_KEY = -5`: sent when `phase === dropped` → notification then deactivate subscription
- `process.ts` loads overrides once per cron run, passes to all `computeLifecycle()` calls

### Subscription API & Dashboard Upgrade
- `/api/user/subscriptions` GET now returns computed lifecycle fields per subscription: `drop_date`, `grace_end`, `redemption_end`, `phase`, `days_to_expiry`, `days_to_drop`, `tld_confidence`
- `dashboard.tsx` removed local 13-TLD `LIFECYCLE` table + `getDomainLifecycle()` — lifecycle data now comes from the API using the full 200+ TLD table
- `urgentSubs` now includes subscriptions where `days_to_drop <= 7` (approaching drop date)
- Subscription cards show purple "X天后可抢注" badge when approaching drop; drop date rendered in purple when urgent

## Registration Security (v2.0)

### Invite Code System
- `invite_codes` table: `XXXXXX-XXXXXX-XXXXXX` uppercase codes, single-use
- `require_invite_code = "1"` site setting gates registration behind invite codes
- `subscription_access` + `invite_code_used` columns on users
- Existing users can apply codes from Dashboard → Subscription tab
- Admin API: `/api/admin/invite-codes` (GET list, POST create, DELETE by id)

### Email OTP Verification
- `/api/user/send-verify-code` — sends 6-digit code via Resend, stored in Redis (`verify:register:{email}`)
- 10-minute TTL, 60-second resend rate limit (`verify:rate:{email}`)
- Register page shows email field + "发送验证码" button with 60s countdown
- OTP input appears after code is sent; register API validates before creating account

### CAPTCHA (Human Verification)
- Provider, site key, secret key stored in `site_settings` (`captcha_provider`, `captcha_site_key`, `captcha_secret_key`)
- `captcha_secret_key` filtered from public GET; returned only for admin session
- `src/lib/server/captcha.ts` — `getCaptchaConfig()` + `verifyCaptchaToken()` supporting Turnstile and hCaptcha
- Register page: loads CAPTCHA script dynamically (explicit render mode), shows widget after invite code field
- Register API: verifies token server-side before account creation
- Admin Settings → 人机验证: provider dropdown, site key input, secret key (password) input

## Admin Backend Comprehensive Enhancement (2026-03-24)

### Critical Bug Fixes
- **Refund auto-revokes subscription**: `mark_refunded` in `/api/admin/payment/orders.ts` now also sets `subscription_access=FALSE` on the user (by `user_id` first, then `user_email` fallback). Returns `subscriptionRevoked: true` flag so UI can show a relevant toast.

### Cross-Page Deep Links
- **Orders → Users**: User email/name in orders list is now a clickable button that navigates to `/admin/users?search=EMAIL`
- **Users → Orders**: Edit modal has a "订单" button that navigates to `/admin/payment/orders?search=EMAIL`
- **URL pre-population**: Both orders and users pages read `?search` query param on mount to pre-fill search input when navigated from cross-links

### Inline Confirm Dialogs (replace native browser `confirm()`)
- **Users page delete**: First click on trash icon shows inline "确认删除 | ✕" row. Second click executes. Auto-clears after 4 seconds.
- **Orders page actions**: First click on mark-paid / refund shows inline amber warning banner "再次点击确认". Auto-clears after 4 seconds.
- **Feedback page delete**: Same inline confirm pattern with 4-second auto-cancel.

### Users Page CSV Export
- "导出 CSV" button in header exports all currently-loaded users with UTF-8 BOM for Excel compatibility
- Fields: email, name, registration time, email_verified, subscription_access, disabled, search_count, stamp_count, reminder_count, admin_notes

### Orders Stats — Per-Currency Revenue
- Stats query now groups by currency; returns `byCurrency: [{currency, revenue, count}]`
- UI shows single value for single-currency setups, per-currency table for multi-currency
- Added "已退款" count stat card alongside total/paid

### Dashboard Refresh Button
- `/admin/index.tsx`: refresh icon button next to "系统概览" heading; triggers `loadStats()`; spins during load

### Missing AdminLayout Titles Fixed
- `changelog.tsx`: `<AdminLayout title="更新日志">`
- `og-styles.tsx`: `<AdminLayout title="OG 卡片样式">`

### OG Styles SSP Auth Fixed
- `og-styles.tsx` used `requireAdmin` (API-route style) from `getServerSideProps` causing `res.status is not a function` 500 error
- Fixed to use `getServerSession` + `isAdmin` directly with proper SSR `redirect` instead

### Feedback Page Enhancements
- Reply-by-email button (envelope icon) appears on hover next to delete; opens pre-filled mailto: with domain in subject
- Expanded panel now shows: user description + action buttons ("复制域名", "RDAP 查看", "回复 EMAIL")
- All in-place confirm dialogs replace native `confirm()` calls UI — v3.22

## Payment System (Added 2026-03-24)

### Architecture
- **DB tables**: `payment_plans` + `payment_orders` (in `src/lib/db.ts`)
- **Core library**: `src/lib/payment.ts` — order lifecycle, provider signing/verification
- **API routes**:
  - `GET /api/payment/plans` — public plan listing
  - `POST /api/payment/create` — create order + redirect URL
  - `GET /api/payment/status?order=ID` — order status polling
  - `POST /api/payment/webhook/stripe` — Stripe payment confirmation
  - `POST /api/payment/webhook/xunhupay` — Xunhupay (虎皮椒) confirmation
  - `POST /api/payment/webhook/alipay` — Alipay confirmation
  - `GET/POST /api/admin/payment/plans` — admin CRUD
  - `GET/POST /api/admin/payment/orders` — admin order management + mark-paid/refund
- **User pages**:
  - `/payment/checkout` — plan selection + provider selection + checkout
  - `/payment/result?order=ID` — payment result with auto-polling
- **Admin pages**:
  - `/admin/payment/plans` — plan CRUD (price, duration, currency, active toggle)
  - `/admin/payment/orders` — order listing with stats, filters, manual mark-paid/refund
  - Settings → 支付网关 — enable/disable providers, set public keys

### Providers
| Provider | Enable Flag | Public Key Setting | Private Key ENV |
|---|---|---|---|
| Stripe | `payment_stripe_enabled` | `payment_stripe_pk` | `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` |
| Xunhupay (虎皮椒) | `payment_xunhupay_enabled` | `payment_xunhupay_appid` | `XUNHUPAY_APP_SECRET` |
| Alipay (官方) | `payment_alipay_enabled` | `payment_alipay_appid`, `payment_alipay_notify_url` | `ALIPAY_PRIVATE_KEY`, `ALIPAY_PUBLIC_KEY` |

### Flow
1. Admin creates plans in `/admin/payment/plans`
2. Admin enables providers in Settings → 支付网关
3. User visits `/payment/checkout`, selects plan + provider
4. Provider redirect → webhook fires → `markOrderPaid()` sets `subscription_access=TRUE` + creates sponsor record
5. User lands on `/payment/result?order=ID` (auto-polls until paid)
6. Dashboard shows "购买套餐解锁" button when any provider is enabled

---

A fast, modern WHOIS and RDAP lookup tool supporting domains, IPv4/IPv6, ASN, and CIDR. Also includes built-in DNS, SSL certificate, and IP/ASN geolocation tools.

---

## Changelog

### v3.22.2 — RDAP Coverage Expansion: 168 ccTLDs + Conflict Fixes + Per-TLD Timeouts (2026-03-24)

**Scope:** Largest single RDAP coverage expansion yet. Fixed 15 blocking conflicts in `STATIC_NO_RDAP`, added 40+ new ccTLD RDAP servers confirmed by live probing, introduced per-TLD timeout map for slow registries, and set up automated monthly bootstrap refresh via GitHub Actions.

| File | Change | Detail |
|------|--------|--------|
| `src/lib/whois/tld-rdap-skip.ts` | **Fixed 15 critical STATIC_NO_RDAP conflicts** | `ru`, `by`, `kz`, `lb`, `ve`, `ec`, `tl`, `cd`, `af`, `gh`, `ug`, `et`, `ci`, `dj`, `ss` were in STATIC_NO_RDAP but also in CCTLD_RDAP_OVERRIDES, causing RDAP to be blocked entirely for these TLDs. All removed. STATIC_NO_RDAP reduced from ~25 → 21 genuinely RDAP-less TLDs. |
| `src/lib/whois/rdap_client.ts` | **CCTLD_RDAP_OVERRIDES expanded to 168 ccTLDs** | Added 40+ new entries: Western Europe (`at`, `be`, `ch`, `de`, `dk`, `ee`, `es`, `gr`, `hr`, `hu`, `ie`, `it`, `li`, `lt`, `lu`, `lv`, `me`, `pt`, `ro`, `rs`, `se`, `sk`), CIS (`by`, `kz`, `ru`, `su`), Other (`im`, `io`, `mn`, `my`, `nu`, `ph`, `hk`, `jp`, `kr`, `co`, `mx`, `pe`, `ve`, `za`). Entries reorganized by region. |
| `src/lib/whois/rdap_client.ts` | **`RDAP_TLD_TIMEOUT_MS` per-TLD timeout map** | 32-entry map with extended timeouts (6–8 s) for known-slow registries in Africa (`ng`, `ke`, `tz`, `gh`, `ug`), CIS (`ru`, `su`, `by`, `kz`), Middle East (`iq`, `sy`, `ye`), and Asia (`pk`, `np`, `mm`, `la`, `kh`). Default remains 4 s. |
| `src/lib/whois/rdap_client.ts` | **`lookupRdap` uses per-TLD timeout** | `RDAP_TLD_TIMEOUT_MS[tld] ?? 4000` passed to `tryRdapWithUrl` instead of hardcoded 4000. |
| `package.json` | **npm script** | `update:rdap-bootstrap` → `node scripts/update-rdap-bootstrap.js` for manual refresh. |
| `.github/workflows/update-rdap-bootstrap.yaml` | **GitHub Actions cron** | Runs `scripts/update-rdap-bootstrap.js` on the 1st of every month at 02:00 UTC, commits updated `rdap_gtld_bootstrap.ts` if changed. |

### v3.22.1 — Bug Fix Batch (2026-03-24)

**Scope:** Six targeted bug fixes across lookup recording, subscription session sync, query-only mode, admin pages, and announcement bar positioning.

**Changes:**

| File | Fix | Detail |
|---|---|---|
| `src/pages/api/lookup.ts` | Search history for logged-in users | Added `getServerSession` call; `saveSearchRecord` now accepts optional `userId` — logged-in users get their own `user_id`-linked records (upsert via delete+insert), anonymous users retain existing trim-to-50 logic. |
| `src/pages/dashboard.tsx` | Subscription session sync | When `apply-invite-code` returns "你已拥有订阅权限" (DB has access, JWT doesn't), client now calls `updateSession({ subscriptionAccess: true })` and switches to subscriptions tab instead of showing an error. |
| `src/components/navbar.tsx` | query_only_mode hides HistoryDrawer | `HistoryDrawer` reads `query_only_mode` from site settings via `useSiteSettings()` and returns `null` for non-admin users when the mode is enabled. Early return placed after all hooks to comply with React rules. |
| `src/pages/_app.tsx` | Announcement bar overlap fix | `AnnouncementBanner` sets CSS custom property `--ann-h` (36px when visible, 0px when dismissed) on the document root. Main element padding updated to `calc(4rem + var(--ann-h, 0px))`. |
| `src/components/navbar.tsx` | Navbar clears announcement overlap | Outer div uses `style={{ top: 'var(--ann-h, 0px)', transition: 'top 0.2s ease' }}` instead of hard-coded `top-0`, smoothly sliding below the announcement bar. |
| `src/pages/admin/tld-lifecycle.tsx` | Built-in lifecycle reference table | Added collapsible section showing all LIFECYCLE_TABLE entries. Each row has "添加覆盖" that pre-fills the form; already-overridden TLDs show a "已覆盖" badge. |
| `src/pages/admin/reminders.tsx` | Edit + Send Email for reminders | Added inline edit panel per record (domain, email, expiration_date, days_before); added send-email button (plane icon). |
| `src/pages/api/admin/reminders.ts` | Extended PATCH + POST send-email | PATCH now updates any combination of domain/email/expiration_date/days_before/active. New POST `?action=send-email` fetches reminder, computes daysLeft, sends `reminderHtml` via Resend. |

---

### v3.22 — Comprehensive Multilingual WHOIS Status Detection (2026-03-24)

**Scope:** Full multilingual expansion of domain status detection (reserved / prohibited / suspended). Both `common_parser.ts` (server-side) and `[...query].tsx` (client-side safety net) are now synced with identical pattern coverage for 25+ languages/registries.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/whois/common_parser.ts` | `syntheticReserved` expansion | Added field:value regex patterns for Italian `riservato`, Swedish `reserverad`, Norwegian `reservert`, Danish `reserveret`, Polish `zarezerwowany`, Dutch `gereserveerd`, Finnish `varattu`, Hungarian `fenntartott`, Romanian `rezervat`, Turkish `rezerve`, Greek `δεσμευμένο`; direct includes for Russian `зарезервирован`/`зарезервировано`/`зарезервирована`, Ukrainian `зарезервовано`, Japanese `予約済み`/`登録停止`, Korean `예약됨`/`예약된`, Arabic `محجوز`, Hebrew `שמור`, Traditional Chinese `保留網域`. |
| `src/lib/whois/common_parser.ts` | `syntheticProhibited` expansion | Added Russian `запрещена регистрация`/`регистрация запрещена`, Ukrainian `реєстрація заборонена`, Italian `registrazione vietata`/`status: vietato`, Japanese `登録不可`/`登録制限`, Korean `등록불가`/`등록 금지`, Arabic `محظور`, Chinese `不可注册`/`禁止使用`. |
| `src/lib/whois/common_parser.ts` | `syntheticSuspended` expansion | Added Portuguese `suspenso`, Italian `status: sospeso`/`dominio sospeso`, Dutch `opgeschort`, Polish `zawieszony`, Finnish `keskeytetty`, Russian `приостановлен`/`приостановлено`, Ukrainian `призупинено`, Japanese `停止中`/`利用停止`, Korean `정지됨`/`사용 정지`, Arabic `موقوف`/`معلق`, Chinese `已停用`/`暂停使用`. |
| `src/pages/[...query].tsx` | `rawHasReserved` / `rawHasProhibited` / `rawHasSuspended` | Synced with identical expanded pattern lists from `common_parser.ts`. Latin-script patterns use field:value regex to avoid false positives from domain names containing those words. Non-Latin scripts use direct includes (safe: domain names are punycode in WHOIS). |
| `src/lib/env.ts` | VERSION bumped to "3.22" | |

**Design rationale:**
- Latin-script single words (e.g. `reserviert`, `riservato`) use `/\bstatus\s*:\s*<word>\b/` regex OR require phrase context, preventing false positives when a domain name itself contains that word (e.g. `riservato.it`).
- Non-Latin scripts (Cyrillic, CJK, Arabic, Hebrew) safely use `includes()` — domain labels appear as punycode (`xn--…`) in WHOIS, never as raw Unicode characters.

---

### v3.21 — Reserved/Premium Domain Detection + Multilingual Patterns (2026-03-24)

**Scope:** Introduced `registry-premium` status tag; added 30+ English reserved phrases; initial multilingual reserved/prohibited/suspended patterns.

---

### v3.20 — Invite Code System Overhaul + UX Fixes (2026-03-24)

**Scope:** Complete rebuild of invite code expiry, validation, and activation flow; fixed critical bug where optional invite codes were silently ignored during registration.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/db.ts` | Schema: `expires_at` | Added `ALTER TABLE invite_codes ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ` migration. |
| `src/pages/api/admin/invite-codes.ts` | Expiry support | POST now accepts `expires_in` (1d / 7d / 30d / 365d / permanent); GET returns `expires_at`; `parseExpiresAt()` helper converts preset to absolute timestamp. |
| `src/pages/api/user/apply-invite-code.ts` | Expiry + updated_at | Validates `expires_at` (rejects if past); updates `updated_at` on user row. |
| `src/pages/api/user/register.ts` | Critical bug fix | Previously, if `require_invite_code = "0"`, any invite code filled in by the user was silently ignored and `subscription_access` stayed `false`. Now: optional codes are still validated + applied, granting `subscription_access = true` on registration. Also adds expiry check. |
| `src/pages/admin/invite-codes.tsx` | UI overhaul | Stats grid → 5 columns (adds 已过期/red); filter tabs → 5 tabs (adds 已过期); create modal → expiry pill picker (永久/1天/1周/1月/1年); table → 有效期 column with relative display; purge button now targets both exhausted AND expired codes. |
| `src/pages/dashboard.tsx` | Better UX after activation | After successful code redemption: clears the input, switches to the subscriptions tab immediately, so users see their newly unlocked feature at once. |
| `src/lib/env.ts` | VERSION bumped to "3.20" | |

---

### v3.19 — Fix Search Spinner on Nav Link Clicks (2026-03-24)

**Scope:** Bug fix — the search button spinner was incorrectly showing when clicking ordinary nav links (e.g. About, Links, Admin pages) from the home page or a results page.

**Root cause:** Both `index.tsx` and `[...query].tsx` defined their own inline `isSearchRoute()` helper with a `STATIC_PATHS` allow-list. The list in `[...query].tsx` was incomplete (missing `/dns`, `/ssl`, `/ip`, `/icp`, `/about`, `/sponsor`, `/links`, `/changelog`, `/admin`, `/feedback`, etc.), so navigating to those paths from a results page would call `setLoading(true)` and spin the button indefinitely until the route completed.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/utils.ts` | `isSearchRoute()` shared export | Single canonical implementation with a complete `STATIC_PAGE_PREFIXES` allow-list; strips locale prefix before matching. |
| `src/pages/index.tsx` | Use shared `isSearchRoute` | Removed inline copy; imports from `@/lib/utils`. |
| `src/pages/[...query].tsx` | Use shared `isSearchRoute` | Removed inline copy (which had the incomplete prefix list); imports from `@/lib/utils`. |
| `src/lib/env.ts` | VERSION bumped to "3.19" | |

---

### v3.18 — Admin Access Keys Enrichment (2026-03-24)

**Scope:** Enriched the API 密钥 (access-keys) admin page with stats, dual filter rows, and bulk expired-key cleanup — matching the quality bar set for invite-codes in v3.17.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/admin/access-keys.tsx` | Stats grid | Added 4-stat grid: 全部 / 启用中 / 已停用 / 已过期 (red). |
| `src/pages/admin/access-keys.tsx` | Dual filter rows | Row 1: status filter pills (全部/启用/停用/已过期); Row 2: scope filter pills (全部范围/API/域名订阅/全部权限). Both compose together. Fixed "all" naming ambiguity by using `__any__` as the scope-filter sentinel. |
| `src/pages/admin/access-keys.tsx` | Relative last-used time | "最近使用" column now shows relative time (刚刚 / N分钟前 / N小时前 / N天前) with clock icon, and "从未使用" when `last_used_at` is null. |
| `src/pages/admin/access-keys.tsx` | Bulk purge + header count | "清理过期 (N)" button in header batch-deletes all expired keys; cumulative call count shown in subtitle. |
| `src/lib/env.ts` | VERSION bumped to "3.18" | |

---

### v3.17 — Admin Page Enrichment: Feedback, Invite Codes & Links (2026-03-24)

**Scope:** Enriched three admin management pages with richer filtering, stats, and bulk operations.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/api/admin/feedback.ts` | Issue-type filter + typeCounts | `GET` now accepts `issue_type` query param to filter by a single issue type; response includes `typeCounts` map (aggregated via `jsonb_array_elements_text`). |
| `src/pages/admin/feedback.tsx` | Stats bar + filter tabs | Added 5-card issue-type stats bar (不准确/不完整/过期/解析错误/其他) with percentage, each card clickable as a filter shortcut; pill-style filter tabs with per-type count badges; search and type filter compose together. |
| `src/pages/admin/invite-codes.tsx` | Stats grid + filter tabs + usage progress + bulk-delete | Added 4-stat grid (全部/可用/停用/耗尽); pill filter tabs (全部/可用/已停用/已耗尽); each code row now shows a colour-coded progress bar (green→amber at ≥80%); "清理耗尽" button batch-deletes all exhausted codes. |
| `src/pages/admin/links.tsx` | Category filter tabs + visibility toggle + stats | Added 3-stat grid (总数/已显示/分类数); dynamic per-category pill tabs derived from existing category values; "未分类" tab when uncategorised links exist; "隐藏已隐藏/显示已隐藏" toggle button shows count of hidden links. |
| `src/lib/env.ts` | VERSION bumped to "3.17" | |

---

### v3.16 — UX Animations Overhaul + No-Server TLD Fast-Fail (2026-03-24)

**Scope:** Mobile UX polish and WHOIS lookup hot-path optimization.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/_app.tsx` | Removed `RouteLoadingBar` | Deleted the 2 px top loading bar and its 50-line component. Text skeleton + shimmer already provide query feedback; the bar was visually redundant. |
| `src/pages/_app.tsx` | Smoother page transition | `pageTransition` duration 0.13 s → 0.20 s; easing `"easeOut"` → cubic-bezier `[0.22, 1, 0.36, 1]` (iOS-style spring feel). |
| `src/pages/[...query].tsx` | Improved card stagger | `CARD_CONTAINER_VARIANTS` stagger 0.025 s → 0.09 s; `CARD_ITEM_VARIANTS` now includes `y: 10 → 0` slide-up with `[0.22, 1, 0.36, 1]` easing, creating a natural "main content first, secondary sidebar after" reveal on mobile. |
| `src/pages/[...query].tsx` | WHOIS/RDAP tab fade | `ResponsePanel` tab content wrapped in `AnimatePresence mode="wait"` — switching between WHOIS and RDAP now cross-fades (0.15 s) instead of hard-cutting. |
| `src/lib/whois/lookup.ts` | `isTldKnownNoServer` hot-path check | Imported from `custom-servers.ts` and checked immediately before the whoiser TCP call. When a TLD is explicitly listed as `null` in `cctld-whois-servers.json`, throws instantly (0 ms) instead of waiting for a TCP timeout, letting the tianhu/yisi fallback race immediately. |
| `src/lib/env.ts` | VERSION bumped to "3.16" | |

---

### v3.15 — DB Cache Fix: In-Memory TLD Gate + Expanded RDAP/WHOIS Skip Lists (2026-03-24)

**Scope:** Eliminated the biggest remaining latency source — a Supabase DB query on every single WHOIS request — and expanded both the RDAP-skip and ccTLD-server lists.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/whois/tld-fallback-gate.ts` | Rewrote with in-memory startup cache | `isTldFallbackEnabled()` was hitting Supabase on every call. Now loads the entire `tld_fallback_overrides` table once at startup into a `Map`; subsequent calls are pure memory lookups (0 ms). Cache invalidated via `invalidateFallbackCache()`. Result: `ab.cd` query time 12 s → 1.26 s. |
| `src/lib/whois/tld-rdap-skip.ts` | Expanded `STATIC_NO_RDAP` | Added 17 confirmed no-RDAP ccTLDs: `.ac .aw .ax .bj .bv .cc .cg .cx .gg .hm .im .je .ms .pm .re .sh .yt`. Prevents wasted RDAP round-trips for these TLDs. |
| `src/data/cctld-whois-servers.json` | Comprehensive ccTLD server list | Grew from 206 → 255 entries covering all IANA ccTLDs. Added working servers for `.ad` (nic.ad), `.bh` (nic.bh), `.fm` (nic.fm), `.gf/.gp/.mq` (whois.nic.mq), `.gn` (ande.gov.gn), `.ls/.mc/.mr/.sl/.sm/.ss/.td` (nic.{tld}), `.mt` (whois.ripe.net), `.sr` (whois.sr), `.ye` (y.net.ye). `null` entries for TLDs with no reachable public server (`.cu`, `.kp`, `.gb`, etc.). |
| `src/lib/whois/custom-servers.ts` | `isTldKnownNoServer()` added | Exposes which TLDs are explicitly `null` in the cctld file. Builds a `Set<string>` (`_knownNoServerCache`) during `getAllCustomServers()` load; `isTldKnownNoServer(tld)` is a fast O(1) lookup. |
| `src/lib/env.ts` | VERSION bumped to "3.15" | |

---

### v3.14 — Query Speed: Timeout Tuning + Parallel Fallback Racing (2026-03-24)

**Scope:** Reduced all network timeouts and started the third-party fallback in parallel with native lookups instead of waiting for full TCP failure.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/whois/lookup.ts` | Timeout reductions | `RDAP_TIMEOUT` 7 s → 2 s; `WHOIS_TIMEOUT` 7 s → 4 s; `FALLBACK_START_MS` added at 2 s — fallback races natively after this delay instead of waiting for TCP timeout. |
| `src/lib/whois/tianhu-fallback.ts` | `TIANHU_TIMEOUT` | Set to 4 s (was unbounded). |
| `src/lib/whois/yisi-fallback.ts` | `YISI_TIMEOUT` | Set to 4 s (was unbounded). |
| `src/lib/pricing/client.ts` | Pricing timeout | Reduced to 4 s. |
| `src/lib/env.ts` | VERSION bumped to "3.14" | |

---

### v3.13 — Remove MOZ DA/PA/Spam Feature (2026-03-24)

**Scope:** Removed the MOZ Domain Authority / Page Authority / Spam Score feature entirely from the domain result page.

**Changes:**

- Removed all MOZ API calls, UI components, and related code from `src/pages/[...query].tsx`
- Removed MOZ-related environment variable references
- Cleaned up unused imports and state variables
- `src/lib/env.ts` VERSION bumped to "3.13"

---

### v3.12 — X.RW Full Rebranding + WeChat OG Image Fix (2026-03-24)

**Scope:** Complete visual rebranding to X.RW identity, with brand image assets and social sharing fixes.

**Changes:**

- Replaced all NEXT WHOIS branding with X.RW across navbar, OG images, meta tags, and site settings defaults
- Added X.RW brand images (`/public/brand/`) for OG cards and apple-touch-icon
- Fixed WeChat `og:image` — now always resolves to an absolute URL using canonical site origin
- Updated `apple-touch-icon`, `manifest.json` icons, and PWA manifest to X.RW assets
- `src/lib/env.ts` VERSION bumped to "3.12"

---

### v3.11 — Brand Stamp Certification: tian.hu / nazhumi.com / yisi.yun (2026-03-24)

**Scope:** Certified three technology-partner domains as official brand stamps in the X.RW stamp registry.

**Changes:**

- Added verified brand stamps for `tian.hu` (tianhu WHOIS data provider), `nazhumi.com` (domain pricing data), and `yisi.yun` (WHOIS fallback API)
- Stamp records created with `brand` style and appropriate card themes
- `src/lib/env.ts` VERSION bumped to "3.11"

---

### v3.10 — OG Image Text Editor, Changelog Sync & UX Cleanup (2026-03-24)

**Scope:** Admin panel enhancements and UX improvements.

**New features / fixes:**

- **OG image text editor (`/admin/og-styles`):** Brand name and tagline are now fully editable in the admin panel. Settings stored in `site_settings` (`og_brand_name`, `og_tagline`) with 5-minute server-side cache invalidation. Both fields are immediately reflected across all 8 OG card styles without code changes.
- **`api/og.tsx` — dynamic text:** All 10 hardcoded `"RDAP+WHOIS"` brand label occurrences across the 8 OG styles now read from the config API. Taglines similarly use the configurable tagline field. Default values remain `"RDAP+WHOIS"` and `"WHOIS / RDAP · Domain Lookup Tool"` when not overridden.
- **`api/og-config.ts` — extended config:** Config API now returns `brand_name` and `tagline` alongside `enabled_styles`, and accepts `PUT` requests to update them.
- **Changelog sync button (`/admin/changelog`):** "同步版本历史" button batch-imports predefined version entries (v3.6–v3.10) from the `changelog-sync` API, skipping duplicates. Useful for seeding a fresh DB.
- **User dashboard — value-tier badges hidden:** High-value / valuable domain badges in the search history list are no longer shown to users (data is still recorded server-side for admin analytics). Removed `tierCfg` badge render; `TIER_CFG` definition and `value_tier` recording untouched.

---

### v3.9 — API Key Authentication System (2026-03-24)

**Scope:** Complete API Key management system. Admins can create, revoke, and scope access keys, and optionally enforce key authentication across all public API endpoints.

**New features:**

- **`access_keys` DB table:** Stores keys with fields: `id`, `key` (`rwh_` + 40 hex), `label`, `scope` (`api` / `subscription` / `all`), `is_active`, `created_at`, `expires_at`, `last_used_at`, `use_count`. Auto-provisioned via `initDb()`.
- **`src/lib/access-key.ts` library:** `generateKey()` (rwh_ prefix + 40 hex chars), `validateApiKey()` (checks active, expired, scope), `extractApiKey()` (reads `X-API-Key` header or `?key=` query param), `enforceApiKey(req, res, scope)` (returns `boolean` — returns early if invalid), `isApiKeyRequired()` (reads `site_settings.require_api_key` with 30 s in-memory cache).
- **`/api/admin/access-keys` endpoint (GET/POST/PATCH/DELETE):** Full CRUD + a `POST { action: "toggle_require", enabled: bool }` to flip global enforcement; cache invalidated on toggle.
- **`/admin/access-keys` page:** Lists all keys (masked), shows scope badge, use count, last-used date; global enforcement toggle; "Generate Key" modal with label/scope/expiry fields; newly-created key revealed once in a dismissible alert; per-row enable/disable and delete actions.
- **Admin nav:** Added "密钥" entry pointing to `/admin/access-keys`.
- **API enforcement:** `enforceApiKey()` inserted (after rate limit, before business logic) in `api/lookup.ts`, `api/dns/records.ts`, `api/dns/txt.ts`, `api/ssl/cert.ts`, `api/ip/lookup.ts`. When `require_api_key = 0` (default), enforcement is a no-op (zero overhead).
- **Docs page:** New "API Key 鉴权" section with `#api-key` anchor; nav pill added; covers: header vs query-param usage, scope table, error response codes (401 / 403). `SectionHeader` updated to accept optional `id` prop.

---

### v3.8 — Page Transition Fixes, URL Param Loading & API Rate Limiting (2026-03-23)

**Scope:** Fixed multiple UX and security bugs accumulated since v3.6. Transitions now reliably fire between domain searches; tool pages correctly load query params from the URL on first render; DNS/IP/SSL APIs are now rate-limited.

**Bug fixes:**

- **`_app.tsx` — animationKey logic was inverted:** Pages under `/[...query]` all shared the same animation key (`router.pathname` = `/[...query]`), so navigating between domain searches produced no transition. Fixed by swapping the key strategy: shallow tool pages (`/dns`, `/ssl`, `/ip`, `/icp`, `/stamp`) use `router.pathname` (so they don't re-animate when the query string changes), and all other pages (including `/[...query]`) use `router.asPath` (so each unique domain URL gets its own transition).
- **`_app.tsx` — Restored `AnimatePresence mode="wait" initial={false}`** with a `motion.div` using pure-opacity `pageVariants` (0 → 1, 0.13 s). The previous v3.6 CSS-only approach was removed in favour of this corrected Framer Motion approach.
- **`[...query].tsx` — Card stagger restored (opacity-only):** The over-aggressive v3.6 removal of all stagger is reverted. Cards now stagger at 0.025 s intervals with opacity-only variants (no y-axis movement), keeping the feel smooth without the earlier jitter.
- **`dns.tsx` / `ssl.tsx` / `ip.tsx` — `router.isReady` missing from `useEffect`:** All three tool pages were reading `router.query` in a `useEffect(fn, [])` that ran before Next.js had populated the query object on first render, causing URL `?q=` params to be silently ignored. Changed dependency arrays to `[router.isReady]` with an early-return guard.
- **DNS/IP/SSL APIs — no rate limiting:** `api/dns/records`, `api/dns/txt`, `api/ip/lookup`, and `api/ssl/cert` had no request throttling, leaving them open to abuse. Added in-memory `rateLimit()` checks (60/min for DNS, 30/min for IP, 20/min for SSL) with `429` responses.

---

### v3.7 — Smart Redis Cache with Adaptive TTL (2026-03-23)

**Scope:** Replaced the flat-TTL Redis cache with a domain-type-aware intelligent cache layer. All lookups now avoid redundant WHOIS/RDAP server calls, with cache expiry tuned to how quickly each domain type's data actually changes.

**Cache TTL strategy:**

| Domain type | TTL | Rationale |
|---|---|---|
| IP / ASN / CIDR query | 24 h | IP allocations change extremely rarely |
| Registry-reserved / pending | 12 h | Slow-moving administrative status |
| Available / unregistered | 5 min | Could be registered at any moment |
| Registered, expired (≤0 d) | 10 min | May be re-registered imminently |
| Registered, expiring ≤7 d | 30 min | Could change hands soon |
| Registered, remaining ≤60 d | 1 h | Watch for changes |
| Registered, remaining >60 d | 6 h | Very stable — safe to cache long |
| Error / failed lookup | 0 | Never cache failures |

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/whois/types.ts` | Added `cachedAt?: number` and `cacheTtl?: number` to `WhoisResult` | `cachedAt` = Unix ms timestamp when result was cached; `cacheTtl` = remaining TTL seconds (from Redis `TTL` command when serving from cache, or initial TTL when freshly computed). |
| `src/lib/server/redis.ts` | Production-grade Redis client rewrite | Added `lazyConnect: true`, `enableOfflineQueue: false` (commands fail immediately when disconnected instead of queuing), `retryStrategy` capped at 3 retries, per-event `_available` flag tracked via `ready`/`close`/`reconnecting`/`end` events. Added `getRemainingTtl(key)` and `getJsonRedisValueWithTtl(key)` helpers (pipeline GET + TTL in one round-trip). |
| `src/lib/whois/lookup.ts` | `computeSmartTtl(result)` function | Exported function that classifies a `WhoisResult` and returns the appropriate cache TTL in seconds. Zero means "do not cache". |
| `src/lib/whois/lookup.ts` | `lookupWhoisWithCache` upgraded | L1 (memory, 30 s) → L2 (Redis, smart TTL). Cache hits return `cachedAt` + `cacheTtl` from stored metadata + live Redis TTL. Cache misses: compute smart TTL, store `{ cachedAt, cacheTtl }` in the stored object, write to Redis with that TTL. Failures (status=false) are never cached. |
| `src/pages/api/lookup.ts` | Dynamic `Cache-Control` header | `s-maxage` is now set to the actual smart TTL (e.g. 21600 for stable domains, 300 for available). `stale-while-revalidate` = min(TTL × 4, 86400). Vercel edge cache now matches Redis expiry. Also passes `cachedAt` and `cacheTtl` through in the JSON response. |
| `src/pages/[...query].tsx` | Cache TTL displayed in result footer | When a result is served from cache, the time strip shows e.g. `0.00s · cached (6h)` — the parenthesised value is the remaining TTL from Redis, formatted as Xh / Xm / Xs. |
| `src/lib/env.ts` | VERSION bumped to "3.7" | |

**Environment variables (Redis connection — any one set activates Redis):**

| Variable | Description |
|---|---|
| `KV_URL` or `REDIS_URL` | Full Redis connection URL (e.g. `redis://...` or `rediss://...`). Vercel KV uses `KV_URL`. Upstash uses `REDIS_URL`. |
| `REDIS_HOST` | Redis hostname (used if URL not set) |
| `REDIS_PORT` | Redis port (default 6379) |
| `REDIS_PASSWORD` | Redis password |
| `REDIS_DB` | Redis database index (default 0) |

### v3.6 — Mobile Animation Fix: No More Flash/Jitter (2026-03-23)

**Scope:** Eliminated all sources of mobile page-transition flash and result-card jitter.

**Root causes fixed:**
1. `AnimatePresence mode="sync"` in `_app.tsx` caused old and new pages to overlap during navigation, making the background "bleed through" and flash white/dark between pages.
2. `CARD_ITEM_VARIANTS` with `y: 12` + `staggerChildren: 0.06` in `[...query].tsx` made result cards appear to jump upward one-by-one, visually jittery on mobile.
3. "Available domain" hero section in `[...query].tsx` had `delay: 0.15 / 0.2 / 0.35` on motion elements, causing content to pop in piece-by-piece.
4. `dns.tsx` result cards had `y: 4` + `delay: index * 0.03` stagger, causing visible card cascade on mobile.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/styles/globals.css` | Added `.page-enter` CSS class | Pure opacity fade-in (0.12 s ease-out) using `@keyframes page-enter`. No transform, no `will-change`. |
| `src/pages/_app.tsx` | Removed `AnimatePresence` + `motion.div` page wrapper | Replaced with a plain `<div key={animationKey} className="page-enter">`. React unmounts old div, mounts new div with CSS animation — zero overlap, zero background flash. Also removed unused `pageVariants`, `pageTransition` constants and framer-motion import from this file. |
| `src/pages/[...query].tsx` | `CARD_CONTAINER_VARIANTS`: removed stagger | Changed from `staggerChildren: 0.06, delayChildren: 0.02` to a simple `duration: 0.15` fade-in for the entire container. |
| `src/pages/[...query].tsx` | `CARD_ITEM_VARIANTS`: removed y-axis movement | Items are now `opacity: 1` in both hidden and visible states — the container fade handles the appearance. No per-item stagger or y-offset. |
| `src/pages/[...query].tsx` | "Available domain" hero: removed delayed animations | Replaced `motion.div` (scale: 0.8→1, delay 0.15) for status badge, `motion.div` (delay 0.2) for domain name, and `motion.a` (scale: 0.95→1, delay 0.35) for CTA button with static `div`/`a` elements. Content appears instantly. |
| `src/pages/[...query].tsx` | Translation pill: removed y-axis offset | Changed `initial={{ opacity: 0, y: -4 }}` to `initial={{ opacity: 0 }}` only. |
| `src/pages/dns.tsx` | Removed `y: 4` stagger from result cards | Both `found` and `not-found` result cards now animate opacity-only (`initial={{ opacity: 0 }}`) with no per-index delay. |
| `src/lib/env.ts` | VERSION bumped to "3.6" | |

### v3.5 — Anonymous History Cap + Enriched Admin Backend (2026-03-23)

**Scope:** Anonymous query history capped at 50 (new replaces old). Admin backend fully enriched: user management gains subscription_access/email_verified toggles and per-user stats; search records gains individual-row delete, anonymous filter, and DB-tier badges; dashboard gains today's counters and richer stats; admin stats API expanded.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/api/lookup.ts` | Anonymous history: 50-cap + replace semantics | `saveAnonymousSearchRecord()` now: DELETE existing record for same query (user_id IS NULL), INSERT new record, then trim to `MAX_ANON_HISTORY = 50` (keep newest 50). Replaces the old 24-hour dedup approach. |
| `src/pages/api/admin/users.ts` | Added `subscription_access`, `email_verified` to SELECT/PATCH | All GET responses now include `subscription_access`, `email_verified`, `search_count`, `stamp_count`, `reminder_count` per user. PATCH accepts `subscription_access` and `email_verified`. New `subscribedCount` and `verifiedCount` summary counts in GET response. |
| `src/pages/api/admin/users.ts` | Added `subscribed` and `verified` filter options | Filter by `?filter=subscribed` or `?filter=verified` to show only users with subscription access or verified email. |
| `src/pages/api/admin/search-records.ts` | Individual record DELETE via `?id=xxx` | `DELETE /api/admin/search-records?id={id}` removes a single record. Also added `period=anonymous` and `user_id=null` bulk-delete options. |
| `src/pages/api/admin/search-records.ts` | Anonymous filter + anon/logged stats | `?filter=anonymous` returns only `user_id IS NULL` records. Stats response now includes `anonymous` and `logged` counts. Daily stats include `anon` column. Value tier now read from DB column (no recompute). |
| `src/pages/api/admin/stats.ts` | Added `anonSearches`, `todaySearches`, `todayUsers`, `subscribedUsers` | Dashboard overview can show today's activity pulse and subscription user count. |
| `src/pages/admin/index.tsx` | Today's activity bar + subscription stat card | Shows "今日动态" bar with new users / queries / anon count. Added "订阅用户" stat card. Recent searches show ghost icon for anonymous. |
| `src/pages/admin/users.tsx` | Full user management enrichment | Edit modal: subscription_access toggle (amber), email_verified toggle (emerald), disabled toggle (red), per-user stat mini-cards (searches / stamps / subscriptions). User list: VIP crown icon for subscription users, verified badge, stat chips, subscription quick-toggle button. Filter tabs: added "已订阅" and "已验证". |
| `src/pages/admin/search-records.tsx` | Individual delete + anonymous filter + DB tier badge | Each row has a delete button (appears on hover). New "匿名查询" filter tab. Stats strip expanded to 8 cards (anon + logged). Bulk delete adds "清空匿名记录". Value tier badge now reads from DB (no client-side score recompute). User/anon breakdown bar chart added to stats panel. |
| `src/lib/env.ts` | VERSION bumped to "3.5" | |

### v3.4 — Mobile UX: Instant Nav Feedback + Tiered History Retention + Pagination (2026-03-23)

**Scope:** Three parallel improvements: (1) immediate tap feedback on navigation via top loading bar; (2) smoother page transitions (pure opacity, no y-axis jank); (3) search history now has tiered expiry, 100-record cap, per-page pagination, value-tier badges, and confirmed delete-all.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/_app.tsx` | Added `RouteLoadingBar` component | 2 px primary-colour bar at top of screen. Appears immediately on `routeChangeStart` (15 % → 50 % → 75 % → 100 % on complete), giving instant click feedback on mobile. Uses router events, no external dependency. |
| `src/pages/_app.tsx` | Simplified page transition animation | Removed y-axis offset (`y: 6`/`y: -3`). Now pure opacity fade only (`0 → 1 → 0`), duration reduced to 0.15 s. Eliminates vertical jank that was especially noticeable on mobile. |
| `src/pages/_app.tsx` | Removed `willChange` hint | `willChange: "opacity, transform"` removed; `transform` is no longer needed since y-axis motion is gone. |
| `src/lib/db.ts` | Added `value_tier` column to `search_history` | `ALTER TABLE … ADD COLUMN IF NOT EXISTS value_tier TEXT NOT NULL DEFAULT 'normal'`. Stores computed domain value tier alongside each record for retention-rule enforcement. |
| `src/pages/api/user/search-history.ts` | Tiered retention cleanup (`pruneExpired`) | Runs after every POST. SQL removes records older than: 10 d (normal), 20 d (valuable, score ≥ 35), 50 d (high, score ≥ 55). |
| `src/pages/api/user/search-history.ts` | `MAX_HISTORY` 500 → 100 | Normal users now capped at 100 records. Oldest records trimmed after every write via `trimToLimit`. |
| `src/pages/api/user/search-history.ts` | Computes and stores `value_tier` on insert | `computeValueTier()` uses `scoreDomain()`: high (≥55) / valuable (≥35) / normal. Only for `domain` queries with `unregistered` status; all others default to `normal`. |
| `src/pages/api/user/search-history.ts` | GET now supports pagination | Accepts `?page=N`, returns `{ history, total, page, pages }`. Page size = 20. |
| `src/pages/dashboard.tsx` | History pagination state + controls | New states: `historyPage`, `historyTotal`, `historyPages`. `fetchHistory(page)` function. Prev / Next buttons shown when `pages > 1`. |
| `src/pages/dashboard.tsx` | Value-tier badges in history list | Each domain row shows a coloured "高价值" (amber) or "有价值" (violet) badge when `valueTier` is set, alongside the existing reg-status badge. |
| `src/pages/dashboard.tsx` | "全部删除" confirmation | `window.confirm` shows total count before deletion. Resets all pagination state on success. |
| `src/pages/dashboard.tsx` | Tab & stat card use `historyTotal` | History tab badge and overview card now show the server-side total instead of the current page length. |
| `src/pages/dashboard.tsx` | Retention hint footer | When only one page exists, shows "普通 10 天 · 有价值 20 天 · 高价值 50 天" instead of old "最近 50 条记录". |

### v3.3 — Fully Branded Email Templates with Dynamic Site Name (2026-03-23)

**Scope:** All outgoing system emails now read the site name from the database (`site_settings.site_logo_text`) and render it in logos, subjects, and footers. No more hardcoded "Next Whois" in any email. Covers every email route in the project.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/email.ts` | `getSiteLabel()` added with 60 s DB cache | Reads `site_logo_text` from `site_settings`; falls back to "NEXT WHOIS". Exported so any API route can call it once and pass the result down. |
| `src/lib/email.ts` | `emailLayout()` accepts `siteName` param | Logo renders site name split on last space, last word coloured with PRIMARY violet; logo is a clickable link to `BASE_URL`. Footer copyright line also uses `siteName`. |
| `src/lib/email.ts` | All builder functions accept `siteName?: string` | `welcomeHtml`, `subscriptionConfirmHtml`, `reminderHtml`, `phaseEventHtml`, `dropApproachingHtml`, `domainDroppedHtml`, `passwordResetHtml`, `adminNotifyHtml`, `feedbackHtml`, `highValueAlertHtml`, `verifyCodeHtml` all default to "NEXT WHOIS" when `siteName` is omitted. |
| `src/lib/email.ts` | `stampVerifyTimeoutHtml()` added | New styled email for DNS verification timeout on stamp/brand-claim flow. Matches app visual style; accepts `domain`, `fileContent`, `verifyUrl`, `siteName`. |
| `src/pages/api/user/register.ts` | Welcome email branded | Calls `getSiteLabel()`, uses `siteName` in subject and `welcomeHtml`. |
| `src/pages/api/user/forgot-password.ts` | Reset email branded | Calls `getSiteLabel()`, uses `siteName` in subject and `passwordResetHtml`. |
| `src/pages/api/user/send-verify-code.ts` | Verify-code email branded | Calls `getSiteLabel()`, uses `siteName` in subject and `verifyCodeHtml`. |
| `src/pages/api/admin/test-email.ts` | Test email branded | Calls `getSiteLabel()`, uses `siteName` in subject and `adminNotifyHtml`. |
| `src/pages/api/stamp/giveup-notify.ts` | Rewritten to use `stampVerifyTimeoutHtml` | Replaced raw Arial-only HTML builder with the new styled template function. Calls `getSiteLabel()`. |
| `src/pages/api/feedback.ts` | Feedback notification branded | Calls `getSiteLabel()`, passes `siteName` to `feedbackHtml`. |
| `src/pages/api/remind/submit.ts` | Subscription confirm email branded | Calls `getSiteLabel()`, passes `siteName` to `subscriptionConfirmHtml`. |
| `src/pages/api/remind/process.ts` | All reminder/phase/drop emails branded | Calls `getSiteLabel()` once per cron invocation; passes `siteName` to all 5 email builder calls (`reminderHtml`, `phaseEventHtml` ×3, `dropApproachingHtml`, `domainDroppedHtml`). |
| `src/pages/api/user/search-history.ts` | High-value domain alert branded | Calls `getSiteLabel()`, passes `siteName` to `highValueAlertHtml`. |

### v3.2 — UX Polish, Branding Consistency & Permission Flow Fixes (2026-03-23)

**Scope:** Session-wide settings caching, page transition stabilization, consistent site branding across all sub-pages, and corrected auth/permission flows in the dashboard and query pages.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/site-settings.tsx` | Added `sessionStorage` cache for site settings | Reads cached settings as initial state on first render, eliminating the title flash caused by `DEFAULT_SETTINGS` showing before the API responds. Cache is written/updated on every successful API fetch. |
| `src/pages/_app.tsx` | Fixed `AnimatePresence` key for client-search pages | Pages in `CLIENT_SEARCH_PAGES` (`/dns`, `/ip`, `/ssl`, `/icp`, `/tools`, `/feedback`) now use `router.pathname` as the animation key instead of `router.asPath`, preventing jarring exit/re-enter transitions when query params change. |
| `src/pages/dns.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | `DNS 查询 — NEXT WHOIS` now uses `settings.site_logo_text` dynamically. |
| `src/pages/ssl.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | `SSL 证书查询 — NEXT WHOIS` now uses `settings.site_logo_text` dynamically. |
| `src/pages/ip.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | `IP / ASN 查询 — NEXT WHOIS` now uses `settings.site_logo_text` dynamically. |
| `src/pages/tools.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | Tools page title now uses `settings.site_logo_text` dynamically. |
| `src/pages/icp.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | ICP page title now uses `settings.site_logo_text` dynamically. |
| `src/pages/docs.tsx` | Added `useSiteSettings` hook; fixed hardcoded title + og/twitter meta | All 3 title occurrences (title, og:title, twitter:title) now use `settings.site_logo_text` dynamically. |
| `src/pages/feedback.tsx` | Fixed hardcoded title | Was already importing `useSiteSettings`; title now uses `settings.site_logo_text`. |
| `src/pages/dashboard.tsx` | Default tab changed to `stamps`; adds smart switch to `subscriptions` when user has `subscriptionAccess` | Users without subscription access now land on the Stamps tab first. Users with access auto-switch to Subscriptions tab after session loads. |
| `src/pages/dashboard.tsx` line 447 | `SubscribeGuideModal` redirect changed from `/remind` to `/stamp` | The "查看订阅管理页" button now correctly sends users to the brand-claim page (`/stamp`), not the subscription reminder page. Label updated to "前往品牌认领页". |
| `src/pages/[...query].tsx` | No-access subscribe toast now includes actionable `/stamp` redirect | Both subscribe button instances now show a toast with an "Apply / 前往申请" action button linking to `/stamp` when user lacks `subscriptionAccess`, instead of a dead-end info message. |

### v3.1 — Enom TLD Reference Chart Full Integration (2026-03-23)

**Scope:** Complete second pass of `src/lib/lifecycle.ts` corrections using the authoritative Enom TLD Reference Chart (2026-03, 922 lines). All grace/redemption/pendingDelete values for supported TLDs corrected to match Enom registrar data. New TLD entries added.

**Source:** Enom TLD Reference Chart 2026-03 (PDF, 922 lines) — authoritative for gTLDs, nTLDs, and ccTLDs where Enom offers registration.

**Comment block updates (LIFECYCLE_TABLE header):**

| TLD | Before | After | Source |
|---|---|---|---|
| `.be` note | grace 0-20d, RGP=40d | no grace, RGP=30d, 3d pre-expiry deletion | Enom 2026-03 |
| `.ch/.li` note | grace=5d, RGP=40d | no grace, RGP=14d, 10d pre-expiry | Enom 2026-03 |
| `.eu` note | no grace, RGP=40d | no grace, RGP=30d, 3d pre-expiry | Enom 2026-03 |
| `.nl` note | no grace, RGP=40d | no grace, RGP=30d, 3d pre-expiry | Enom 2026-03 |
| `.es` note | RGP=10d | RGP=14d, 12d pre-expiry | Enom 2026-03 |
| `.nz` note | grace=40d, RGP=90d | no grace, RGP=90d, 3d pre-expiry | Enom 2026-03 |
| `.au` note | grace=30d, no RGP | no grace, RGP=31d, 10d pre-expiry | Enom 2026-03 |

**Europe ccTLD corrections:**

| TLD | grace Before→After | rdmp Before→After | Source |
|---|---|---|---|
| `.de` | 10→**0** | 30→30 | Enom 2026-03: N/30 |
| `.nl` | 0→0 | 40→**30** | Enom 2026-03: N/30 |
| `.eu` | 0→0 | 40→**30** | Enom 2026-03: N/30 |
| `.es` | 0→0 | 10→**14** | Enom 2026-03: N/14 |
| `.be` | 10→**0** | 40→**30** | Enom 2026-03: N/30 |
| `.ch` | 5→**0** | 40→**14** | Enom 2026-03: N/14 |
| `.li` | 5→**0** | 40→**14** | Enom 2026-03: N/14 |
| `.am` | grace=30, rdmp=30 | **IMMEDIATE** | Enom 2026-03: N/N |

**Asia-Pacific ccTLD corrections:**

| TLD | grace Before→After | rdmp Before→After | Source |
|---|---|---|---|
| `.sg` | 30→**0** | 30→**14** | Enom 2026-03: N/14 |
| `com/net/org/edu.sg` | 30→**0** | 30→**14** | Enom 2026-03: N/14 |
| `.nz` | 40→**0** | 90→90 | Enom 2026-03: N/90 |
| `co/net/org/school.nz` | 40→**0** | 90→90 | Enom 2026-03: N/90 |
| `.in` | 40→**30** | 30→30 | Enom 2026-03: 30/30 |
| `co/net/org.in` | 40→**30** | 30→30 | Enom 2026-03: 30/30 |
| `.au` (bare TLD) | 30→**0** | 0→**31** | Enom 2026-03: N/31 |
| `.mu` | 30→**40** | 0→**30** | Enom 2026-03: 40/30 |
| `.tm` | grace=30, rdmp=0 | **IMMEDIATE** | Enom 2026-03: N/N |

**Americas ccTLD corrections:**

| TLD | grace Before→After | rdmp Before→After | Source |
|---|---|---|---|
| `.ca` | 40→**30** | 30→30 | Enom 2026-03: 30/30 |
| `.pe` | 30→**0** | 30→**10** | Enom 2026-03: N/10 |
| `com.pe` | 30→**0** | 30→**10** | Enom 2026-03: N/10 |
| `com.mx` | 30→**40** | 30→**0** | Enom 2026-03: 40/N |
| `.hn` | rdmp 0→**30** | — | Enom 2026-03: 30/30 |

**Batch 1 corrections (applied earlier in v3.1):**

| TLD | Change | Source |
|---|---|---|
| `.io` | grace 30→**32** | Enom 2026-03 |
| `.ai` | grace 30→**45** | Enom 2026-03 |
| `.la` | grace 28→**30** | Enom 2026-03 |
| `.tv` | grace 30→**42** | Enom 2026-03 |
| `.ac` / `.sh` | grace 30→**32** | Enom 2026-03 |
| `.vg` | grace 30→**32**, rdmp 30→30 | Enom 2026-03 |
| `.tc` | grace 30→**32**, rdmp 0→**30** | Enom 2026-03 |
| `.sc` / `.mn` / `.fm` / `.ms` / `.gs` / `.tk` / `.bz` | **IMMEDIATE** | Enom 2026-03 |
| `.de` | grace 10→**0** | Enom 2026-03 |
| `.nl` | rdmp 40→**30** | Enom 2026-03 |
| `.eu` | rdmp 40→**30** | Enom 2026-03 |
| `.es` | rdmp 10→**14** | Enom 2026-03 |

**New entries added:**

| TLD | Data | Registry |
|---|---|---|
| `.eus` | grace=45, rdmp=30, pd=5 | PUNTUEUS (Basque Country) |
| `.free` / `.fast` / `.hot` / `.spot` / `.talk` / `.you` | grace=40, rdmp=30, pd=5 | Amazon Registry Services |
| `com/net/org.mu` | grace=40, rdmp=30, pd=5 | ICTA (Mauritius) |

**Other changes:**
- `.inc`: grace corrected 30→42 (Enom 2026-03: 42/30)
- Duplicate `.tc` entry (line 676, old est-confidence entry) removed

---

### v3.0 — TLD Lifecycle Data Accuracy Overhaul (2026-03-23)

**Scope:** Major accuracy corrections to `src/lib/lifecycle.ts` based on cross-referencing Namecheap KB (updated 2025-09-10) and Dynadot TLD pages (verified 2026-03) against the Enom TLD Reference Chart.

**Sources:**
- Namecheap KB: https://www.namecheap.com/support/knowledgebase/article.aspx/9916/2207/tlds-grace-periods
- Dynadot TLD pages: https://www.dynadot.com/domain/[tld]
- Enom TLD Reference Chart: https://docs.google.com/spreadsheets/d/1oVNszsvqhxh3hlT1LYMfcwq3lw_e6J7DeBePvN4t2aw

**Named preset updates:**

| Preset | Before | After | Reason |
|---|---|---|---|
| `STD` (default gTLD) | grace=45, rdmp=30, pd=5 | grace=**30**, rdmp=30, pd=5 | Dynadot: 30d in practice, not 45d max |
| `AFNIC` (.fr etc.) | grace=0, rdmp=30, pd=**10** | grace=0, rdmp=30, pd=**5** | Dynadot verified: .pm/.wf delete=5 |
| `NOMINET` (.uk etc.) | grace=**92**, rdmp=0, pd=**0** | grace=**90**, rdmp=0, pd=**5** | Dynadot: grace=85/5; Namecheap: 90d total |
| `CNNIC` (.cn etc.) | grace=0, rdmp=**14**, pd=5 | grace=0, rdmp=**15**, pd=5 | Dynadot restore=15d |
| `HKIRC` (.hk etc.) | grace=**90**, rdmp=**0**, pd=0 | grace=**30**, rdmp=**60**, pd=0 | Dynadot: grace=30, restore=60 |

**Major TLD corrections:**

| TLD | Before | After | Source |
|---|---|---|---|
| `.de` | IMMEDIATE (0/0/0) | grace=10, rdmp=30, pd=25 | Dynadot: variable grace 0-20d; NOT immediate |
| `.it` | IMMEDIATE | grace=10, rdmp=30, pd=0 | Dynadot: grace=10, restore=30 |
| `.pl` | IMMEDIATE | grace=0, rdmp=30, pd=0 | Dynadot: restore=30 |
| `.no` | IMMEDIATE | grace=89, rdmp=0, pd=0 | Dynadot: 89-day grace |
| `.ie` | IMMEDIATE | grace=30, rdmp=30, pd=14 | Dynadot: grace=30, restore=30, delete=14 |
| `.be` | IMMEDIATE | grace=10, rdmp=40, pd=0 | Dynadot: variable 0-20d grace, restore=40 |
| `.cl` | IMMEDIATE | grace=10, rdmp=30, pd=10 | Dynadot: grace=10, restore=30, delete=10 |
| `.es` | IMMEDIATE | grace=0, rdmp=10, pd=0 | Namecheap: 10-day RGP only, no pendingDelete |
| `.eu` | grace=40, rdmp=0 | grace=0, rdmp=40, pd=0 | Dynadot: no grace, restore=40 |
| `.nl` | grace=40, rdmp=0 | grace=0, rdmp=40, pd=0 | Dynadot: no grace, restore=40 |
| `.ch` | grace=30, rdmp=0, pd=5 | grace=5, rdmp=40, pd=0 | Dynadot: grace=5, restore=40 |
| `.li` | grace=30, rdmp=0, pd=5 | grace=5, rdmp=40, pd=0 | Dynadot: grace=5, restore=40 |
| `.pt` | grace=30, rdmp=0 | grace=29, rdmp=0 | Dynadot: grace=29 |
| `.cz` | grace=30, rdmp=0 | grace=59, rdmp=0 | Dynadot: grace=59 |
| `.ro` | grace=30, rdmp=0 | grace=80, rdmp=0 | Dynadot: grace=80 |
| `.lt` | grace=30, rdmp=30, pd=5 | grace=0, rdmp=30, pd=0 | Dynadot: no grace, restore=30 |
| `.lv` | grace=30, rdmp=30, pd=5 | grace=0, rdmp=30, pd=0 | Dynadot: no grace, restore=30 |
| `.tw` | grace=0, rdmp=30, pd=5 | grace=32, rdmp=0, pd=10 | Dynadot: grace=32, delete=10, no restore |
| `.nz` | IMMEDIATE | grace=40, rdmp=90, pd=5 | Dynadot: grace=40, restore=90 |
| `.hk` | HKIRC (grace=90) | HKIRC (grace=30, rdmp=60) | Preset updated |
| `.in` | grace=30, rdmp=30 | grace=40, rdmp=30 | Dynadot: grace=40 |
| `.id` | grace=30, rdmp=30 | grace=40, rdmp=30 | Dynadot: grace=40 |
| `.ph` | grace=30, rdmp=0, pd=5 | grace=50, rdmp=0, pd=0 | Dynadot: grace=50, delete=0 |
| `.ae` | grace=30, rdmp=30, pd=5 | grace=20, rdmp=0, pd=0 | Dynadot: grace=20, no restore |
| `.cm` | grace=30, rdmp=0, pd=0 | IMMEDIATE | Namecheap: expires = deleted same day |
| `.nu` | grace=45, rdmp=30, pd=5 | grace=7, rdmp=60, pd=0 | Namecheap: 7d then 60d RGP |
| `.gg` | grace=45, rdmp=30, pd=5 | grace=28, rdmp=12, pd=0 | Dynadot: grace=28, restore=12 |
| `.la` | grace=45, rdmp=30, pd=5 | grace=28, rdmp=30, pd=0 | Dynadot: grace=28, no delete |
| `.to` | grace=45, rdmp=30, pd=5 | grace=40, rdmp=30, pd=5 | Dynadot: grace=40 |
| `.fm` | grace=45, rdmp=30, pd=5 | grace=30, rdmp=30, pd=4 | Dynadot: delete=4 |
| `.vg` | grace=45, rdmp=30, pd=5 | grace=30, rdmp=30, pd=4 | Dynadot: delete=4 |
| (all 45d island TLDs) | grace=45 | grace=30 | Dynadot shows 30d for all VeriSign-managed |

**SLD corrections:**
- `.co.nz` / `.net.nz` / `.org.nz` / `.school.nz`: IMMEDIATE → grace=40, rdmp=90, pd=5
- `.com.hk` and all `*.hk`: auto-updated via HKIRC preset
- `.com.ph` / `.net.ph` / `.org.ph`: grace=30/pd=5 → grace=50/pd=0
- `co.in` / `net.in` / `org.in`: grace=30 → grace=40 (matching .in TLD)

---

### v2.9 — Comprehensive TLD Lifecycle Rules Expansion (2026-03-23)

**Scope:** `src/lib/lifecycle.ts` completely rewritten. Table grew from ~150 entries to **634 total entries** (547 TLD-level + 87 SLD-level), covering the vast majority of the global domain namespace.

**Sources consulted:**
- ICANN RAA (standard gTLD: 45d grace / 30d RGP / 5d pendingDelete)
- Namecheap KB: https://www.namecheap.com/support/knowledgebase/article.aspx/9916/2207/tlds-grace-periods
- Dynadot TLD pages: https://www.dynadot.com/domain/tlds.html
- Individual registry policy pages (CNNIC, HKIRC, Nominet, AFNIC, DENIC, auDA, etc.)
- IANA root-zone database

**Accuracy corrections:**

| TLD | Before | After | Source |
|---|---|---|---|
| `.cn` | grace=0, redemption=30, pendingDelete=5 | grace=0, **redemption=14**, pendingDelete=5 | Namecheap KB / CNNIC registry-level RGP |
| `.hk` | grace=0, redemption=30, pendingDelete=5 | grace=**90**, redemption=**0**, pendingDelete=**0** | HKIRC policy (90-day renewal window, no separate RGP) |
| `.ph` | grace=30, redemption=30, pendingDelete=5 | grace=30, redemption=**0**, pendingDelete=5 | PH Domains Foundation — no redemption period |
| `.ly` | grace=30, redemption=0, pendingDelete=0 | **IMMEDIATE** (0/0/0) | LYNIC policy |
| `.au` | grace=0, redemption=0, pendingDelete=5 | grace=**30**, redemption=0, pendingDelete=5 | auDA new top-level TLD (launched 2022) |
| `com.hk` | grace=0, redemption=30, pendingDelete=5 | **HKIRC** (90/0/0) | HKIRC — consistent with .hk |

**New named presets (reusable policy families):**
- `CNNIC` — `.cn` and all `*.cn` sub-TLDs: `{ grace: 0, redemption: 14, pendingDelete: 5 }`
- `HKIRC` — `.hk` and all `*.hk` sub-TLDs: `{ grace: 90, redemption: 0, pendingDelete: 0 }`
- `NOMINET` — `.uk` and all `*.uk` sub-TLDs: `{ grace: 92, redemption: 0, pendingDelete: 0 }`
- `JPRS` — `.jp` and all `*.jp` sub-TLDs: immediate delete `{ grace: 0, redemption: 0, pendingDelete: 0 }`
- `REGISTROBR` — `.br` and all `*.br` sub-TLDs: immediate delete
- `NICAR` — `.ar` and all `*.ar` sub-TLDs: immediate delete

**New TLD categories added:**

1. **Popular new gTLDs (~60)**: `xyz`, `club`, `fun`, `icu`, `top`, `vip`, `wiki`, `ink`, `buzz`, `website`, `uno`, `bio`, `ski`, `ltd`, `llc`, `srl`, `gmbh`, `inc`, `bar`, `fit`, `fan`, `bet`, `best`, `cash`
2. **Business/professional new gTLDs (~150)**: `academy`, `accountant`, `auction`, `bargains`, `bike`, `boutique`, `cafe`, `camera`, `careers`, `casino`, `chat`, `clinic`, `coach`, `codes`, `coffee`, `community`, `condos`, `construction`, `consulting`, `coupons`, `dance`, `dating`, `dental`, `diamonds`, `doctor`, `energy`, `engineering`, `estate`, `financial`, `fitness`, `flights`, `furniture`, `games`, `glass`, `golf`, `graphics`, `guru`, `healthcare`, `hockey`, `homes`, `industries`, `insure`, `investments`, `kitchen`, `legal`, `lighting`, `limited`, `limo`, `loans`, `management`, `marketing`, `mba`, `memorial`, `mortgage`, `movie`, `ninja`, `partners`, `pet`, `photography`, `pizza`, `plumbing`, `productions`, `properties`, `pub`, `racing`, `realty`, `recipes`, `rehab`, `rentals`, `repair`, `restaurant`, `rocks`, `rugby`, `school`, `security`, `sexy`, `shoes`, `singles`, `solar`, `surgery`, `tax`, `taxi`, `technology`, `tennis`, `tips`, `today`, `tours`, `town`, `toys`, `trade`, `training`, `university`, `vacations`, `ventures`, `villas`, `vision`, `voyage`, `wine`, `works`, `wtf`, `zone` (all STD 45/30/5)
3. **Geographic / city new gTLDs (~30)**: `amsterdam`, `barcelona`, `berlin`, `brussels`, `capetown`, `cologne`, `dubai`, `istanbul`, `london`, `miami`, `nagoya`, `nyc`, `okinawa`, `osaka`, `paris`, `quebec`, `rio`, `ryukyu`, `saarland`, `tirol`, `tokyo`, `vegas`, `wien`, `yokohama`, `zuerich`, `boston`, `wales`, `scot`, `irish`, `africa`, `arab`, `nrw` (all STD)
4. **Pacific ccTLDs**: `tl` (Timor-Leste), `fj`, `pg`, `sb`, `vu`, `ki`, `nr`, `ck`, `as`, `pf`, `nc`, `gp`, `mq`
5. **African ccTLDs (~25)**: `mz`, `zw`, `zm`, `ao`, `bi`, `bj`, `bf`, `td`, `cg`, `cd`, `gq`, `gw`, `mr`, `ne`, `tg`, `bw`, `na`, `ls`, `sz`, `mw`, `mg`, `mu`, `km`, `so`, `dj`, `er`, `st`, `cv`, `gn`, `sl`, `lr`
6. **European ccTLDs**: `fo` (Faroe), `mc` (Monaco), `sm` (San Marino), `ad` (Andorra), `gi` (Gibraltar), `im` (Isle of Man), `xk` (Kosovo)
7. **Caribbean/Americas ccTLDs**: `gd`, `dm`, `bb`, `ky`, `bm`, `bs`, `tc`, `kn`, `fk`, `sr`, `aw`, `cw`, `sx`
8. **AFNIC extensions**: `pf`, `nc`, `gp`, `mq` (all managed by AFNIC, same policy as `.fr`)

**New SLD entries (87 total):**

| Country | New SLDs |
|---|---|
| Australia (auDA) | `id.au`, `asn.au`, `edu.au`, `gov.au` (existing `com/net/org.au` kept at 30/30/5) |
| Taiwan (TWNIC) | `com.tw`, `net.tw`, `org.tw`, `idv.tw`, `edu.tw`, `gov.tw` |
| Hong Kong (HKIRC) | `net.hk`, `org.hk`, `idv.hk`, `edu.hk`, `gov.hk` (all 90/0/0) |
| New Zealand (InternetNZ) | `net.nz`, `org.nz`, `school.nz`, `govt.nz` (all IMMEDIATE) |
| Japan (JPRS) | `gr.jp`, `ac.jp`, `go.jp` (all IMMEDIATE) |
| Korea (KISA) | `or.kr` |
| Singapore (SGNIC) | `net.sg`, `org.sg`, `edu.sg`, `gov.sg` |
| Malaysia (MYNIC) | `net.my`, `org.my`, `edu.my` |
| Philippines (PH Domains) | `net.ph`, `org.ph` (no redemption) |
| India (NIXI) | `co.in`, `net.in`, `org.in` |
| Israel (ISOC-IL) | `org.il`, `net.il` |
| South Africa (ZADNA) | `org.za`, `net.za`, `web.za` (all IMMEDIATE) |
| Kenya (KENIC) | `or.ke`, `ne.ke` |
| Nigeria (NIRA) | `org.ng`, `net.ng` |
| Brazil (Registro.br) | `edu.br`, `gov.br` (all IMMEDIATE) |
| Mexico (NIC México) | `org.mx`, `net.mx` |
| Argentina (NIC Argentina) | `net.ar`, `org.ar` (all IMMEDIATE) |
| Ukraine | `com.ua` |
| Turkey (NIC TR) | `org.tr`, `net.tr` (all IMMEDIATE) |
| Venezuela | `com.ve` |
| Colombia | `com.co` |
| Peru | `com.pe` |

---

### v2.8 — CN Reserved Second-Level Domain Detection (2026-03-23)

**Problem:** CNNIC reserves 43 second-level domain labels under `.cn` for official use — 34 provincial administrative codes (bj.cn, sh.cn…), 7 functional suffixes (gov.cn, edu.cn…), and 2 system domains (nic.cn, cnnic.cn). Previously, these were either showing as "已注册" (incorrect) or as a misleading "该域名已注册但注册机构未提供公开的WHOIS/RDAP服务" fallback. The WHOIS lookup took 2.4s+ and returned no useful information.

**New file: `src/lib/whois/cn-reserved-sld.ts`**

Comprehensive database of all 43 reserved CN SLDs with bilingual descriptions, organized into three maps:

| Category | Count | Example |
|---|---|---|
| `CN_PROVINCE_SLDS` — 34 provincial codes | 34 | `bj` → 北京市, `gd` → 广东省 |
| `CN_FUNCTIONAL_SLDS` — sector suffixes | 7 | `gov` → 政府机构, `edu` → 教育机构 |
| `CN_SYSTEM_RESERVED` — exact domains | 2 | `nic.cn`, `cnnic.cn` |

`getCnReservedSldInfo(domain)` checks these in priority order and returns a typed `CnReservedInfo` object (or `null` for non-reserved domains).

**Three-layer interception — in priority order:**

1. **`getServerSideProps` pre-check** (`src/pages/[...query].tsx` line ~1315) — intercepts the raw URL query BEFORE `cleanDomain()` runs. Critical because the lib's `specialDomains` map rewrites functional SLDs (e.g. `gov.cn → www.gov.cn`) to make WHOIS lookups work — without this early check, SSR would look up `www.gov.cn` (a real registered domain) instead of showing "保留域名".

2. **`lookupWhoisWithCache` pre-check** (`src/lib/whois/lookup.ts` line ~504) — the first thing called in the function, before any L1/L2 cache lookup. Ensures no stale Redis-cached result for these domains ever overrides the correct synthetic result.

3. **`/api/lookup` pre-check** (`src/pages/api/lookup.ts` line ~115) — catches client-side searches (typed into the search bar after page load) that hit the API directly.

**Synthetic result format:**

All three interception points return the same structure:
```typescript
{
  time: 0, status: true, cached: false, source: "whois",
  result: {
    domain: "gov.cn",
    status: [{ status: "registry-reserved", url: "" }],
    rawWhoisContent: "[CN Reserved] GOV.CN 是 CNNIC 保留的功能性二级域名...",
    // all other fields: Unknown / null (from initialWhoisAnalyzeResult)
  }
}
```

**UI updates:**

- `DomainStatusInfoCard` now accepts `customDesc?: { zh: string; en: string }` to override the generic "保留域名" description with the domain-specific CNNIC explanation (e.g. "BJ.CN 是 CNNIC 为北京市保留的省级行政区划域名（共34个）...")
- The call site passes `cnInfo` to the card when `regStatus.type === "reserved"`
- Cache header for CN reserved responses: `s-maxage=86400, stale-while-revalidate=604800` (24h/7d)

**Verified results:**

| Domain | Before | After |
|---|---|---|
| `bj.cn` (Beijing province) | ● 已注册 + "no WHOIS" fallback, 2.4s | ● 保留域名 + "BJ.CN 是 CNNIC 为北京市保留…" **0ms** |
| `sh.cn` (Shanghai) | ● 已注册 + "no WHOIS" fallback | ● 保留域名 + specific description **0ms** |
| `gov.cn` (Government) | ● 正常 (showing www.gov.cn data!) | ● 保留域名 + "GOV.CN 是 CNNIC 保留的功能性二级域名…" **0ms** |
| `edu.cn` (Education) | ● 正常 (showing www.edu.cn data!) | ● 保留域名 + "EDU.CN 是 CNNIC 保留的功能性二级域名…" **0ms** |
| `nic.cn` (CNNIC system) | ● 已注册 + "no WHOIS" fallback | ● 保留域名 + "nic.cn 为 CNNIC 系统保留域名…" **0ms** |
| `google.cn` (normal domain) | ● 正常 ✓ | ● 正常 ✓ (no false positive) |

All 43 reserved SLDs now return the correct badge and description in **0ms** with no WHOIS/RDAP network query.

---

### v2.7 — Enhanced Domain Status Detection: Reserved / Prohibited / Suspended (2026-03-23)

**Problem:** Many ccTLD and gTLD registries express special domain states (reserved, prohibited, blocked, suspended) as free-form text in WHOIS responses rather than EPP status codes. The parser only understood structured `Domain Status:` fields, so domains like `com.tw` (WHOIS says "reserved name") were incorrectly shown as **已注册 (Registered)**.

**Two-layer fix:**

**1. `src/lib/whois/common_parser.ts` — Synthetic status injection**

After the normal EPP status deduplication pass, scans the raw WHOIS text for non-EPP state keywords and injects synthetic status entries:

| Pattern matched in raw text | Synthetic status injected | UI result |
|---|---|---|
| `reserved name`, `this name is reserved`, `domain is reserved`, `reserved by the registry`, standalone `reserved` line | `registry-reserved` | 保留域名 (amber) |
| `registration prohibited`, `cannot be registered`, `registration not available`, `not eligible for registration`, `prohibited string`, `registry banned`, `registration blocked` | `registrationProhibited` | 禁止注册 (red) |
| `suspended by registry/registrar`, `registry-suspended`, `domain is suspended` | `suspended` | 暂停 (orange) |

These patterns are conservative — specific enough to avoid false positives in WHOIS legal footer text (e.g. "all rights reserved" does NOT match "reserved name").

**2. `src/pages/[...query].tsx` — `getDomainRegistrationStatus` enhanced**

Added a raw content scan as a safety net, checking both `result.rawWhoisContent` and `result.rawRdapContent` (serialized to string) for the same patterns. This covers RDAP-sourced data where `common_parser.ts` doesn't run.

Also added `suspended` EPP code detection to the hold check: `hasSuspended = allStatusText.includes("suspended") || rawHasSuspended`.

**3. `src/lib/whois/epp_status.ts` — Two new entries**

- `registryreserved` → displayName `registry-reserved`, category `server`  
- `registrationprohibited` → displayName `registrationProhibited`, category `server`

These ensure the EPP status badge in the 状态 section shows correct Chinese/English descriptions instead of the generic "暂无标准释义" fallback.

**4. `src/pages/[...query].tsx` — EPP lock filter robustness fix**

Pre-existing bug: Some WHOIS servers (e.g. TWNIC for `.tw`) emit EPP lock statuses with **spaces** (`"client delete prohibited"`) rather than camelCase or hyphens. The original filter took only `s.split(/\s+/)[0]` ("client") which is not in the EPP lock set, letting the string pass through — and `prohibitCheckText.includes("prohibited")` was then true, incorrectly triggering the **禁止注册** badge for all Google-owned `.tw` domains.

**Fix:** The filter now checks the code against the lock set in TWO additional forms — the raw first-word AND the space/hyphen-stripped concatenated form:
```
"client delete prohibited"
  → noSep = "clientdeleteprohibited" → IN set → filtered ✓
"client-transfer-prohibited"  
  → noSep = "clienttransferprohibited" → IN set → filtered ✓
"clientUpdateProhibited" → toLowerCase → "clientupdateprohibited"
  → noSep = "clientupdateprohibited" → IN set → filtered ✓
```

**Verified results:**

| Domain | Before | After |
|---|---|---|
| `com.tw` | ● 已注册 (WRONG — WHOIS says "reserved name") | ● 保留域名 ✓ |
| `google.tw` | ● 禁止注册 (WRONG — only has EPP lock codes) | ● 正常 ✓ |
| `google.com` | ● 已注册 ✓ | ● 已注册 ✓ (no false positive) |

---

### v2.6 — RDAP-First Optimization: Massive Speed Improvement for 30+ ccTLDs (2026-03-23)

**Root cause identified and fixed:** `STATIC_NO_RDAP` in `src/lib/whois/tld-rdap-skip.ts` was incorrectly listing ~40 ccTLDs that actually have public RDAP endpoints (either via the IANA RDAP bootstrap or via `CCTLD_RDAP_OVERRIDES`). This forced all of them through the slower WHOIS path (2–6s) instead of the fast RDAP path (1–2s).

**1. `src/lib/whois/tld-rdap-skip.ts` — STATIC_NO_RDAP reduced from ~40 → 19 TLDs**

Previously listed as "no RDAP" (incorrectly — all have working RDAP):
- European ccTLDs: `.de`, `.it`, `.pl`, `.hu`, `.ro`, `.bg`, `.gr`, `.sk`, `.no`, `.fi`, `.lt`, `.lv`, `.ua`
- East/SE Asia: `.jp`, `.kr`, `.tw`, `.hk`, `.vn`, `.th`, `.sg`, `.my`, `.id`, `.ph`, `.in`
- ccTLDs with RDAP overrides: `.mm`, `.kh`, `.la`, `.np`, `.ke`, `.gh`, `.tz`, `.ug`, `.et`, `.sn`, `.iq`, `.ly`, `.tr`, `.ae`, `.il`, `.pe`, `.ph`, `.uy`
- Latin America: `.mx`, `.ar`, `.co`, `.cl`, `.pe`, `.za`

Now STATIC_NO_RDAP contains **only genuinely RDAP-less TLDs** (19 total):
`cn, mo, ru, by, kz, ir, sa, lb, eg, ma, dz, tn, bd, lk, ve, ec, bo, py, tl`

**Self-healing safety net:** If a TLD is wrongly absent from the list and RDAP fails at runtime, `markRdapSkipped()` is called automatically — it adds the TLD to the DB-backed runtime skip set, so all future requests go straight to WHOIS. No manual correction needed.

**2. `src/lib/whois/lookup.ts` — Timeout adjustments**

| Constant | Before | After | Reason |
|---|---|---|---|
| `RDAP_TIMEOUT` | 4 000 ms | 3 000 ms | HTTP/JSON servers respond in ≤2 s on Vercel; 3 s is generous |
| `WHOIS_TIMEOUT` | 8 000 ms | 7 000 ms | Reduce max wait time; legitimate slow servers still get 7 s |

**3. `src/lib/whois/rdap_client.ts` — `tryRdapOverride` internal timeout**

`AbortSignal.timeout(12000)` → `AbortSignal.timeout(2500)`. The outer `withTimeout(RDAP_TIMEOUT=3000)` already caps the entire RDAP flow; the internal 12-second signal was redundant and left dangling fetch connections alive for 12 s after the outer timeout fired.

**4. `src/lib/env.ts` — `LOOKUP_TIMEOUT` default aligned**

`8_000` → `7_000` ms — keeps the internal whoiser TCP timeout consistent with the new `WHOIS_TIMEOUT` outer cap.

**Measured results on Vercel-equivalent network (parallel RDAP + WHOIS):**

| TLD | Before | After | Source |
|---|---|---|---|
| `.sg` | ~3–4s (WHOIS) | **1.85s** | RDAP ✓ |
| `.tw` | ~3–4s (WHOIS) | **1.68s** | RDAP ✓ |
| `.jp` | ~3–4s (WHOIS) | **1.07s** (cached) | RDAP ✓ |
| `.de` | ~4.5s (WHOIS) | same | RDAP restricted by DENIC GDPR → auto-marked as rdap_skip |
| `.cn` | ~5–6s (WHOIS) | same | Kept in STATIC_NO_RDAP (no public RDAP) |

---

### v2.5 — Local-First Architecture: Bug Fixes + After-Native Fallback (2026-03-23)

**Three fixes in `src/lib/whois/lookup.ts`:**

1. **Critical bug: `UnhandledPromiseRejection` crash on RDAP-skipped TLDs (`.cn`, `.bf`, `.lu`, `.ye`, etc.)**
   - **Root cause:** `rdapPromise = Promise.reject(...)` when `skipRdap=true`, but no `.catch()` was ever attached. Node.js 15+ crashes the process on any unhandled rejection.
   - **Fix:** Changed to `Promise.resolve(null)` — safe because `rdapPromise` is excluded from `taggedRacers` and never read when `skipRdap=true`.

2. **Architecture overhaul: True "local-first" — third-party only fires after native fails**
   - **Old (broken) behavior:** A 3-second timer would fire `lookupTianhu()`/`lookupYisi()` even while WHOIS was still running (WHOIS timeout = 6s). If WHOIS takes 3–5s (common for legitimate WHOIS servers), third-party would race against it and win. Then `forceTldFallback()` would be called, permanently opening the early gate for that TLD — creating a feedback loop where the system increasingly bypassed native WHOIS in favour of third-party.
   - **New behavior:** `progressiveFallbackRacer` now uses `await Promise.allSettled([rdapPromise, whoisPromise])` — waits for ALL native lookups to genuinely settle (succeed, fail, or timeout) before calling `lookupTianhu()`/`lookupYisi()`. Third-party is truly a last resort.
   - **Bonus:** For TLDs with no WHOIS server, `getLookupWhois` rejects almost instantly ("No WHOIS server responded") so the fallback fires immediately without waiting — actually faster than the old 3s timer for quickly-failing TLDs.
   - **`nativeWon` flag:** Set to `true` when `firstNonNull()` resolves with a native result. The progressive async function checks this after `allSettled` and skips third-party calls if native already won.
   - **`forceTldFallback` preserved:** Still called when progressive wins, since with the new architecture this truly means native completely failed — justified to open the early gate for next time.

3. **WHOIS timeout increased: 6000ms → 8000ms**
   - Many legitimate WHOIS servers (especially for ccTLDs) need 5-7s to respond. Increasing the cap reduces false timeouts and unnecessary fallback gate triggers. RDAP timeout unchanged at 4000ms (HTTP/JSON is faster).

**Architecture summary:**
- `lookupTianhu`: only if `tianhu_enabled=true` in admin config (25/min, 300/day)
- `lookupYisi`: only if `yisi_enabled=true AND yisi_key` set in admin config
- Progressive path: after native settles (not on a timer)
- Early gate: after ≥3 recorded native failures for a TLD (`tld_fallback_stats` table)

---

### v2.4 — Premium Domain Pricing: Accurate API-Based Detection (2026-03-23)

**Two distinct concepts now properly separated:**
- `isPremium` (on pricing) = registry/API confirmed premium-priced TLD (price > $100 USD/EUR/CAD, OR `currencytype === "premium"` from API response)
- `negotiable` = domain name has high resale value (from domain value scoring engine — independent of TLD pricing)

**Changes:**

1. **`src/lib/pricing/client.ts` — `calcIsPremium` improved:**
   - Now also checks `r.currencytype.toLowerCase().includes("premium")` — detects registry-marked premium pricing from the Nazhumi API response field before the price-threshold fallback
   - Ensures both server-side (`getDomainPricing`) and client-side (`getTopRegistrars`) correctly propagate API-reported premium status

2. **`src/pages/[...query].tsx` — `rawPrices` client mapping updated:**
   - Now checks `r.currencytype.toLowerCase().includes("premium")` in addition to price threshold
   - Removed incorrect `result.negotiable === true` conflation from rawPrices

3. **UI — Register/Renew price badges (desktop + mobile):**
   - Normal domains: grey `text-muted-foreground` (unchanged)
   - Registry-premium TLD (isPremium = true): **amber** `text-amber-500` with amber icon
   - Renew price badge now also respects `isPremium` for amber coloring (previously had no isPremium styling)

4. **DomainReminderDialog mini card:**
   - Colors updated: `text-red-500` → `text-amber-500` for consistency with main badge row
   - 溢价 cell background: `bg-red-500/8` → `bg-amber-500/8`
   - 溢价 value: `text-red-500` → `text-amber-500`

**Result:** `ai.dev` — shows grey $4.99 register / $11.62 renew (correct: `.dev` is not a premium-priced TLD), amber "Negotiable: Yes" (correct: high-value domain name). A domain like `.ai` with $100+ registration price would show all pricing in amber.

---

### v2.3 — Full 8-Locale i18n Coverage (2026-03-23)

**Added missing translation keys to all 6 remaining locales (de, ja, ko, ru, fr, zh-tw):**
- `"search"` top-level key added to all 6 locales (was only in en + zh)
- All new nav keys added: `nav_tagline`, `nav_version_menu`, `nav_search_history`, `nav_toolbox`, `nav_login`, `nav_api_docs` + `_desc`, `nav_tlds` + `_desc`, `nav_domain_lookup` + `_desc`, `nav_dns` + `_desc`, `nav_ssl` + `_desc`, `nav_ip` + `_desc`, `nav_icp` + `_desc`, `nav_about` + `_desc`, `nav_sponsor` + `_desc` — all in native language (de/ja/ko/ru/fr/zh-tw)
- Complete `"icp"` section added to all 6 locales (32 keys each) with fully native-language translations: German, Japanese, Korean, Russian, French, Traditional Chinese
- All 8 locales (en, zh, de, ja, ko, ru, fr, zh-tw) now have 100% key coverage for navbar, ICP page, and search functionality — no more English fallbacks for known new keys

**Key count per locale:** each grew from ~402 to ~470 lines (68+ new keys per file)

---

### v2.2 — i18n Complete (2026-03-23)

**Navbar i18n (HistoryDrawer, NavDrawer, UserButton, Navbar):**
- `HistoryDrawer`: DrawerTitle, trigger `aria-label`, status label map (registered/unregistered/reserved/error/unknown), and empty-state title + description all use `t()` — no hardcoded Chinese
- `NavDrawer`: Removed `label`/`labelEn`/`description` fields; replaced with `labelKey`/`descKey` (TranslationKey) referencing `nav_api_docs`, `nav_tlds`, `nav_domain_lookup`, `nav_dns`, `nav_ssl`, `nav_ip`, `nav_icp`, `nav_about`, `nav_sponsor` and their `_desc` variants; version subtitle uses `t("nav_version_menu", {version})`; footer uses `t("nav_tagline")`
- `UserButton`: `aria-label` uses `t("nav_login")`
- `Navbar`: toolbox `aria-label` uses `t("nav_toolbox")`

**ICP page i18n (`src/pages/icp.tsx`):**
- `ICP_TYPES` array: replaced `label` with `tabKey` (`"icp.tab_web"` etc.) — rendered with `t(typeItem.tabKey)`
- `CopyButton`: `title` uses `t("icp.copy")`
- `BlackListBadge`: uses `t("icp.threat_none")` and `t("icp.threat_level", {level})`
- `RecordCard`: all `InfoRow` labels use `t("icp.field_*")` keys; "限制接入" badge uses `t("icp.field_limit")`
- `Pagination`: counter uses `t("icp.results_count", {count})`; page indicator uses `t("icp.page_of", {current, total})`
- `ApiStatusBadge`: all status text uses `t("icp.offline")` / `t("icp.check_status")`
- `IcpPage`: `<title>`, header h1/subtitle, offline banner, type-selector blacklist hint, search placeholder, search button (`t("search")`), loading overlay, error/empty states, results summary badge — all translated
- Added `t` dependency to `handleSearch` useCallback; renamed local `t`/`type` vars to `tp` to avoid shadowing

**Locale additions:**
- `locales/en.json` + `locales/zh.json`: Added `"search"` key at top level (`"Search"` / `"查询"`)

---

## Recent Changes (v2.0 → v2.1)

- **Page transitions**: y-axis slide (y:8→0 enter, y:0→-4 exit) with custom cubic-bezier [0.22,1,0.36,1] at 0.22s for silky-smooth feel
- **Result card stagger**: Main grid uses `CARD_CONTAINER_VARIANTS` (staggerChildren:0.06s) — left and right columns animate in sequence with `CARD_ITEM_VARIANTS` (y:12→0, duration:0.32s)
- **NS row animations**: Each nameserver row is a `motion.div` with spring tap (scale:0.97) and hover nudge (x:2px)
- **Domain title animation**: `motion.h2` with spring tap (scale:0.97) on click-to-copy
- **Search button**: Spring tap (scale:0.9) via `motion.div` wrapper around submit button
- **Hydration fix**: `ResultSkeleton` replaced `Math.random()` widths with deterministic fixed array `[85,72,90,65,80,70]`
- **Glass panel polish**: Added `box-shadow` for depth; dark mode shadow uses black/30
- **CSS utilities added**: `animate-fade-in-up`, `animate-fade-in`, `animate-scale-in`, `stagger-1` through `stagger-5` delay classes
- **DNS tool** (`dns.tsx`): CAA record type added; AnimatePresence for all states; MX priority badges; SOA structured display; 4×DoH resolvers; preset shortcuts (基础解析/邮件安全/域名服务器/证书授权)
- **SSL tool** (`ssl.tsx`): ValidityBar progress component; AnimatePresence for all states; quick examples (google.com/github.com/cloudflare.com); refresh button
- **IP/ASN tool** (`ip.tsx`): AnimatePresence for all states; Yandex static map preview; IPv6 + ASN examples
- **Sponsor page** (`sponsor.tsx`): Full redesign — animated heart hero with floating hearts; Alipay/WeChat QR cards; PayPal button; BTC/ETH/USDT/OKX crypto addresses (CopyButton); "已完成赞助" post-payment form with AnimatePresence; bouncing emoji thank-you section
- **Sponsor submit API** (`/api/sponsors/submit.ts`): Public endpoint — inserts with `is_visible=false` for admin approval
- **Admin settings**: Added PayPal URL + 4 crypto address fields to sponsor section
- **DNS API** (`/api/dns/records.ts`): CAA (type 257) added to RECORD_TYPES, TYPE_NUM, and parseDoHData
- **Docs page** (`docs.tsx`): Three new API sections — `/api/dns/records`, `/api/ssl/cert`, `/api/ip/lookup`

## Tech Stack

- **Framework**: Next.js 14 (Pages Router)
- **Styling**: Tailwind CSS + Shadcn UI + Framer Motion
- **WHOIS**: whoiser library + node-rdap for RDAP queries
- **Caching**: ioredis (Redis)
- **i18n**: next-i18next (EN, ZH, DE, RU, JA, FR, KO)
- **Fonts**: Geist

## Build / Deployment

- **Config**: `next.config.js` (CommonJS, `require`/`module.exports`) — converted from `.mjs` to be compatible with Vercel's `sed`-based build command which patches `next.config.js`
- **TypeScript errors**: `typescript: { ignoreBuildErrors: true }` is pre-applied in the config, so Vercel's sed patch is a harmless no-op
- **Vercel build command**: `sed -i '...' next.config.js && node scripts/migrate.js && pnpm run build`

## Key Files

- `src/lib/whois/lookup.ts` — WHOIS/RDAP orchestration, caching, error detection
- `src/lib/whois/common_parser.ts` — Raw WHOIS text parser, field extraction, data cleaning
- `src/lib/whois/epp_status.ts` — EPP status code mapping with Chinese translations
- `src/lib/whois/rdap_client.ts` — RDAP query client
- `src/pages/api/lookup.ts` — API endpoint
- `src/pages/[...query].tsx` — Result display page
- `src/lib/lifecycle.ts` — Shared TLD lifecycle table (65+ gTLD/ccTLD); used by both frontend and backend for grace/redemption/pendingDelete period computation
- `src/pages/api/remind/submit.ts` — Subscription submission API
- `src/pages/api/remind/process.ts` — Cron processor that fires pre-expiry AND phase-event reminders
- `src/lib/email.ts` — All email templates (welcome, subscription confirm, pre-expiry reminder, phase event)
- `src/lib/admin-shared.ts` — Client-safe admin helpers: `ADMIN_EMAIL` constant and `isAdmin()` function (no Node.js imports)
- `src/lib/admin-server.ts` — Server-only admin helpers: `getAdminEmail()` (reads DB `site_settings.admin_email`, falls back to `ADMIN_EMAIL`), `isAdminEmail()` (async DB-checked comparison)
- `src/lib/admin.ts` — Server-only admin middleware: `requireAdmin()` for API route protection (uses `admin-server.ts` for dynamic email check)
- `src/lib/site-settings.tsx` — Site settings context: `SiteSettingsProvider`, `useSiteSettings()` hook, `DEFAULT_SETTINGS`
- `src/components/admin-layout.tsx` — Shared admin backend layout with sidebar navigation and auth guard
- `src/pages/admin/index.tsx` — Admin dashboard with real-time stats (users, stamps, reminders, searches)
- `src/pages/admin/settings.tsx` — Site settings editor (title, logo, subtitle, description, footer, icon, announcement)
- `src/pages/admin/users.tsx` — User management (search, list, delete)
- `src/pages/admin/stamps.tsx` — Stamp management (search, verify/unverify, delete)
- `src/pages/admin/reminders.tsx` — Reminder management (search, deactivate)
- `src/pages/api/admin/settings.ts` — GET (public) / PUT (admin-only) site settings
- `src/pages/api/admin/stats.ts` — Admin stats endpoint
- `src/pages/api/admin/users.ts` — Admin user management API
- `src/pages/api/admin/stamps.ts` — Admin stamp management API
- `src/pages/api/admin/reminders.ts` — Admin reminder management API
- `src/pages/api/admin/feedback.ts` — Admin feedback management API (GET list, DELETE)
- `src/pages/admin/feedback.tsx` — Feedback viewer: expandable cards with issue type badges, search, delete
- `src/pages/admin/sponsors.tsx` — Sponsor management: add/edit/delete records, visibility toggle, stats, payment QR settings
- `src/pages/api/admin/sponsors.ts` — Sponsor CRUD API (GET public with visible_only, POST/PUT/DELETE admin-only)
- `src/pages/sponsor.tsx` — Public sponsor page: payment QR codes, sponsor list, cumulative stats
- `src/lib/server/rate-limit.ts` — In-process sliding-window rate limiter: `rateLimit(key, limit, windowMs)` + `getClientIp(req)`

## Architecture

The lookup flow: API request → try RDAP → fallback to WHOIS → merge results → if still empty try yisi.yun fallback → cache in Redis → return to client.

### Lookup fallback chain

1. **RDAP** (`node-rdap` + bootstrap) — primary, returns structured JSON
2. **WHOIS** (`whoiser` + custom servers) — secondary, raw text parsed by `common_parser.ts`
3. **yisi.yun API** (`src/lib/whois/yisi-fallback.ts`) — tertiary; only invoked when both RDAP and WHOIS fail or return empty/error data for a domain query. Supports unusual TLDs with no public RDAP/WHOIS server. Zero overhead when native lookups succeed.

## Version History (current: 1.9)

- **v1.9** — Page smoothness: page transition 0.28 s → 0.22 s + ease-out-expo curve, `will-change` GPU hint, `prefers-reduced-motion` full support, smooth scroll, preconnect hints for exchange-rate API / IANA RDAP in `_document.tsx`
- **v1.8** — Lookup speed: WHOIS merge-wait 600 → 350 ms, progressive-fallback trigger 3 500 → 3 000 ms, whoiser eager warm-up at module init, TLD DB calls halved for 2-part domains (tld === tldSuffix deduplication)
- **v1.7** — API security: IP sliding-window rate limiting 40 req/min, GET-only method check, query length ≤ 300 chars, control-char rejection, standard X-RateLimit-* headers; four access-control toggles (disable_login / maintenance_mode / query_only_mode / hide_raw_whois) enforced in navbar + login + _app.tsx + query page

## Data Cleaning Enhancements (2026-03)

Enhanced `common_parser.ts` with:
- **HTML entity decoding**: Handles ccTLD WHOIS servers that return HTML entities in field values (e.g., `Activ&eacute;` → `Activé`)
- **Dot-pattern cleaning**: Strips leading dot sequences used by some ccTLD WHOIS servers as privacy redaction markers (e.g., `............value` → `value`)
- **Redacted value filtering**: Skips contact fields (email, phone, org, country) that are privacy-redacted (high dot ratio, REDACTED/WITHHELD keywords)
- **Universal field cleaning**: Applied to all parsed values via `cleanFieldValue()`

Enhanced `epp_status.ts` with:
- **Expanded status map**: 50+ status codes covering standard EPP + ccTLD-specific variants
- **Multi-language status support**: French (Activé, Enregistré, Supprimé, Expiré), German (registriert, aktiv, gesperrt, gelöscht), Spanish/Portuguese (registrado, activo, ativo), Dutch (actief, geregistreerd), Italian (registrato), Turkish (kaydedildi), etc.
- **Robust normalization**: Two-pass lookup — first tries with accented characters preserved, then falls back to ASCII-folded form
- **New categories**: Added `unknown` category for unregistered/available status codes
- **More EPP statuses**: quarantine, dispute, abuse, withheld, pendingPurge, verificationFailed, courtOrder, etc.

## Custom WHOIS Server Management (2026-03)

Added local WHOIS server management without touching rdap/whoiser libraries:

- **`src/lib/whois/custom-servers.ts`** — Extended server entry types:
  - `string` → TCP hostname (legacy, port 43)
  - `{ type: "tcp", host, port? }` → TCP with optional custom port
  - `{ type: "http", url, method?, body? }` → HTTP GET/POST with `{{domain}}` placeholder
- **`src/lib/whois/lookup.ts`** — Added:
  - `queryWhoisTcp()` — raw Node.js `net` TCP connection for non-43 ports
  - `queryWhoisHttp()` — fetch-based HTTP WHOIS query with URL template substitution
  - Updated `getLookupWhois()` to dispatch based on entry type
- **`src/pages/api/whois-servers.ts`** — GET/POST/DELETE API for managing custom servers (no auth required)
- **`src/pages/whois-servers.tsx`** — Full UI management page accessible via navbar "Servers" link
- **`src/data/custom-tld-servers.json`** — User-editable server map (persisted on disk)

Priority order: user custom servers → built-in servers → ccTLD servers → whoiser default discovery.

### ScraperEntry type (2026-03)

Added `{ type: "scraper", name, registryUrl }` entry type for TLDs that require multi-step HTTP scraping (e.g. CSRF tokens + cookies):
- **`src/lib/whois/http-scrapers/nic-ba.ts`** — Dedicated scraper for .ba (Bosnia) via nic.ba. Performs GET+POST form submission; fails gracefully when reCAPTCHA v2 blocks automated access.
- **`ScraperRequiredError`** — Custom error class in `lookup.ts` that carries `registryUrl` for propagation to the API response.
- **`WhoisResult.registryUrl`** — New optional field on `WhoisResult` type passed through to the API `Data` type.
- **Frontend** — Shows "Look up at Registry" button (with external-link icon) in both the "registered but no WHOIS" panel and the generic error fallback panel whenever `registryUrl` is present.
- **`.ba` fix** — Removed wrong `"ba": "whois.ripe.net"` mapping from `cctld-whois-servers.json` (set to `null`). Now .ba domains correctly show DNS-probe–based registration status + registry link.
- **Null filter** — `getAllCustomServers()` now filters out null values from cctld-whois-servers.json so BUILTIN_SERVERS entries can take precedence.

## Vercel / Edge Platform Deployment

The app is production-ready for Vercel and similar serverless platforms.

### Key configuration files:
- **`vercel.json`** — Function maxDuration per route (30s for lookup, 10s for others)
- **`.env.example`** — All required environment variables documented

### Environment variables for production:
| Variable | Required | Default | Description |
|---|---|---|---|
| `POSTGRES_URL` | **Yes** | — | Supabase/Neon PostgreSQL pooling URL |
| `POSTGRES_URL_NON_POOLING` | **Yes** | — | Direct connection for migrations |
| `NEXTAUTH_SECRET` | **Yes** | — | Random secret for JWT signing (`openssl rand -base64 32`) |
| `NEXTAUTH_URL` | **Yes** | — | Production URL e.g. `https://your-app.vercel.app` |
| `RESEND_API_KEY` | **Yes** | — | Resend API key for sending emails |
| `RESEND_FROM_EMAIL` | **Yes** | `noreply@x.rw` | Verified sender address on Resend |
| `NEXT_PUBLIC_BASE_URL` | Recommended | NEXTAUTH_URL | Base URL used in email links |
| `CRON_SECRET` | Recommended | — | Protects cron jobs; Vercel sends as `Authorization: Bearer` |
| `WHOIS_TIMEOUT_MS` | No | 4000 | WHOIS query timeout in ms (keep ≤ 7000 on Hobby plan) |
| `RDAP_TIMEOUT_MS` | No | 5000 | RDAP query timeout in ms |
| `FALLBACK_START_MS` | No | 1200 | ms delay before 3rd-party fallback starts racing native lookups |
| `NEXT_PUBLIC_MAX_WHOIS_FOLLOW` | No | 0 | WHOIS follow depth (0 = fastest) |
| `REDIS_URL` | No | — | Redis connection URL (optional caching) |
| `REDIS_CACHE_TTL` | No | 3600 | Result cache TTL in seconds |

See `.env.example` for complete reference with comments.

### Redis storage:
- Lookup results cached at key `whois:{query}` with TTL from `REDIS_CACHE_TTL`
- User-managed custom WHOIS servers stored at key `whois:user-servers` (no TTL — persistent)
- Without Redis, custom servers fall back to `src/data/custom-tld-servers.json` (local only)

### Vercel plan considerations:
- **Hobby plan (10s limit)**: Default `WHOIS_TIMEOUT_MS=4000` + `RDAP_TIMEOUT_MS=5000` keeps total request time well under 10s.
- **Pro plan (300s limit)**: Can safely increase `WHOIS_TIMEOUT_MS=7000` for maximum ccTLD WHOIS coverage.

## Brand Claim (品牌认领) & Domain Subscription (域名订阅)

### New Pages
- `src/pages/stamp.tsx` — Brand Claim page with DNS TXT ownership verification (3-step flow: form → verify → done)
- `src/pages/remind/cancel.tsx` — Subscription cancellation page (reads `?token=` param, calls cancel API)

### New API Routes
- `src/pages/api/stamp/submit.ts` — Submit a stamp claim; returns `txtRecord` and `txtValue` for DNS TXT verification
- `src/pages/api/stamp/check.ts` — Query verified stamps for a domain
- `src/pages/api/stamp/verify.ts` — DNS TXT + HTTP file verification (multi-resolver, DoH fallback, fuzzy match)
- `src/pages/api/vercel/add-domain.ts` — Register domain with Vercel project; returns `_vercel` TXT record for ownership proof
- `src/pages/api/vercel/check-domain.ts` — Poll Vercel verify endpoint; updates stamp as verified if DNS propagated
- `src/pages/api/remind/submit.ts` — Subscribe to domain expiry reminders
- `src/pages/api/remind/cancel.ts` — Cancel a subscription via cancel token (returns JSON)
- `src/pages/api/remind/process.ts` — Cron job: sends reminder emails via Resend, marks sent records

### Libraries
- `src/lib/supabase.ts` — Supabase JS client singleton (REST-based, works from any network)
- `src/lib/db.ts` — Retained for pg Pool schema definitions (TABLES array); pg Pool only used on Vercel where TCP is allowed
- `src/lib/rate-limit.ts` — In-memory IP rate limiter (5 req/min per IP, auto-cleanup)

### Database Architecture
All API routes use `@supabase/supabase-js` (HTTP/REST) via `src/lib/supabase.ts`.
This allows the app to connect to Supabase from **any network** (Replit dev, Vercel production) 
without requiring direct TCP access to PostgreSQL port 5432/6543.

Required Supabase tables — **created automatically by `scripts/migrate.js` on each Vercel build**:
- `users` — user accounts for auth
- `password_reset_tokens` — password reset tokens (60-min expiry, single-use)
- `stamps` — brand claiming records
- `reminders` — domain expiry reminder subscriptions (`phase_flags TEXT` column required — run migration below)
- `reminder_logs` — tracking which reminder thresholds have been sent
- `tool_clicks` — global aggregate click counts per tool URL
- `user_tool_clicks` — per-user click counts for personalized sorting
- `search_history` — per-user search history (last 50 queries)

### Environment Variables Required
| Variable | Required | Description |
|---|---|---|
| `SUPABASE_URL` | Yes | Supabase project URL (e.g. `https://xxxx.supabase.co`) |
| `SUPABASE_SERVICE_KEY` | Yes | Supabase service role key (from project Settings → API) |
| `NEXTAUTH_SECRET` | Yes | Random secret for NextAuth JWT signing |
| `RESEND_API_KEY` | Yes | Resend API key for sending reminder/reset emails |
| `RESEND_FROM_EMAIL` | No | Sender address for emails (defaults to `noreply@x.rw`) |
| `NEXT_PUBLIC_BASE_URL` | Yes | Public URL for cancel/reset links in emails |
| `CRON_SECRET` | Recommended | Secret token to protect `POST /api/remind/process` |
| `VERCEL_API_TOKEN` | Yes (Vercel verify) | Vercel API token for domain verification |
| `VERCEL_PROJECT_ID` | Yes (Vercel verify) | Vercel project ID (`prj_...`) |
| `POSTGRES_URL_NON_POOLING` | Vercel only | Direct Supabase connection for pg Pool migrations |

### Pending DB Migrations
Run in **Supabase Dashboard → SQL Editor**:
```sql
-- Add phase_flags column to reminders table (phase event notification preferences)
ALTER TABLE reminders ADD COLUMN IF NOT EXISTS phase_flags text DEFAULT NULL;
```
The column is optional — the code defaults all phase flags to `true` if the column is missing or null, so existing subscriptions are unaffected until users re-subscribe.

### Cron Setup
To trigger reminder emails automatically, set up a cron job (e.g. daily) to call:
```
GET /api/remind/process?secret=<CRON_SECRET>
```
Or with a header:
```
GET /api/remind/process
x-cron-secret: <CRON_SECRET>
```

## IDN / Chinese Domain Handling

- **WHOIS punycode conversion**: `getLookupWhois` converts non-ASCII domains (e.g., `亲爱的.中国`) to their punycode equivalents (e.g., `xn--7lq487f54c.xn--fiqs8s`) via `domainToASCII()` before querying the WHOIS server
- **DNS probe punycode**: `probeDomain` similarly converts IDN inputs to punycode before DNS lookups
- **"No matching record" = available**: When WHOIS returns a "no match / not found" type response (pattern set `WHOIS_NOT_REGISTERED_PATTERNS`), the code treats this as "domain available" rather than a lookup failure — skipping the DNS fallback probe (which gives false positives for TLDs with wildcard A records like `.中国`). Yisi.yun is still tried first; if it fails, the domain is returned with `dnsProbe.registrationStatus: "unregistered", confidence: "high"` so the AvailableDomainCard is shown correctly.

## Dev Server

Runs on port 5000 via `pnpm run dev` (next dev -p 5000 -H 0.0.0.0).

## Tian.hu (田虎) Integration

Free public API (25 req/min, 300 req/day), no auth required.

### Integrated Features

| Feature | Endpoint | Usage |
|---------|----------|-------|
| WHOIS fallback | `/whois/{domain}` | `src/lib/whois/tianhu-fallback.ts` (tried before yisi.yun) |
| Domain pricing | `/tlds/pricing/{tld}` | `src/lib/pricing/client.ts` (3rd source, merged) |
| Translation | `/translate/{stem}` | `src/pages/api/tianhu/translate.ts` → shown on result page |
| DNS records | `/dns/{domain}` | `src/pages/api/tianhu/dns.ts` → shown on result page |

### Result Page Display

**Translation strip** (`[...query].tsx`):  
- Fetched client-side via `useEffect` when domain changes
- Displayed horizontally between "time·source" row and dates section
- Shows: "含义 **{zh translation}** {pos tag} {meaning}" in violet
- Only shown when `dst !== null` (omits pure-numeric domains, IPs)

**DNS Records card** (`[...query].tsx`):
- Shown after the WHOIS Name Servers card
- Displays A, NS, MX, SOA, TXT, AAAA records with TTL
- Skeleton loading animation while fetching
- Records animate in staggered with opacity

### Anti-Flicker Improvements

- ResultSkeleton now wrapped in `AnimatePresence` with opacity 0→1/0 transitions (no abrupt switch)
- Main result cards use pure `opacity` animation (no scale → no "pop" effect)
- Async-loaded sections (translation, DNS) animate in smoothly without layout shift

## Database Schema (Full Table List)

All persistent state lives in PostgreSQL (`src/lib/db.ts`). Tables auto-created on startup via `runMigrations()`.

| Table | Purpose |
|-------|---------|
| `users` | Registered accounts — email, password_hash, disabled, avatar_color, email_verified, etc. |
| `password_reset_tokens` | Secure time-limited reset links |
| `stamps` | Domain brand claims, awaiting admin verification |
| `reminders` | Domain expiry alert subscriptions |
| `reminder_logs` | Tracks which reminder phases have been sent (dedup) |
| `tool_clicks` | Aggregate link-click counts for Tools/Links pages |
| `user_tool_clicks` | Per-user link-click history |
| `search_history` | All queries (user_id nullable — anonymous queries also recorded) |
| `feedback` | User-submitted issue reports |
| `site_settings` | Key-value admin settings (title, OG, API keys, announcements) |
| `tld_fallback_stats` | Per-TLD failure tracking; enables 3rd-party fallback after 3 consecutive failures |
| `custom_whois_servers` | Admin-managed custom WHOIS server overrides (JSONB per TLD) |
| `rate_limit_records` | DB-backed rate limiting (key = IP, count + reset_at per 60s window) |

**Concurrent migration guard**: `getDbReady()` uses a shared Promise lock (`global.__pgMigrating`) so parallel Next.js requests on cold start never trigger duplicate migrations.

## Rate Limiting

`src/lib/rate-limit.ts` — DB-backed with in-memory fast-path:
- Hot path: in-memory Map for IPs seen within current server process window
- Cold path: atomic `INSERT … ON CONFLICT DO UPDATE` into `rate_limit_records`
- Fallback: pure in-memory if DB unavailable
- `checkRateLimit(ip, maxRequests)` is now `async` — all call sites use `await`

## TLD Smart Fallback Gate

`src/lib/whois/tld-fallback-gate.ts` — prevents over-reliance on paid 3rd-party APIs:
- Tracks per-TLD failure count in `tld_fallback_stats`
- Native RDAP/WHOIS failures increment count; success resets to 0
- Third-party APIs (tianhu / yisi) only invoked when `fail_count >= 3` AND `use_fallback = true`
- Admin UI: `/admin/tld-fallback` — view stats, toggle fallback per TLD, bulk clear

## v2.0 — UI Micro-Interactions

- **Button press feedback**: `Button` base class gains `active:scale-[0.96] touch-manipulation select-none` — all buttons scale slightly on press
- **Spring physics clicks**: `src/components/motion/clickable.tsx` — `<Clickable>` wraps any child with a Framer Motion spring (stiffness 600 / damping 32 / mass 0.6) for a natural squish-and-release feel
- **TLD page tab animation**: `AnimatePresence mode="wait"` with x-slide + fade between "TLD List" and "WHOIS Servers" tabs (0.22s ease-out-expo)
- **Server row edit expansion**: Inline edit form animates open/closed with `height: 0 → auto` via `motion.div`; row → form swap is wrapped in per-row `AnimatePresence mode="wait"`
- **Add-server form**: Same height animation via `AnimatePresence` wrapping the `showAdd` conditional
- **Global tap delay elimination**: `globals.css` adds `touch-action: manipulation` to all `button`, `a`, `[role="button"]`, `select` elements — removes 300 ms iOS tap delay everywhere

## Admin Backend Pages

| Page | Route |
|------|-------|
| Dashboard | `/admin` |
| Users | `/admin/users` |
| Brand Claims | `/admin/stamps` |
| Reminders | `/admin/reminders` |
| Search Records | `/admin/search-records` |
| User Feedback | `/admin/feedback` |
| TLD Fallback Stats | `/admin/tld-fallback` |
| System Status | `/admin/system` |
| API Keys | `/admin/api` |
| Site Settings | `/admin/settings` |
| Invite Codes | `/admin/invite-codes` |
| Friendly Links | `/admin/links` |

## Admin-Managed Content (v2.0)

### Friendly Links (`/links`)
- Fully DB-backed: `friendly_links` table (id, name, url, description, category, sort_order, active)
- Public API: `/api/links` (GET active links, sorted by sort_order then id)
- Admin CRUD: `/api/admin/links` (GET/POST/PUT/DELETE)
- Admin page: `/admin/links` — create/edit/delete/toggle visibility, optional category grouping
- Links page groups by category, shows empty state when no links added
- Subtitle and title customizable via `links_title` / `links_content` in site settings

### About Page (`/about`)
- Chinese intro (`about_content`), English intro (`about_intro_en`) — both editable in admin settings
- Contact email (`about_contact_email`) — shown as a mailto link on about + links pages
- GitHub URL (`about_github_url`) — shown in tech stack section
- Thanks/acknowledgements (`about_thanks`) — JSON array `[{name, url, desc, descEn}]`, falls back to hardcoded defaults
- All fields editable via Admin Settings → 关于页面 section

## Domain Subscription Enhancement (v2.0)

### DB-Configurable TLD Lifecycle Rules
- `tld_lifecycle_overrides` table: admin-set grace/redemption/pendingDelete days per TLD
- `src/lib/server/lifecycle-overrides.ts`: 5-minute in-memory cache; `loadLifecycleOverrides()` + `invalidateLifecycleOverridesCache()`
- `getTldLifecycle()` and `computeLifecycle()` in `lifecycle.ts` accept optional `overrides` dict; DB values take priority over hardcoded table
- Admin API: `/api/admin/tld-lifecycle` — GET list, POST create (id auto-gen), PATCH update, DELETE; all writes call `invalidateLifecycleOverridesCache()`
- Admin page: `/admin/tld-lifecycle` — searchable table, add/edit/delete dialog, shows TLD + days + registry + built-in comparison

### Drop Notifications (v2.0)
- `dropApproachingHtml` + `domainDroppedHtml` templates added to `src/lib/email.ts`
- `DROP_SOON_KEY = -4`: sent when `phase === pendingDelete` AND `daysToDropDate <= 7` (not already sent)
- `DROPPED_KEY = -5`: sent when `phase === dropped` → notification then deactivate subscription
- `process.ts` loads overrides once per cron run, passes to all `computeLifecycle()` calls

### Subscription API & Dashboard Upgrade
- `/api/user/subscriptions` GET now returns computed lifecycle fields per subscription: `drop_date`, `grace_end`, `redemption_end`, `phase`, `days_to_expiry`, `days_to_drop`, `tld_confidence`
- `dashboard.tsx` removed local 13-TLD `LIFECYCLE` table + `getDomainLifecycle()` — lifecycle data now comes from the API using the full 200+ TLD table
- `urgentSubs` now includes subscriptions where `days_to_drop <= 7` (approaching drop date)
- Subscription cards show purple "X天后可抢注" badge when approaching drop; drop date rendered in purple when urgent

## Registration Security (v2.0)

### Invite Code System
- `invite_codes` table: `XXXXXX-XXXXXX-XXXXXX` uppercase codes, single-use
- `require_invite_code = "1"` site setting gates registration behind invite codes
- `subscription_access` + `invite_code_used` columns on users
- Existing users can apply codes from Dashboard → Subscription tab
- Admin API: `/api/admin/invite-codes` (GET list, POST create, DELETE by id)

### Email OTP Verification
- `/api/user/send-verify-code` — sends 6-digit code via Resend, stored in Redis (`verify:register:{email}`)
- 10-minute TTL, 60-second resend rate limit (`verify:rate:{email}`)
- Register page shows email field + "发送验证码" button with 60s countdown
- OTP input appears after code is sent; register API validates before creating account

### CAPTCHA (Human Verification)
- Provider, site key, secret key stored in `site_settings` (`captcha_provider`, `captcha_site_key`, `captcha_secret_key`)
- `captcha_secret_key` filtered from public GET; returned only for admin session
- `src/lib/server/captcha.ts` — `getCaptchaConfig()` + `verifyCaptchaToken()` supporting Turnstile and hCaptcha
- Register page: loads CAPTCHA script dynamically (explicit render mode), shows widget after invite code field
- Register API: verifies token server-side before account creation
- Admin Settings → 人机验证: provider dropdown, site key input, secret key (password) input

## Admin Backend Comprehensive Enhancement (2026-03-24)

### Critical Bug Fixes
- **Refund auto-revokes subscription**: `mark_refunded` in `/api/admin/payment/orders.ts` now also sets `subscription_access=FALSE` on the user (by `user_id` first, then `user_email` fallback). Returns `subscriptionRevoked: true` flag so UI can show a relevant toast.

### Cross-Page Deep Links
- **Orders → Users**: User email/name in orders list is now a clickable button that navigates to `/admin/users?search=EMAIL`
- **Users → Orders**: Edit modal has a "订单" button that navigates to `/admin/payment/orders?search=EMAIL`
- **URL pre-population**: Both orders and users pages read `?search` query param on mount to pre-fill search input when navigated from cross-links

### Inline Confirm Dialogs (replace native browser `confirm()`)
- **Users page delete**: First click on trash icon shows inline "确认删除 | ✕" row. Second click executes. Auto-clears after 4 seconds.
- **Orders page actions**: First click on mark-paid / refund shows inline amber warning banner "再次点击确认". Auto-clears after 4 seconds.
- **Feedback page delete**: Same inline confirm pattern with 4-second auto-cancel.

### Users Page CSV Export
- "导出 CSV" button in header exports all currently-loaded users with UTF-8 BOM for Excel compatibility
- Fields: email, name, registration time, email_verified, subscription_access, disabled, search_count, stamp_count, reminder_count, admin_notes

### Orders Stats — Per-Currency Revenue
- Stats query now groups by currency; returns `byCurrency: [{currency, revenue, count}]`
- UI shows single value for single-currency setups, per-currency table for multi-currency
- Added "已退款" count stat card alongside total/paid

### Dashboard Refresh Button
- `/admin/index.tsx`: refresh icon button next to "系统概览" heading; triggers `loadStats()`; spins during load

### Missing AdminLayout Titles Fixed
- `changelog.tsx`: `<AdminLayout title="更新日志">`
- `og-styles.tsx`: `<AdminLayout title="OG 卡片样式">`

### OG Styles SSP Auth Fixed
- `og-styles.tsx` used `requireAdmin` (API-route style) from `getServerSideProps` causing `res.status is not a function` 500 error
- Fixed to use `getServerSession` + `isAdmin` directly with proper SSR `redirect` instead

### Feedback Page Enhancements
- Reply-by-email button (envelope icon) appears on hover next to delete; opens pre-filled mailto: with domain in subject
- Expanded panel now shows: user description + action buttons ("复制域名", "RDAP 查看", "回复 EMAIL")
- All in-place confirm dialogs replace native `confirm()` calls
## Payment System (Added 2026-03-24)

### Architecture
- **DB tables**: `payment_plans` + `payment_orders` (in `src/lib/db.ts`)
- **Core library**: `src/lib/payment.ts` — order lifecycle, provider signing/verification
- **API routes**:
  - `GET /api/payment/plans` — public plan listing
  - `POST /api/payment/create` — create order + redirect URL
  - `GET /api/payment/status?order=ID` — order status polling
  - `POST /api/payment/webhook/stripe` — Stripe payment confirmation
  - `POST /api/payment/webhook/xunhupay` — Xunhupay (虎皮椒) confirmation
  - `POST /api/payment/webhook/alipay` — Alipay confirmation
  - `GET/POST /api/admin/payment/plans` — admin CRUD
  - `GET/POST /api/admin/payment/orders` — admin order management + mark-paid/refund
- **User pages**:
  - `/payment/checkout` — plan selection + provider selection + checkout
  - `/payment/result?order=ID` — payment result with auto-polling
- **Admin pages**:
  - `/admin/payment/plans` — plan CRUD (price, duration, currency, active toggle)
  - `/admin/payment/orders` — order listing with stats, filters, manual mark-paid/refund
  - Settings → 支付网关 — enable/disable providers, set public keys

### Providers
| Provider | Enable Flag | Public Key Setting | Private Key ENV |
|---|---|---|---|
| Stripe | `payment_stripe_enabled` | `payment_stripe_pk` | `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` |
| Xunhupay (虎皮椒) | `payment_xunhupay_enabled` | `payment_xunhupay_appid` | `XUNHUPAY_APP_SECRET` |
| Alipay (官方) | `payment_alipay_enabled` | `payment_alipay_appid`, `payment_alipay_notify_url` | `ALIPAY_PRIVATE_KEY`, `ALIPAY_PUBLIC_KEY` |

### Flow
1. Admin creates plans in `/admin/payment/plans`
2. Admin enables providers in Settings → 支付网关
3. User visits `/payment/checkout`, selects plan + provider
4. Provider redirect → webhook fires → `markOrderPaid()` sets `subscription_access=TRUE` + creates sponsor record
5. User lands on `/payment/result?order=ID` (auto-polls until paid)
6. Dashboard shows "购买套餐解锁" button when any provider is enabled

---

A fast, modern WHOIS and RDAP lookup tool supporting domains, IPv4/IPv6, ASN, and CIDR. Also includes built-in DNS, SSL certificate, and IP/ASN geolocation tools.

---

## Changelog

### v3.22.2 — RDAP Coverage Expansion: 168 ccTLDs + Conflict Fixes + Per-TLD Timeouts (2026-03-24)

**Scope:** Largest single RDAP coverage expansion yet. Fixed 15 blocking conflicts in `STATIC_NO_RDAP`, added 40+ new ccTLD RDAP servers confirmed by live probing, introduced per-TLD timeout map for slow registries, and set up automated monthly bootstrap refresh via GitHub Actions.

| File | Change | Detail |
|------|--------|--------|
| `src/lib/whois/tld-rdap-skip.ts` | **Fixed 15 critical STATIC_NO_RDAP conflicts** | `ru`, `by`, `kz`, `lb`, `ve`, `ec`, `tl`, `cd`, `af`, `gh`, `ug`, `et`, `ci`, `dj`, `ss` were in STATIC_NO_RDAP but also in CCTLD_RDAP_OVERRIDES, causing RDAP to be blocked entirely for these TLDs. All removed. STATIC_NO_RDAP reduced from ~25 → 21 genuinely RDAP-less TLDs. |
| `src/lib/whois/rdap_client.ts` | **CCTLD_RDAP_OVERRIDES expanded to 168 ccTLDs** | Added 40+ new entries: Western Europe (`at`, `be`, `ch`, `de`, `dk`, `ee`, `es`, `gr`, `hr`, `hu`, `ie`, `it`, `li`, `lt`, `lu`, `lv`, `me`, `pt`, `ro`, `rs`, `se`, `sk`), CIS (`by`, `kz`, `ru`, `su`), Other (`im`, `io`, `mn`, `my`, `nu`, `ph`, `hk`, `jp`, `kr`, `co`, `mx`, `pe`, `ve`, `za`). Entries reorganized by region. |
| `src/lib/whois/rdap_client.ts` | **`RDAP_TLD_TIMEOUT_MS` per-TLD timeout map** | 32-entry map with extended timeouts (6–8 s) for known-slow registries in Africa (`ng`, `ke`, `tz`, `gh`, `ug`), CIS (`ru`, `su`, `by`, `kz`), Middle East (`iq`, `sy`, `ye`), and Asia (`pk`, `np`, `mm`, `la`, `kh`). Default remains 4 s. |
| `src/lib/whois/rdap_client.ts` | **`lookupRdap` uses per-TLD timeout** | `RDAP_TLD_TIMEOUT_MS[tld] ?? 4000` passed to `tryRdapWithUrl` instead of hardcoded 4000. |
| `package.json` | **npm script** | `update:rdap-bootstrap` → `node scripts/update-rdap-bootstrap.js` for manual refresh. |
| `.github/workflows/update-rdap-bootstrap.yaml` | **GitHub Actions cron** | Runs `scripts/update-rdap-bootstrap.js` on the 1st of every month at 02:00 UTC, commits updated `rdap_gtld_bootstrap.ts` if changed. |

### v3.22.1 — Bug Fix Batch (2026-03-24)

**Scope:** Six targeted bug fixes across lookup recording, subscription session sync, query-only mode, admin pages, and announcement bar positioning.

**Changes:**

| File | Fix | Detail |
|---|---|---|
| `src/pages/api/lookup.ts` | Search history for logged-in users | Added `getServerSession` call; `saveSearchRecord` now accepts optional `userId` — logged-in users get their own `user_id`-linked records (upsert via delete+insert), anonymous users retain existing trim-to-50 logic. |
| `src/pages/dashboard.tsx` | Subscription session sync | When `apply-invite-code` returns "你已拥有订阅权限" (DB has access, JWT doesn't), client now calls `updateSession({ subscriptionAccess: true })` and switches to subscriptions tab instead of showing an error. |
| `src/components/navbar.tsx` | query_only_mode hides HistoryDrawer | `HistoryDrawer` reads `query_only_mode` from site settings via `useSiteSettings()` and returns `null` for non-admin users when the mode is enabled. Early return placed after all hooks to comply with React rules. |
| `src/pages/_app.tsx` | Announcement bar overlap fix | `AnnouncementBanner` sets CSS custom property `--ann-h` (36px when visible, 0px when dismissed) on the document root. Main element padding updated to `calc(4rem + var(--ann-h, 0px))`. |
| `src/components/navbar.tsx` | Navbar clears announcement overlap | Outer div uses `style={{ top: 'var(--ann-h, 0px)', transition: 'top 0.2s ease' }}` instead of hard-coded `top-0`, smoothly sliding below the announcement bar. |
| `src/pages/admin/tld-lifecycle.tsx` | Built-in lifecycle reference table | Added collapsible section showing all LIFECYCLE_TABLE entries. Each row has "添加覆盖" that pre-fills the form; already-overridden TLDs show a "已覆盖" badge. |
| `src/pages/admin/reminders.tsx` | Edit + Send Email for reminders | Added inline edit panel per record (domain, email, expiration_date, days_before); added send-email button (plane icon). |
| `src/pages/api/admin/reminders.ts` | Extended PATCH + POST send-email | PATCH now updates any combination of domain/email/expiration_date/days_before/active. New POST `?action=send-email` fetches reminder, computes daysLeft, sends `reminderHtml` via Resend. |

---

### v3.22 — Comprehensive Multilingual WHOIS Status Detection (2026-03-24)

**Scope:** Full multilingual expansion of domain status detection (reserved / prohibited / suspended). Both `common_parser.ts` (server-side) and `[...query].tsx` (client-side safety net) are now synced with identical pattern coverage for 25+ languages/registries.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/whois/common_parser.ts` | `syntheticReserved` expansion | Added field:value regex patterns for Italian `riservato`, Swedish `reserverad`, Norwegian `reservert`, Danish `reserveret`, Polish `zarezerwowany`, Dutch `gereserveerd`, Finnish `varattu`, Hungarian `fenntartott`, Romanian `rezervat`, Turkish `rezerve`, Greek `δεσμευμένο`; direct includes for Russian `зарезервирован`/`зарезервировано`/`зарезервирована`, Ukrainian `зарезервовано`, Japanese `予約済み`/`登録停止`, Korean `예약됨`/`예약된`, Arabic `محجوز`, Hebrew `שמור`, Traditional Chinese `保留網域`. |
| `src/lib/whois/common_parser.ts` | `syntheticProhibited` expansion | Added Russian `запрещена регистрация`/`регистрация запрещена`, Ukrainian `реєстрація заборонена`, Italian `registrazione vietata`/`status: vietato`, Japanese `登録不可`/`登録制限`, Korean `등록불가`/`등록 금지`, Arabic `محظور`, Chinese `不可注册`/`禁止使用`. |
| `src/lib/whois/common_parser.ts` | `syntheticSuspended` expansion | Added Portuguese `suspenso`, Italian `status: sospeso`/`dominio sospeso`, Dutch `opgeschort`, Polish `zawieszony`, Finnish `keskeytetty`, Russian `приостановлен`/`приостановлено`, Ukrainian `призупинено`, Japanese `停止中`/`利用停止`, Korean `정지됨`/`사용 정지`, Arabic `موقوف`/`معلق`, Chinese `已停用`/`暂停使用`. |
| `src/pages/[...query].tsx` | `rawHasReserved` / `rawHasProhibited` / `rawHasSuspended` | Synced with identical expanded pattern lists from `common_parser.ts`. Latin-script patterns use field:value regex to avoid false positives from domain names containing those words. Non-Latin scripts use direct includes (safe: domain names are punycode in WHOIS). |
| `src/lib/env.ts` | VERSION bumped to "3.22" | |

**Design rationale:**
- Latin-script single words (e.g. `reserviert`, `riservato`) use `/\bstatus\s*:\s*<word>\b/` regex OR require phrase context, preventing false positives when a domain name itself contains that word (e.g. `riservato.it`).
- Non-Latin scripts (Cyrillic, CJK, Arabic, Hebrew) safely use `includes()` — domain labels appear as punycode (`xn--…`) in WHOIS, never as raw Unicode characters.

---

### v3.21 — Reserved/Premium Domain Detection + Multilingual Patterns (2026-03-24)

**Scope:** Introduced `registry-premium` status tag; added 30+ English reserved phrases; initial multilingual reserved/prohibited/suspended patterns.

---

### v3.20 — Invite Code System Overhaul + UX Fixes (2026-03-24)

**Scope:** Complete rebuild of invite code expiry, validation, and activation flow; fixed critical bug where optional invite codes were silently ignored during registration.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/db.ts` | Schema: `expires_at` | Added `ALTER TABLE invite_codes ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ` migration. |
| `src/pages/api/admin/invite-codes.ts` | Expiry support | POST now accepts `expires_in` (1d / 7d / 30d / 365d / permanent); GET returns `expires_at`; `parseExpiresAt()` helper converts preset to absolute timestamp. |
| `src/pages/api/user/apply-invite-code.ts` | Expiry + updated_at | Validates `expires_at` (rejects if past); updates `updated_at` on user row. |
| `src/pages/api/user/register.ts` | Critical bug fix | Previously, if `require_invite_code = "0"`, any invite code filled in by the user was silently ignored and `subscription_access` stayed `false`. Now: optional codes are still validated + applied, granting `subscription_access = true` on registration. Also adds expiry check. |
| `src/pages/admin/invite-codes.tsx` | UI overhaul | Stats grid → 5 columns (adds 已过期/red); filter tabs → 5 tabs (adds 已过期); create modal → expiry pill picker (永久/1天/1周/1月/1年); table → 有效期 column with relative display; purge button now targets both exhausted AND expired codes. |
| `src/pages/dashboard.tsx` | Better UX after activation | After successful code redemption: clears the input, switches to the subscriptions tab immediately, so users see their newly unlocked feature at once. |
| `src/lib/env.ts` | VERSION bumped to "3.20" | |

---

### v3.19 — Fix Search Spinner on Nav Link Clicks (2026-03-24)

**Scope:** Bug fix — the search button spinner was incorrectly showing when clicking ordinary nav links (e.g. About, Links, Admin pages) from the home page or a results page.

**Root cause:** Both `index.tsx` and `[...query].tsx` defined their own inline `isSearchRoute()` helper with a `STATIC_PATHS` allow-list. The list in `[...query].tsx` was incomplete (missing `/dns`, `/ssl`, `/ip`, `/icp`, `/about`, `/sponsor`, `/links`, `/changelog`, `/admin`, `/feedback`, etc.), so navigating to those paths from a results page would call `setLoading(true)` and spin the button indefinitely until the route completed.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/utils.ts` | `isSearchRoute()` shared export | Single canonical implementation with a complete `STATIC_PAGE_PREFIXES` allow-list; strips locale prefix before matching. |
| `src/pages/index.tsx` | Use shared `isSearchRoute` | Removed inline copy; imports from `@/lib/utils`. |
| `src/pages/[...query].tsx` | Use shared `isSearchRoute` | Removed inline copy (which had the incomplete prefix list); imports from `@/lib/utils`. |
| `src/lib/env.ts` | VERSION bumped to "3.19" | |

---

### v3.18 — Admin Access Keys Enrichment (2026-03-24)

**Scope:** Enriched the API 密钥 (access-keys) admin page with stats, dual filter rows, and bulk expired-key cleanup — matching the quality bar set for invite-codes in v3.17.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/admin/access-keys.tsx` | Stats grid | Added 4-stat grid: 全部 / 启用中 / 已停用 / 已过期 (red). |
| `src/pages/admin/access-keys.tsx` | Dual filter rows | Row 1: status filter pills (全部/启用/停用/已过期); Row 2: scope filter pills (全部范围/API/域名订阅/全部权限). Both compose together. Fixed "all" naming ambiguity by using `__any__` as the scope-filter sentinel. |
| `src/pages/admin/access-keys.tsx` | Relative last-used time | "最近使用" column now shows relative time (刚刚 / N分钟前 / N小时前 / N天前) with clock icon, and "从未使用" when `last_used_at` is null. |
| `src/pages/admin/access-keys.tsx` | Bulk purge + header count | "清理过期 (N)" button in header batch-deletes all expired keys; cumulative call count shown in subtitle. |
| `src/lib/env.ts` | VERSION bumped to "3.18" | |

---

### v3.17 — Admin Page Enrichment: Feedback, Invite Codes & Links (2026-03-24)

**Scope:** Enriched three admin management pages with richer filtering, stats, and bulk operations.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/api/admin/feedback.ts` | Issue-type filter + typeCounts | `GET` now accepts `issue_type` query param to filter by a single issue type; response includes `typeCounts` map (aggregated via `jsonb_array_elements_text`). |
| `src/pages/admin/feedback.tsx` | Stats bar + filter tabs | Added 5-card issue-type stats bar (不准确/不完整/过期/解析错误/其他) with percentage, each card clickable as a filter shortcut; pill-style filter tabs with per-type count badges; search and type filter compose together. |
| `src/pages/admin/invite-codes.tsx` | Stats grid + filter tabs + usage progress + bulk-delete | Added 4-stat grid (全部/可用/停用/耗尽); pill filter tabs (全部/可用/已停用/已耗尽); each code row now shows a colour-coded progress bar (green→amber at ≥80%); "清理耗尽" button batch-deletes all exhausted codes. |
| `src/pages/admin/links.tsx` | Category filter tabs + visibility toggle + stats | Added 3-stat grid (总数/已显示/分类数); dynamic per-category pill tabs derived from existing category values; "未分类" tab when uncategorised links exist; "隐藏已隐藏/显示已隐藏" toggle button shows count of hidden links. |
| `src/lib/env.ts` | VERSION bumped to "3.17" | |

---

### v3.16 — UX Animations Overhaul + No-Server TLD Fast-Fail (2026-03-24)

**Scope:** Mobile UX polish and WHOIS lookup hot-path optimization.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/_app.tsx` | Removed `RouteLoadingBar` | Deleted the 2 px top loading bar and its 50-line component. Text skeleton + shimmer already provide query feedback; the bar was visually redundant. |
| `src/pages/_app.tsx` | Smoother page transition | `pageTransition` duration 0.13 s → 0.20 s; easing `"easeOut"` → cubic-bezier `[0.22, 1, 0.36, 1]` (iOS-style spring feel). |
| `src/pages/[...query].tsx` | Improved card stagger | `CARD_CONTAINER_VARIANTS` stagger 0.025 s → 0.09 s; `CARD_ITEM_VARIANTS` now includes `y: 10 → 0` slide-up with `[0.22, 1, 0.36, 1]` easing, creating a natural "main content first, secondary sidebar after" reveal on mobile. |
| `src/pages/[...query].tsx` | WHOIS/RDAP tab fade | `ResponsePanel` tab content wrapped in `AnimatePresence mode="wait"` — switching between WHOIS and RDAP now cross-fades (0.15 s) instead of hard-cutting. |
| `src/lib/whois/lookup.ts` | `isTldKnownNoServer` hot-path check | Imported from `custom-servers.ts` and checked immediately before the whoiser TCP call. When a TLD is explicitly listed as `null` in `cctld-whois-servers.json`, throws instantly (0 ms) instead of waiting for a TCP timeout, letting the tianhu/yisi fallback race immediately. |
| `src/lib/env.ts` | VERSION bumped to "3.16" | |

---

### v3.15 — DB Cache Fix: In-Memory TLD Gate + Expanded RDAP/WHOIS Skip Lists (2026-03-24)

**Scope:** Eliminated the biggest remaining latency source — a Supabase DB query on every single WHOIS request — and expanded both the RDAP-skip and ccTLD-server lists.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/whois/tld-fallback-gate.ts` | Rewrote with in-memory startup cache | `isTldFallbackEnabled()` was hitting Supabase on every call. Now loads the entire `tld_fallback_overrides` table once at startup into a `Map`; subsequent calls are pure memory lookups (0 ms). Cache invalidated via `invalidateFallbackCache()`. Result: `ab.cd` query time 12 s → 1.26 s. |
| `src/lib/whois/tld-rdap-skip.ts` | Expanded `STATIC_NO_RDAP` | Added 17 confirmed no-RDAP ccTLDs: `.ac .aw .ax .bj .bv .cc .cg .cx .gg .hm .im .je .ms .pm .re .sh .yt`. Prevents wasted RDAP round-trips for these TLDs. |
| `src/data/cctld-whois-servers.json` | Comprehensive ccTLD server list | Grew from 206 → 255 entries covering all IANA ccTLDs. Added working servers for `.ad` (nic.ad), `.bh` (nic.bh), `.fm` (nic.fm), `.gf/.gp/.mq` (whois.nic.mq), `.gn` (ande.gov.gn), `.ls/.mc/.mr/.sl/.sm/.ss/.td` (nic.{tld}), `.mt` (whois.ripe.net), `.sr` (whois.sr), `.ye` (y.net.ye). `null` entries for TLDs with no reachable public server (`.cu`, `.kp`, `.gb`, etc.). |
| `src/lib/whois/custom-servers.ts` | `isTldKnownNoServer()` added | Exposes which TLDs are explicitly `null` in the cctld file. Builds a `Set<string>` (`_knownNoServerCache`) during `getAllCustomServers()` load; `isTldKnownNoServer(tld)` is a fast O(1) lookup. |
| `src/lib/env.ts` | VERSION bumped to "3.15" | |

---

### v3.14 — Query Speed: Timeout Tuning + Parallel Fallback Racing (2026-03-24)

**Scope:** Reduced all network timeouts and started the third-party fallback in parallel with native lookups instead of waiting for full TCP failure.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/whois/lookup.ts` | Timeout reductions | `RDAP_TIMEOUT` 7 s → 2 s; `WHOIS_TIMEOUT` 7 s → 4 s; `FALLBACK_START_MS` added at 2 s — fallback races natively after this delay instead of waiting for TCP timeout. |
| `src/lib/whois/tianhu-fallback.ts` | `TIANHU_TIMEOUT` | Set to 4 s (was unbounded). |
| `src/lib/whois/yisi-fallback.ts` | `YISI_TIMEOUT` | Set to 4 s (was unbounded). |
| `src/lib/pricing/client.ts` | Pricing timeout | Reduced to 4 s. |
| `src/lib/env.ts` | VERSION bumped to "3.14" | |

---

### v3.13 — Remove MOZ DA/PA/Spam Feature (2026-03-24)

**Scope:** Removed the MOZ Domain Authority / Page Authority / Spam Score feature entirely from the domain result page.

**Changes:**

- Removed all MOZ API calls, UI components, and related code from `src/pages/[...query].tsx`
- Removed MOZ-related environment variable references
- Cleaned up unused imports and state variables
- `src/lib/env.ts` VERSION bumped to "3.13"

---

### v3.12 — X.RW Full Rebranding + WeChat OG Image Fix (2026-03-24)

**Scope:** Complete visual rebranding to X.RW identity, with brand image assets and social sharing fixes.

**Changes:**

- Replaced all NEXT WHOIS branding with X.RW across navbar, OG images, meta tags, and site settings defaults
- Added X.RW brand images (`/public/brand/`) for OG cards and apple-touch-icon
- Fixed WeChat `og:image` — now always resolves to an absolute URL using canonical site origin
- Updated `apple-touch-icon`, `manifest.json` icons, and PWA manifest to X.RW assets
- `src/lib/env.ts` VERSION bumped to "3.12"

---

### v3.11 — Brand Stamp Certification: tian.hu / nazhumi.com / yisi.yun (2026-03-24)

**Scope:** Certified three technology-partner domains as official brand stamps in the X.RW stamp registry.

**Changes:**

- Added verified brand stamps for `tian.hu` (tianhu WHOIS data provider), `nazhumi.com` (domain pricing data), and `yisi.yun` (WHOIS fallback API)
- Stamp records created with `brand` style and appropriate card themes
- `src/lib/env.ts` VERSION bumped to "3.11"

---

### v3.10 — OG Image Text Editor, Changelog Sync & UX Cleanup (2026-03-24)

**Scope:** Admin panel enhancements and UX improvements.

**New features / fixes:**

- **OG image text editor (`/admin/og-styles`):** Brand name and tagline are now fully editable in the admin panel. Settings stored in `site_settings` (`og_brand_name`, `og_tagline`) with 5-minute server-side cache invalidation. Both fields are immediately reflected across all 8 OG card styles without code changes.
- **`api/og.tsx` — dynamic text:** All 10 hardcoded `"RDAP+WHOIS"` brand label occurrences across the 8 OG styles now read from the config API. Taglines similarly use the configurable tagline field. Default values remain `"RDAP+WHOIS"` and `"WHOIS / RDAP · Domain Lookup Tool"` when not overridden.
- **`api/og-config.ts` — extended config:** Config API now returns `brand_name` and `tagline` alongside `enabled_styles`, and accepts `PUT` requests to update them.
- **Changelog sync button (`/admin/changelog`):** "同步版本历史" button batch-imports predefined version entries (v3.6–v3.10) from the `changelog-sync` API, skipping duplicates. Useful for seeding a fresh DB.
- **User dashboard — value-tier badges hidden:** High-value / valuable domain badges in the search history list are no longer shown to users (data is still recorded server-side for admin analytics). Removed `tierCfg` badge render; `TIER_CFG` definition and `value_tier` recording untouched.

---

### v3.9 — API Key Authentication System (2026-03-24)

**Scope:** Complete API Key management system. Admins can create, revoke, and scope access keys, and optionally enforce key authentication across all public API endpoints.

**New features:**

- **`access_keys` DB table:** Stores keys with fields: `id`, `key` (`rwh_` + 40 hex), `label`, `scope` (`api` / `subscription` / `all`), `is_active`, `created_at`, `expires_at`, `last_used_at`, `use_count`. Auto-provisioned via `initDb()`.
- **`src/lib/access-key.ts` library:** `generateKey()` (rwh_ prefix + 40 hex chars), `validateApiKey()` (checks active, expired, scope), `extractApiKey()` (reads `X-API-Key` header or `?key=` query param), `enforceApiKey(req, res, scope)` (returns `boolean` — returns early if invalid), `isApiKeyRequired()` (reads `site_settings.require_api_key` with 30 s in-memory cache).
- **`/api/admin/access-keys` endpoint (GET/POST/PATCH/DELETE):** Full CRUD + a `POST { action: "toggle_require", enabled: bool }` to flip global enforcement; cache invalidated on toggle.
- **`/admin/access-keys` page:** Lists all keys (masked), shows scope badge, use count, last-used date; global enforcement toggle; "Generate Key" modal with label/scope/expiry fields; newly-created key revealed once in a dismissible alert; per-row enable/disable and delete actions.
- **Admin nav:** Added "密钥" entry pointing to `/admin/access-keys`.
- **API enforcement:** `enforceApiKey()` inserted (after rate limit, before business logic) in `api/lookup.ts`, `api/dns/records.ts`, `api/dns/txt.ts`, `api/ssl/cert.ts`, `api/ip/lookup.ts`. When `require_api_key = 0` (default), enforcement is a no-op (zero overhead).
- **Docs page:** New "API Key 鉴权" section with `#api-key` anchor; nav pill added; covers: header vs query-param usage, scope table, error response codes (401 / 403). `SectionHeader` updated to accept optional `id` prop.

---

### v3.8 — Page Transition Fixes, URL Param Loading & API Rate Limiting (2026-03-23)

**Scope:** Fixed multiple UX and security bugs accumulated since v3.6. Transitions now reliably fire between domain searches; tool pages correctly load query params from the URL on first render; DNS/IP/SSL APIs are now rate-limited.

**Bug fixes:**

- **`_app.tsx` — animationKey logic was inverted:** Pages under `/[...query]` all shared the same animation key (`router.pathname` = `/[...query]`), so navigating between domain searches produced no transition. Fixed by swapping the key strategy: shallow tool pages (`/dns`, `/ssl`, `/ip`, `/icp`, `/stamp`) use `router.pathname` (so they don't re-animate when the query string changes), and all other pages (including `/[...query]`) use `router.asPath` (so each unique domain URL gets its own transition).
- **`_app.tsx` — Restored `AnimatePresence mode="wait" initial={false}`** with a `motion.div` using pure-opacity `pageVariants` (0 → 1, 0.13 s). The previous v3.6 CSS-only approach was removed in favour of this corrected Framer Motion approach.
- **`[...query].tsx` — Card stagger restored (opacity-only):** The over-aggressive v3.6 removal of all stagger is reverted. Cards now stagger at 0.025 s intervals with opacity-only variants (no y-axis movement), keeping the feel smooth without the earlier jitter.
- **`dns.tsx` / `ssl.tsx` / `ip.tsx` — `router.isReady` missing from `useEffect`:** All three tool pages were reading `router.query` in a `useEffect(fn, [])` that ran before Next.js had populated the query object on first render, causing URL `?q=` params to be silently ignored. Changed dependency arrays to `[router.isReady]` with an early-return guard.
- **DNS/IP/SSL APIs — no rate limiting:** `api/dns/records`, `api/dns/txt`, `api/ip/lookup`, and `api/ssl/cert` had no request throttling, leaving them open to abuse. Added in-memory `rateLimit()` checks (60/min for DNS, 30/min for IP, 20/min for SSL) with `429` responses.

---

### v3.7 — Smart Redis Cache with Adaptive TTL (2026-03-23)

**Scope:** Replaced the flat-TTL Redis cache with a domain-type-aware intelligent cache layer. All lookups now avoid redundant WHOIS/RDAP server calls, with cache expiry tuned to how quickly each domain type's data actually changes.

**Cache TTL strategy:**

| Domain type | TTL | Rationale |
|---|---|---|
| IP / ASN / CIDR query | 24 h | IP allocations change extremely rarely |
| Registry-reserved / pending | 12 h | Slow-moving administrative status |
| Available / unregistered | 5 min | Could be registered at any moment |
| Registered, expired (≤0 d) | 10 min | May be re-registered imminently |
| Registered, expiring ≤7 d | 30 min | Could change hands soon |
| Registered, remaining ≤60 d | 1 h | Watch for changes |
| Registered, remaining >60 d | 6 h | Very stable — safe to cache long |
| Error / failed lookup | 0 | Never cache failures |

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/whois/types.ts` | Added `cachedAt?: number` and `cacheTtl?: number` to `WhoisResult` | `cachedAt` = Unix ms timestamp when result was cached; `cacheTtl` = remaining TTL seconds (from Redis `TTL` command when serving from cache, or initial TTL when freshly computed). |
| `src/lib/server/redis.ts` | Production-grade Redis client rewrite | Added `lazyConnect: true`, `enableOfflineQueue: false` (commands fail immediately when disconnected instead of queuing), `retryStrategy` capped at 3 retries, per-event `_available` flag tracked via `ready`/`close`/`reconnecting`/`end` events. Added `getRemainingTtl(key)` and `getJsonRedisValueWithTtl(key)` helpers (pipeline GET + TTL in one round-trip). |
| `src/lib/whois/lookup.ts` | `computeSmartTtl(result)` function | Exported function that classifies a `WhoisResult` and returns the appropriate cache TTL in seconds. Zero means "do not cache". |
| `src/lib/whois/lookup.ts` | `lookupWhoisWithCache` upgraded | L1 (memory, 30 s) → L2 (Redis, smart TTL). Cache hits return `cachedAt` + `cacheTtl` from stored metadata + live Redis TTL. Cache misses: compute smart TTL, store `{ cachedAt, cacheTtl }` in the stored object, write to Redis with that TTL. Failures (status=false) are never cached. |
| `src/pages/api/lookup.ts` | Dynamic `Cache-Control` header | `s-maxage` is now set to the actual smart TTL (e.g. 21600 for stable domains, 300 for available). `stale-while-revalidate` = min(TTL × 4, 86400). Vercel edge cache now matches Redis expiry. Also passes `cachedAt` and `cacheTtl` through in the JSON response. |
| `src/pages/[...query].tsx` | Cache TTL displayed in result footer | When a result is served from cache, the time strip shows e.g. `0.00s · cached (6h)` — the parenthesised value is the remaining TTL from Redis, formatted as Xh / Xm / Xs. |
| `src/lib/env.ts` | VERSION bumped to "3.7" | |

**Environment variables (Redis connection — any one set activates Redis):**

| Variable | Description |
|---|---|
| `KV_URL` or `REDIS_URL` | Full Redis connection URL (e.g. `redis://...` or `rediss://...`). Vercel KV uses `KV_URL`. Upstash uses `REDIS_URL`. |
| `REDIS_HOST` | Redis hostname (used if URL not set) |
| `REDIS_PORT` | Redis port (default 6379) |
| `REDIS_PASSWORD` | Redis password |
| `REDIS_DB` | Redis database index (default 0) |

### v3.6 — Mobile Animation Fix: No More Flash/Jitter (2026-03-23)

**Scope:** Eliminated all sources of mobile page-transition flash and result-card jitter.

**Root causes fixed:**
1. `AnimatePresence mode="sync"` in `_app.tsx` caused old and new pages to overlap during navigation, making the background "bleed through" and flash white/dark between pages.
2. `CARD_ITEM_VARIANTS` with `y: 12` + `staggerChildren: 0.06` in `[...query].tsx` made result cards appear to jump upward one-by-one, visually jittery on mobile.
3. "Available domain" hero section in `[...query].tsx` had `delay: 0.15 / 0.2 / 0.35` on motion elements, causing content to pop in piece-by-piece.
4. `dns.tsx` result cards had `y: 4` + `delay: index * 0.03` stagger, causing visible card cascade on mobile.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/styles/globals.css` | Added `.page-enter` CSS class | Pure opacity fade-in (0.12 s ease-out) using `@keyframes page-enter`. No transform, no `will-change`. |
| `src/pages/_app.tsx` | Removed `AnimatePresence` + `motion.div` page wrapper | Replaced with a plain `<div key={animationKey} className="page-enter">`. React unmounts old div, mounts new div with CSS animation — zero overlap, zero background flash. Also removed unused `pageVariants`, `pageTransition` constants and framer-motion import from this file. |
| `src/pages/[...query].tsx` | `CARD_CONTAINER_VARIANTS`: removed stagger | Changed from `staggerChildren: 0.06, delayChildren: 0.02` to a simple `duration: 0.15` fade-in for the entire container. |
| `src/pages/[...query].tsx` | `CARD_ITEM_VARIANTS`: removed y-axis movement | Items are now `opacity: 1` in both hidden and visible states — the container fade handles the appearance. No per-item stagger or y-offset. |
| `src/pages/[...query].tsx` | "Available domain" hero: removed delayed animations | Replaced `motion.div` (scale: 0.8→1, delay 0.15) for status badge, `motion.div` (delay 0.2) for domain name, and `motion.a` (scale: 0.95→1, delay 0.35) for CTA button with static `div`/`a` elements. Content appears instantly. |
| `src/pages/[...query].tsx` | Translation pill: removed y-axis offset | Changed `initial={{ opacity: 0, y: -4 }}` to `initial={{ opacity: 0 }}` only. |
| `src/pages/dns.tsx` | Removed `y: 4` stagger from result cards | Both `found` and `not-found` result cards now animate opacity-only (`initial={{ opacity: 0 }}`) with no per-index delay. |
| `src/lib/env.ts` | VERSION bumped to "3.6" | |

### v3.5 — Anonymous History Cap + Enriched Admin Backend (2026-03-23)

**Scope:** Anonymous query history capped at 50 (new replaces old). Admin backend fully enriched: user management gains subscription_access/email_verified toggles and per-user stats; search records gains individual-row delete, anonymous filter, and DB-tier badges; dashboard gains today's counters and richer stats; admin stats API expanded.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/api/lookup.ts` | Anonymous history: 50-cap + replace semantics | `saveAnonymousSearchRecord()` now: DELETE existing record for same query (user_id IS NULL), INSERT new record, then trim to `MAX_ANON_HISTORY = 50` (keep newest 50). Replaces the old 24-hour dedup approach. |
| `src/pages/api/admin/users.ts` | Added `subscription_access`, `email_verified` to SELECT/PATCH | All GET responses now include `subscription_access`, `email_verified`, `search_count`, `stamp_count`, `reminder_count` per user. PATCH accepts `subscription_access` and `email_verified`. New `subscribedCount` and `verifiedCount` summary counts in GET response. |
| `src/pages/api/admin/users.ts` | Added `subscribed` and `verified` filter options | Filter by `?filter=subscribed` or `?filter=verified` to show only users with subscription access or verified email. |
| `src/pages/api/admin/search-records.ts` | Individual record DELETE via `?id=xxx` | `DELETE /api/admin/search-records?id={id}` removes a single record. Also added `period=anonymous` and `user_id=null` bulk-delete options. |
| `src/pages/api/admin/search-records.ts` | Anonymous filter + anon/logged stats | `?filter=anonymous` returns only `user_id IS NULL` records. Stats response now includes `anonymous` and `logged` counts. Daily stats include `anon` column. Value tier now read from DB column (no recompute). |
| `src/pages/api/admin/stats.ts` | Added `anonSearches`, `todaySearches`, `todayUsers`, `subscribedUsers` | Dashboard overview can show today's activity pulse and subscription user count. |
| `src/pages/admin/index.tsx` | Today's activity bar + subscription stat card | Shows "今日动态" bar with new users / queries / anon count. Added "订阅用户" stat card. Recent searches show ghost icon for anonymous. |
| `src/pages/admin/users.tsx` | Full user management enrichment | Edit modal: subscription_access toggle (amber), email_verified toggle (emerald), disabled toggle (red), per-user stat mini-cards (searches / stamps / subscriptions). User list: VIP crown icon for subscription users, verified badge, stat chips, subscription quick-toggle button. Filter tabs: added "已订阅" and "已验证". |
| `src/pages/admin/search-records.tsx` | Individual delete + anonymous filter + DB tier badge | Each row has a delete button (appears on hover). New "匿名查询" filter tab. Stats strip expanded to 8 cards (anon + logged). Bulk delete adds "清空匿名记录". Value tier badge now reads from DB (no client-side score recompute). User/anon breakdown bar chart added to stats panel. |
| `src/lib/env.ts` | VERSION bumped to "3.5" | |

### v3.4 — Mobile UX: Instant Nav Feedback + Tiered History Retention + Pagination (2026-03-23)

**Scope:** Three parallel improvements: (1) immediate tap feedback on navigation via top loading bar; (2) smoother page transitions (pure opacity, no y-axis jank); (3) search history now has tiered expiry, 100-record cap, per-page pagination, value-tier badges, and confirmed delete-all.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/_app.tsx` | Added `RouteLoadingBar` component | 2 px primary-colour bar at top of screen. Appears immediately on `routeChangeStart` (15 % → 50 % → 75 % → 100 % on complete), giving instant click feedback on mobile. Uses router events, no external dependency. |
| `src/pages/_app.tsx` | Simplified page transition animation | Removed y-axis offset (`y: 6`/`y: -3`). Now pure opacity fade only (`0 → 1 → 0`), duration reduced to 0.15 s. Eliminates vertical jank that was especially noticeable on mobile. |
| `src/pages/_app.tsx` | Removed `willChange` hint | `willChange: "opacity, transform"` removed; `transform` is no longer needed since y-axis motion is gone. |
| `src/lib/db.ts` | Added `value_tier` column to `search_history` | `ALTER TABLE … ADD COLUMN IF NOT EXISTS value_tier TEXT NOT NULL DEFAULT 'normal'`. Stores computed domain value tier alongside each record for retention-rule enforcement. |
| `src/pages/api/user/search-history.ts` | Tiered retention cleanup (`pruneExpired`) | Runs after every POST. SQL removes records older than: 10 d (normal), 20 d (valuable, score ≥ 35), 50 d (high, score ≥ 55). |
| `src/pages/api/user/search-history.ts` | `MAX_HISTORY` 500 → 100 | Normal users now capped at 100 records. Oldest records trimmed after every write via `trimToLimit`. |
| `src/pages/api/user/search-history.ts` | Computes and stores `value_tier` on insert | `computeValueTier()` uses `scoreDomain()`: high (≥55) / valuable (≥35) / normal. Only for `domain` queries with `unregistered` status; all others default to `normal`. |
| `src/pages/api/user/search-history.ts` | GET now supports pagination | Accepts `?page=N`, returns `{ history, total, page, pages }`. Page size = 20. |
| `src/pages/dashboard.tsx` | History pagination state + controls | New states: `historyPage`, `historyTotal`, `historyPages`. `fetchHistory(page)` function. Prev / Next buttons shown when `pages > 1`. |
| `src/pages/dashboard.tsx` | Value-tier badges in history list | Each domain row shows a coloured "高价值" (amber) or "有价值" (violet) badge when `valueTier` is set, alongside the existing reg-status badge. |
| `src/pages/dashboard.tsx` | "全部删除" confirmation | `window.confirm` shows total count before deletion. Resets all pagination state on success. |
| `src/pages/dashboard.tsx` | Tab & stat card use `historyTotal` | History tab badge and overview card now show the server-side total instead of the current page length. |
| `src/pages/dashboard.tsx` | Retention hint footer | When only one page exists, shows "普通 10 天 · 有价值 20 天 · 高价值 50 天" instead of old "最近 50 条记录". |

### v3.3 — Fully Branded Email Templates with Dynamic Site Name (2026-03-23)

**Scope:** All outgoing system emails now read the site name from the database (`site_settings.site_logo_text`) and render it in logos, subjects, and footers. No more hardcoded "Next Whois" in any email. Covers every email route in the project.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/email.ts` | `getSiteLabel()` added with 60 s DB cache | Reads `site_logo_text` from `site_settings`; falls back to "NEXT WHOIS". Exported so any API route can call it once and pass the result down. |
| `src/lib/email.ts` | `emailLayout()` accepts `siteName` param | Logo renders site name split on last space, last word coloured with PRIMARY violet; logo is a clickable link to `BASE_URL`. Footer copyright line also uses `siteName`. |
| `src/lib/email.ts` | All builder functions accept `siteName?: string` | `welcomeHtml`, `subscriptionConfirmHtml`, `reminderHtml`, `phaseEventHtml`, `dropApproachingHtml`, `domainDroppedHtml`, `passwordResetHtml`, `adminNotifyHtml`, `feedbackHtml`, `highValueAlertHtml`, `verifyCodeHtml` all default to "NEXT WHOIS" when `siteName` is omitted. |
| `src/lib/email.ts` | `stampVerifyTimeoutHtml()` added | New styled email for DNS verification timeout on stamp/brand-claim flow. Matches app visual style; accepts `domain`, `fileContent`, `verifyUrl`, `siteName`. |
| `src/pages/api/user/register.ts` | Welcome email branded | Calls `getSiteLabel()`, uses `siteName` in subject and `welcomeHtml`. |
| `src/pages/api/user/forgot-password.ts` | Reset email branded | Calls `getSiteLabel()`, uses `siteName` in subject and `passwordResetHtml`. |
| `src/pages/api/user/send-verify-code.ts` | Verify-code email branded | Calls `getSiteLabel()`, uses `siteName` in subject and `verifyCodeHtml`. |
| `src/pages/api/admin/test-email.ts` | Test email branded | Calls `getSiteLabel()`, uses `siteName` in subject and `adminNotifyHtml`. |
| `src/pages/api/stamp/giveup-notify.ts` | Rewritten to use `stampVerifyTimeoutHtml` | Replaced raw Arial-only HTML builder with the new styled template function. Calls `getSiteLabel()`. |
| `src/pages/api/feedback.ts` | Feedback notification branded | Calls `getSiteLabel()`, passes `siteName` to `feedbackHtml`. |
| `src/pages/api/remind/submit.ts` | Subscription confirm email branded | Calls `getSiteLabel()`, passes `siteName` to `subscriptionConfirmHtml`. |
| `src/pages/api/remind/process.ts` | All reminder/phase/drop emails branded | Calls `getSiteLabel()` once per cron invocation; passes `siteName` to all 5 email builder calls (`reminderHtml`, `phaseEventHtml` ×3, `dropApproachingHtml`, `domainDroppedHtml`). |
| `src/pages/api/user/search-history.ts` | High-value domain alert branded | Calls `getSiteLabel()`, passes `siteName` to `highValueAlertHtml`. |

### v3.2 — UX Polish, Branding Consistency & Permission Flow Fixes (2026-03-23)

**Scope:** Session-wide settings caching, page transition stabilization, consistent site branding across all sub-pages, and corrected auth/permission flows in the dashboard and query pages.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/lib/site-settings.tsx` | Added `sessionStorage` cache for site settings | Reads cached settings as initial state on first render, eliminating the title flash caused by `DEFAULT_SETTINGS` showing before the API responds. Cache is written/updated on every successful API fetch. |
| `src/pages/_app.tsx` | Fixed `AnimatePresence` key for client-search pages | Pages in `CLIENT_SEARCH_PAGES` (`/dns`, `/ip`, `/ssl`, `/icp`, `/tools`, `/feedback`) now use `router.pathname` as the animation key instead of `router.asPath`, preventing jarring exit/re-enter transitions when query params change. |
| `src/pages/dns.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | `DNS 查询 — NEXT WHOIS` now uses `settings.site_logo_text` dynamically. |
| `src/pages/ssl.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | `SSL 证书查询 — NEXT WHOIS` now uses `settings.site_logo_text` dynamically. |
| `src/pages/ip.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | `IP / ASN 查询 — NEXT WHOIS` now uses `settings.site_logo_text` dynamically. |
| `src/pages/tools.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | Tools page title now uses `settings.site_logo_text` dynamically. |
| `src/pages/icp.tsx` | Added `useSiteSettings` hook; fixed hardcoded title | ICP page title now uses `settings.site_logo_text` dynamically. |
| `src/pages/docs.tsx` | Added `useSiteSettings` hook; fixed hardcoded title + og/twitter meta | All 3 title occurrences (title, og:title, twitter:title) now use `settings.site_logo_text` dynamically. |
| `src/pages/feedback.tsx` | Fixed hardcoded title | Was already importing `useSiteSettings`; title now uses `settings.site_logo_text`. |
| `src/pages/dashboard.tsx` | Default tab changed to `stamps`; adds smart switch to `subscriptions` when user has `subscriptionAccess` | Users without subscription access now land on the Stamps tab first. Users with access auto-switch to Subscriptions tab after session loads. |
| `src/pages/dashboard.tsx` line 447 | `SubscribeGuideModal` redirect changed from `/remind` to `/stamp` | The "查看订阅管理页" button now correctly sends users to the brand-claim page (`/stamp`), not the subscription reminder page. Label updated to "前往品牌认领页". |
| `src/pages/[...query].tsx` | No-access subscribe toast now includes actionable `/stamp` redirect | Both subscribe button instances now show a toast with an "Apply / 前往申请" action button linking to `/stamp` when user lacks `subscriptionAccess`, instead of a dead-end info message. |

### v3.1 — Enom TLD Reference Chart Full Integration (2026-03-23)

**Scope:** Complete second pass of `src/lib/lifecycle.ts` corrections using the authoritative Enom TLD Reference Chart (2026-03, 922 lines). All grace/redemption/pendingDelete values for supported TLDs corrected to match Enom registrar data. New TLD entries added.

**Source:** Enom TLD Reference Chart 2026-03 (PDF, 922 lines) — authoritative for gTLDs, nTLDs, and ccTLDs where Enom offers registration.

**Comment block updates (LIFECYCLE_TABLE header):**

| TLD | Before | After | Source |
|---|---|---|---|
| `.be` note | grace 0-20d, RGP=40d | no grace, RGP=30d, 3d pre-expiry deletion | Enom 2026-03 |
| `.ch/.li` note | grace=5d, RGP=40d | no grace, RGP=14d, 10d pre-expiry | Enom 2026-03 |
| `.eu` note | no grace, RGP=40d | no grace, RGP=30d, 3d pre-expiry | Enom 2026-03 |
| `.nl` note | no grace, RGP=40d | no grace, RGP=30d, 3d pre-expiry | Enom 2026-03 |
| `.es` note | RGP=10d | RGP=14d, 12d pre-expiry | Enom 2026-03 |
| `.nz` note | grace=40d, RGP=90d | no grace, RGP=90d, 3d pre-expiry | Enom 2026-03 |
| `.au` note | grace=30d, no RGP | no grace, RGP=31d, 10d pre-expiry | Enom 2026-03 |

**Europe ccTLD corrections:**

| TLD | grace Before→After | rdmp Before→After | Source |
|---|---|---|---|
| `.de` | 10→**0** | 30→30 | Enom 2026-03: N/30 |
| `.nl` | 0→0 | 40→**30** | Enom 2026-03: N/30 |
| `.eu` | 0→0 | 40→**30** | Enom 2026-03: N/30 |
| `.es` | 0→0 | 10→**14** | Enom 2026-03: N/14 |
| `.be` | 10→**0** | 40→**30** | Enom 2026-03: N/30 |
| `.ch` | 5→**0** | 40→**14** | Enom 2026-03: N/14 |
| `.li` | 5→**0** | 40→**14** | Enom 2026-03: N/14 |
| `.am` | grace=30, rdmp=30 | **IMMEDIATE** | Enom 2026-03: N/N |

**Asia-Pacific ccTLD corrections:**

| TLD | grace Before→After | rdmp Before→After | Source |
|---|---|---|---|
| `.sg` | 30→**0** | 30→**14** | Enom 2026-03: N/14 |
| `com/net/org/edu.sg` | 30→**0** | 30→**14** | Enom 2026-03: N/14 |
| `.nz` | 40→**0** | 90→90 | Enom 2026-03: N/90 |
| `co/net/org/school.nz` | 40→**0** | 90→90 | Enom 2026-03: N/90 |
| `.in` | 40→**30** | 30→30 | Enom 2026-03: 30/30 |
| `co/net/org.in` | 40→**30** | 30→30 | Enom 2026-03: 30/30 |
| `.au` (bare TLD) | 30→**0** | 0→**31** | Enom 2026-03: N/31 |
| `.mu` | 30→**40** | 0→**30** | Enom 2026-03: 40/30 |
| `.tm` | grace=30, rdmp=0 | **IMMEDIATE** | Enom 2026-03: N/N |

**Americas ccTLD corrections:**

| TLD | grace Before→After | rdmp Before→After | Source |
|---|---|---|---|
| `.ca` | 40→**30** | 30→30 | Enom 2026-03: 30/30 |
| `.pe` | 30→**0** | 30→**10** | Enom 2026-03: N/10 |
| `com.pe` | 30→**0** | 30→**10** | Enom 2026-03: N/10 |
| `com.mx` | 30→**40** | 30→**0** | Enom 2026-03: 40/N |
| `.hn` | rdmp 0→**30** | — | Enom 2026-03: 30/30 |

**Batch 1 corrections (applied earlier in v3.1):**

| TLD | Change | Source |
|---|---|---|
| `.io` | grace 30→**32** | Enom 2026-03 |
| `.ai` | grace 30→**45** | Enom 2026-03 |
| `.la` | grace 28→**30** | Enom 2026-03 |
| `.tv` | grace 30→**42** | Enom 2026-03 |
| `.ac` / `.sh` | grace 30→**32** | Enom 2026-03 |
| `.vg` | grace 30→**32**, rdmp 30→30 | Enom 2026-03 |
| `.tc` | grace 30→**32**, rdmp 0→**30** | Enom 2026-03 |
| `.sc` / `.mn` / `.fm` / `.ms` / `.gs` / `.tk` / `.bz` | **IMMEDIATE** | Enom 2026-03 |
| `.de` | grace 10→**0** | Enom 2026-03 |
| `.nl` | rdmp 40→**30** | Enom 2026-03 |
| `.eu` | rdmp 40→**30** | Enom 2026-03 |
| `.es` | rdmp 10→**14** | Enom 2026-03 |

**New entries added:**

| TLD | Data | Registry |
|---|---|---|
| `.eus` | grace=45, rdmp=30, pd=5 | PUNTUEUS (Basque Country) |
| `.free` / `.fast` / `.hot` / `.spot` / `.talk` / `.you` | grace=40, rdmp=30, pd=5 | Amazon Registry Services |
| `com/net/org.mu` | grace=40, rdmp=30, pd=5 | ICTA (Mauritius) |

**Other changes:**
- `.inc`: grace corrected 30→42 (Enom 2026-03: 42/30)
- Duplicate `.tc` entry (line 676, old est-confidence entry) removed

---

### v3.0 — TLD Lifecycle Data Accuracy Overhaul (2026-03-23)

**Scope:** Major accuracy corrections to `src/lib/lifecycle.ts` based on cross-referencing Namecheap KB (updated 2025-09-10) and Dynadot TLD pages (verified 2026-03) against the Enom TLD Reference Chart.

**Sources:**
- Namecheap KB: https://www.namecheap.com/support/knowledgebase/article.aspx/9916/2207/tlds-grace-periods
- Dynadot TLD pages: https://www.dynadot.com/domain/[tld]
- Enom TLD Reference Chart: https://docs.google.com/spreadsheets/d/1oVNszsvqhxh3hlT1LYMfcwq3lw_e6J7DeBePvN4t2aw

**Named preset updates:**

| Preset | Before | After | Reason |
|---|---|---|---|
| `STD` (default gTLD) | grace=45, rdmp=30, pd=5 | grace=**30**, rdmp=30, pd=5 | Dynadot: 30d in practice, not 45d max |
| `AFNIC` (.fr etc.) | grace=0, rdmp=30, pd=**10** | grace=0, rdmp=30, pd=**5** | Dynadot verified: .pm/.wf delete=5 |
| `NOMINET` (.uk etc.) | grace=**92**, rdmp=0, pd=**0** | grace=**90**, rdmp=0, pd=**5** | Dynadot: grace=85/5; Namecheap: 90d total |
| `CNNIC` (.cn etc.) | grace=0, rdmp=**14**, pd=5 | grace=0, rdmp=**15**, pd=5 | Dynadot restore=15d |
| `HKIRC` (.hk etc.) | grace=**90**, rdmp=**0**, pd=0 | grace=**30**, rdmp=**60**, pd=0 | Dynadot: grace=30, restore=60 |

**Major TLD corrections:**

| TLD | Before | After | Source |
|---|---|---|---|
| `.de` | IMMEDIATE (0/0/0) | grace=10, rdmp=30, pd=25 | Dynadot: variable grace 0-20d; NOT immediate |
| `.it` | IMMEDIATE | grace=10, rdmp=30, pd=0 | Dynadot: grace=10, restore=30 |
| `.pl` | IMMEDIATE | grace=0, rdmp=30, pd=0 | Dynadot: restore=30 |
| `.no` | IMMEDIATE | grace=89, rdmp=0, pd=0 | Dynadot: 89-day grace |
| `.ie` | IMMEDIATE | grace=30, rdmp=30, pd=14 | Dynadot: grace=30, restore=30, delete=14 |
| `.be` | IMMEDIATE | grace=10, rdmp=40, pd=0 | Dynadot: variable 0-20d grace, restore=40 |
| `.cl` | IMMEDIATE | grace=10, rdmp=30, pd=10 | Dynadot: grace=10, restore=30, delete=10 |
| `.es` | IMMEDIATE | grace=0, rdmp=10, pd=0 | Namecheap: 10-day RGP only, no pendingDelete |
| `.eu` | grace=40, rdmp=0 | grace=0, rdmp=40, pd=0 | Dynadot: no grace, restore=40 |
| `.nl` | grace=40, rdmp=0 | grace=0, rdmp=40, pd=0 | Dynadot: no grace, restore=40 |
| `.ch` | grace=30, rdmp=0, pd=5 | grace=5, rdmp=40, pd=0 | Dynadot: grace=5, restore=40 |
| `.li` | grace=30, rdmp=0, pd=5 | grace=5, rdmp=40, pd=0 | Dynadot: grace=5, restore=40 |
| `.pt` | grace=30, rdmp=0 | grace=29, rdmp=0 | Dynadot: grace=29 |
| `.cz` | grace=30, rdmp=0 | grace=59, rdmp=0 | Dynadot: grace=59 |
| `.ro` | grace=30, rdmp=0 | grace=80, rdmp=0 | Dynadot: grace=80 |
| `.lt` | grace=30, rdmp=30, pd=5 | grace=0, rdmp=30, pd=0 | Dynadot: no grace, restore=30 |
| `.lv` | grace=30, rdmp=30, pd=5 | grace=0, rdmp=30, pd=0 | Dynadot: no grace, restore=30 |
| `.tw` | grace=0, rdmp=30, pd=5 | grace=32, rdmp=0, pd=10 | Dynadot: grace=32, delete=10, no restore |
| `.nz` | IMMEDIATE | grace=40, rdmp=90, pd=5 | Dynadot: grace=40, restore=90 |
| `.hk` | HKIRC (grace=90) | HKIRC (grace=30, rdmp=60) | Preset updated |
| `.in` | grace=30, rdmp=30 | grace=40, rdmp=30 | Dynadot: grace=40 |
| `.id` | grace=30, rdmp=30 | grace=40, rdmp=30 | Dynadot: grace=40 |
| `.ph` | grace=30, rdmp=0, pd=5 | grace=50, rdmp=0, pd=0 | Dynadot: grace=50, delete=0 |
| `.ae` | grace=30, rdmp=30, pd=5 | grace=20, rdmp=0, pd=0 | Dynadot: grace=20, no restore |
| `.cm` | grace=30, rdmp=0, pd=0 | IMMEDIATE | Namecheap: expires = deleted same day |
| `.nu` | grace=45, rdmp=30, pd=5 | grace=7, rdmp=60, pd=0 | Namecheap: 7d then 60d RGP |
| `.gg` | grace=45, rdmp=30, pd=5 | grace=28, rdmp=12, pd=0 | Dynadot: grace=28, restore=12 |
| `.la` | grace=45, rdmp=30, pd=5 | grace=28, rdmp=30, pd=0 | Dynadot: grace=28, no delete |
| `.to` | grace=45, rdmp=30, pd=5 | grace=40, rdmp=30, pd=5 | Dynadot: grace=40 |
| `.fm` | grace=45, rdmp=30, pd=5 | grace=30, rdmp=30, pd=4 | Dynadot: delete=4 |
| `.vg` | grace=45, rdmp=30, pd=5 | grace=30, rdmp=30, pd=4 | Dynadot: delete=4 |
| (all 45d island TLDs) | grace=45 | grace=30 | Dynadot shows 30d for all VeriSign-managed |

**SLD corrections:**
- `.co.nz` / `.net.nz` / `.org.nz` / `.school.nz`: IMMEDIATE → grace=40, rdmp=90, pd=5
- `.com.hk` and all `*.hk`: auto-updated via HKIRC preset
- `.com.ph` / `.net.ph` / `.org.ph`: grace=30/pd=5 → grace=50/pd=0
- `co.in` / `net.in` / `org.in`: grace=30 → grace=40 (matching .in TLD)

---

### v2.9 — Comprehensive TLD Lifecycle Rules Expansion (2026-03-23)

**Scope:** `src/lib/lifecycle.ts` completely rewritten. Table grew from ~150 entries to **634 total entries** (547 TLD-level + 87 SLD-level), covering the vast majority of the global domain namespace.

**Sources consulted:**
- ICANN RAA (standard gTLD: 45d grace / 30d RGP / 5d pendingDelete)
- Namecheap KB: https://www.namecheap.com/support/knowledgebase/article.aspx/9916/2207/tlds-grace-periods
- Dynadot TLD pages: https://www.dynadot.com/domain/tlds.html
- Individual registry policy pages (CNNIC, HKIRC, Nominet, AFNIC, DENIC, auDA, etc.)
- IANA root-zone database

**Accuracy corrections:**

| TLD | Before | After | Source |
|---|---|---|---|
| `.cn` | grace=0, redemption=30, pendingDelete=5 | grace=0, **redemption=14**, pendingDelete=5 | Namecheap KB / CNNIC registry-level RGP |
| `.hk` | grace=0, redemption=30, pendingDelete=5 | grace=**90**, redemption=**0**, pendingDelete=**0** | HKIRC policy (90-day renewal window, no separate RGP) |
| `.ph` | grace=30, redemption=30, pendingDelete=5 | grace=30, redemption=**0**, pendingDelete=5 | PH Domains Foundation — no redemption period |
| `.ly` | grace=30, redemption=0, pendingDelete=0 | **IMMEDIATE** (0/0/0) | LYNIC policy |
| `.au` | grace=0, redemption=0, pendingDelete=5 | grace=**30**, redemption=0, pendingDelete=5 | auDA new top-level TLD (launched 2022) |
| `com.hk` | grace=0, redemption=30, pendingDelete=5 | **HKIRC** (90/0/0) | HKIRC — consistent with .hk |

**New named presets (reusable policy families):**
- `CNNIC` — `.cn` and all `*.cn` sub-TLDs: `{ grace: 0, redemption: 14, pendingDelete: 5 }`
- `HKIRC` — `.hk` and all `*.hk` sub-TLDs: `{ grace: 90, redemption: 0, pendingDelete: 0 }`
- `NOMINET` — `.uk` and all `*.uk` sub-TLDs: `{ grace: 92, redemption: 0, pendingDelete: 0 }`
- `JPRS` — `.jp` and all `*.jp` sub-TLDs: immediate delete `{ grace: 0, redemption: 0, pendingDelete: 0 }`
- `REGISTROBR` — `.br` and all `*.br` sub-TLDs: immediate delete
- `NICAR` — `.ar` and all `*.ar` sub-TLDs: immediate delete

**New TLD categories added:**

1. **Popular new gTLDs (~60)**: `xyz`, `club`, `fun`, `icu`, `top`, `vip`, `wiki`, `ink`, `buzz`, `website`, `uno`, `bio`, `ski`, `ltd`, `llc`, `srl`, `gmbh`, `inc`, `bar`, `fit`, `fan`, `bet`, `best`, `cash`
2. **Business/professional new gTLDs (~150)**: `academy`, `accountant`, `auction`, `bargains`, `bike`, `boutique`, `cafe`, `camera`, `careers`, `casino`, `chat`, `clinic`, `coach`, `codes`, `coffee`, `community`, `condos`, `construction`, `consulting`, `coupons`, `dance`, `dating`, `dental`, `diamonds`, `doctor`, `energy`, `engineering`, `estate`, `financial`, `fitness`, `flights`, `furniture`, `games`, `glass`, `golf`, `graphics`, `guru`, `healthcare`, `hockey`, `homes`, `industries`, `insure`, `investments`, `kitchen`, `legal`, `lighting`, `limited`, `limo`, `loans`, `management`, `marketing`, `mba`, `memorial`, `mortgage`, `movie`, `ninja`, `partners`, `pet`, `photography`, `pizza`, `plumbing`, `productions`, `properties`, `pub`, `racing`, `realty`, `recipes`, `rehab`, `rentals`, `repair`, `restaurant`, `rocks`, `rugby`, `school`, `security`, `sexy`, `shoes`, `singles`, `solar`, `surgery`, `tax`, `taxi`, `technology`, `tennis`, `tips`, `today`, `tours`, `town`, `toys`, `trade`, `training`, `university`, `vacations`, `ventures`, `villas`, `vision`, `voyage`, `wine`, `works`, `wtf`, `zone` (all STD 45/30/5)
3. **Geographic / city new gTLDs (~30)**: `amsterdam`, `barcelona`, `berlin`, `brussels`, `capetown`, `cologne`, `dubai`, `istanbul`, `london`, `miami`, `nagoya`, `nyc`, `okinawa`, `osaka`, `paris`, `quebec`, `rio`, `ryukyu`, `saarland`, `tirol`, `tokyo`, `vegas`, `wien`, `yokohama`, `zuerich`, `boston`, `wales`, `scot`, `irish`, `africa`, `arab`, `nrw` (all STD)
4. **Pacific ccTLDs**: `tl` (Timor-Leste), `fj`, `pg`, `sb`, `vu`, `ki`, `nr`, `ck`, `as`, `pf`, `nc`, `gp`, `mq`
5. **African ccTLDs (~25)**: `mz`, `zw`, `zm`, `ao`, `bi`, `bj`, `bf`, `td`, `cg`, `cd`, `gq`, `gw`, `mr`, `ne`, `tg`, `bw`, `na`, `ls`, `sz`, `mw`, `mg`, `mu`, `km`, `so`, `dj`, `er`, `st`, `cv`, `gn`, `sl`, `lr`
6. **European ccTLDs**: `fo` (Faroe), `mc` (Monaco), `sm` (San Marino), `ad` (Andorra), `gi` (Gibraltar), `im` (Isle of Man), `xk` (Kosovo)
7. **Caribbean/Americas ccTLDs**: `gd`, `dm`, `bb`, `ky`, `bm`, `bs`, `tc`, `kn`, `fk`, `sr`, `aw`, `cw`, `sx`
8. **AFNIC extensions**: `pf`, `nc`, `gp`, `mq` (all managed by AFNIC, same policy as `.fr`)

**New SLD entries (87 total):**

| Country | New SLDs |
|---|---|
| Australia (auDA) | `id.au`, `asn.au`, `edu.au`, `gov.au` (existing `com/net/org.au` kept at 30/30/5) |
| Taiwan (TWNIC) | `com.tw`, `net.tw`, `org.tw`, `idv.tw`, `edu.tw`, `gov.tw` |
| Hong Kong (HKIRC) | `net.hk`, `org.hk`, `idv.hk`, `edu.hk`, `gov.hk` (all 90/0/0) |
| New Zealand (InternetNZ) | `net.nz`, `org.nz`, `school.nz`, `govt.nz` (all IMMEDIATE) |
| Japan (JPRS) | `gr.jp`, `ac.jp`, `go.jp` (all IMMEDIATE) |
| Korea (KISA) | `or.kr` |
| Singapore (SGNIC) | `net.sg`, `org.sg`, `edu.sg`, `gov.sg` |
| Malaysia (MYNIC) | `net.my`, `org.my`, `edu.my` |
| Philippines (PH Domains) | `net.ph`, `org.ph` (no redemption) |
| India (NIXI) | `co.in`, `net.in`, `org.in` |
| Israel (ISOC-IL) | `org.il`, `net.il` |
| South Africa (ZADNA) | `org.za`, `net.za`, `web.za` (all IMMEDIATE) |
| Kenya (KENIC) | `or.ke`, `ne.ke` |
| Nigeria (NIRA) | `org.ng`, `net.ng` |
| Brazil (Registro.br) | `edu.br`, `gov.br` (all IMMEDIATE) |
| Mexico (NIC México) | `org.mx`, `net.mx` |
| Argentina (NIC Argentina) | `net.ar`, `org.ar` (all IMMEDIATE) |
| Ukraine | `com.ua` |
| Turkey (NIC TR) | `org.tr`, `net.tr` (all IMMEDIATE) |
| Venezuela | `com.ve` |
| Colombia | `com.co` |
| Peru | `com.pe` |

---

### v2.8 — CN Reserved Second-Level Domain Detection (2026-03-23)

**Problem:** CNNIC reserves 43 second-level domain labels under `.cn` for official use — 34 provincial administrative codes (bj.cn, sh.cn…), 7 functional suffixes (gov.cn, edu.cn…), and 2 system domains (nic.cn, cnnic.cn). Previously, these were either showing as "已注册" (incorrect) or as a misleading "该域名已注册但注册机构未提供公开的WHOIS/RDAP服务" fallback. The WHOIS lookup took 2.4s+ and returned no useful information.

**New file: `src/lib/whois/cn-reserved-sld.ts`**

Comprehensive database of all 43 reserved CN SLDs with bilingual descriptions, organized into three maps:

| Category | Count | Example |
|---|---|---|
| `CN_PROVINCE_SLDS` — 34 provincial codes | 34 | `bj` → 北京市, `gd` → 广东省 |
| `CN_FUNCTIONAL_SLDS` — sector suffixes | 7 | `gov` → 政府机构, `edu` → 教育机构 |
| `CN_SYSTEM_RESERVED` — exact domains | 2 | `nic.cn`, `cnnic.cn` |

`getCnReservedSldInfo(domain)` checks these in priority order and returns a typed `CnReservedInfo` object (or `null` for non-reserved domains).

**Three-layer interception — in priority order:**

1. **`getServerSideProps` pre-check** (`src/pages/[...query].tsx` line ~1315) — intercepts the raw URL query BEFORE `cleanDomain()` runs. Critical because the lib's `specialDomains` map rewrites functional SLDs (e.g. `gov.cn → www.gov.cn`) to make WHOIS lookups work — without this early check, SSR would look up `www.gov.cn` (a real registered domain) instead of showing "保留域名".

2. **`lookupWhoisWithCache` pre-check** (`src/lib/whois/lookup.ts` line ~504) — the first thing called in the function, before any L1/L2 cache lookup. Ensures no stale Redis-cached result for these domains ever overrides the correct synthetic result.

3. **`/api/lookup` pre-check** (`src/pages/api/lookup.ts` line ~115) — catches client-side searches (typed into the search bar after page load) that hit the API directly.

**Synthetic result format:**

All three interception points return the same structure:
```typescript
{
  time: 0, status: true, cached: false, source: "whois",
  result: {
    domain: "gov.cn",
    status: [{ status: "registry-reserved", url: "" }],
    rawWhoisContent: "[CN Reserved] GOV.CN 是 CNNIC 保留的功能性二级域名...",
    // all other fields: Unknown / null (from initialWhoisAnalyzeResult)
  }
}
```

**UI updates:**

- `DomainStatusInfoCard` now accepts `customDesc?: { zh: string; en: string }` to override the generic "保留域名" description with the domain-specific CNNIC explanation (e.g. "BJ.CN 是 CNNIC 为北京市保留的省级行政区划域名（共34个）...")
- The call site passes `cnInfo` to the card when `regStatus.type === "reserved"`
- Cache header for CN reserved responses: `s-maxage=86400, stale-while-revalidate=604800` (24h/7d)

**Verified results:**

| Domain | Before | After |
|---|---|---|
| `bj.cn` (Beijing province) | ● 已注册 + "no WHOIS" fallback, 2.4s | ● 保留域名 + "BJ.CN 是 CNNIC 为北京市保留…" **0ms** |
| `sh.cn` (Shanghai) | ● 已注册 + "no WHOIS" fallback | ● 保留域名 + specific description **0ms** |
| `gov.cn` (Government) | ● 正常 (showing www.gov.cn data!) | ● 保留域名 + "GOV.CN 是 CNNIC 保留的功能性二级域名…" **0ms** |
| `edu.cn` (Education) | ● 正常 (showing www.edu.cn data!) | ● 保留域名 + "EDU.CN 是 CNNIC 保留的功能性二级域名…" **0ms** |
| `nic.cn` (CNNIC system) | ● 已注册 + "no WHOIS" fallback | ● 保留域名 + "nic.cn 为 CNNIC 系统保留域名…" **0ms** |
| `google.cn` (normal domain) | ● 正常 ✓ | ● 正常 ✓ (no false positive) |

All 43 reserved SLDs now return the correct badge and description in **0ms** with no WHOIS/RDAP network query.

---

### v2.7 — Enhanced Domain Status Detection: Reserved / Prohibited / Suspended (2026-03-23)

**Problem:** Many ccTLD and gTLD registries express special domain states (reserved, prohibited, blocked, suspended) as free-form text in WHOIS responses rather than EPP status codes. The parser only understood structured `Domain Status:` fields, so domains like `com.tw` (WHOIS says "reserved name") were incorrectly shown as **已注册 (Registered)**.

**Two-layer fix:**

**1. `src/lib/whois/common_parser.ts` — Synthetic status injection**

After the normal EPP status deduplication pass, scans the raw WHOIS text for non-EPP state keywords and injects synthetic status entries:

| Pattern matched in raw text | Synthetic status injected | UI result |
|---|---|---|
| `reserved name`, `this name is reserved`, `domain is reserved`, `reserved by the registry`, standalone `reserved` line | `registry-reserved` | 保留域名 (amber) |
| `registration prohibited`, `cannot be registered`, `registration not available`, `not eligible for registration`, `prohibited string`, `registry banned`, `registration blocked` | `registrationProhibited` | 禁止注册 (red) |
| `suspended by registry/registrar`, `registry-suspended`, `domain is suspended` | `suspended` | 暂停 (orange) |

These patterns are conservative — specific enough to avoid false positives in WHOIS legal footer text (e.g. "all rights reserved" does NOT match "reserved name").

**2. `src/pages/[...query].tsx` — `getDomainRegistrationStatus` enhanced**

Added a raw content scan as a safety net, checking both `result.rawWhoisContent` and `result.rawRdapContent` (serialized to string) for the same patterns. This covers RDAP-sourced data where `common_parser.ts` doesn't run.

Also added `suspended` EPP code detection to the hold check: `hasSuspended = allStatusText.includes("suspended") || rawHasSuspended`.

**3. `src/lib/whois/epp_status.ts` — Two new entries**

- `registryreserved` → displayName `registry-reserved`, category `server`  
- `registrationprohibited` → displayName `registrationProhibited`, category `server`

These ensure the EPP status badge in the 状态 section shows correct Chinese/English descriptions instead of the generic "暂无标准释义" fallback.

**4. `src/pages/[...query].tsx` — EPP lock filter robustness fix**

Pre-existing bug: Some WHOIS servers (e.g. TWNIC for `.tw`) emit EPP lock statuses with **spaces** (`"client delete prohibited"`) rather than camelCase or hyphens. The original filter took only `s.split(/\s+/)[0]` ("client") which is not in the EPP lock set, letting the string pass through — and `prohibitCheckText.includes("prohibited")` was then true, incorrectly triggering the **禁止注册** badge for all Google-owned `.tw` domains.

**Fix:** The filter now checks the code against the lock set in TWO additional forms — the raw first-word AND the space/hyphen-stripped concatenated form:
```
"client delete prohibited"
  → noSep = "clientdeleteprohibited" → IN set → filtered ✓
"client-transfer-prohibited"  
  → noSep = "clienttransferprohibited" → IN set → filtered ✓
"clientUpdateProhibited" → toLowerCase → "clientupdateprohibited"
  → noSep = "clientupdateprohibited" → IN set → filtered ✓
```

**Verified results:**

| Domain | Before | After |
|---|---|---|
| `com.tw` | ● 已注册 (WRONG — WHOIS says "reserved name") | ● 保留域名 ✓ |
| `google.tw` | ● 禁止注册 (WRONG — only has EPP lock codes) | ● 正常 ✓ |
| `google.com` | ● 已注册 ✓ | ● 已注册 ✓ (no false positive) |

---

### v2.6 — RDAP-First Optimization: Massive Speed Improvement for 30+ ccTLDs (2026-03-23)

**Root cause identified and fixed:** `STATIC_NO_RDAP` in `src/lib/whois/tld-rdap-skip.ts` was incorrectly listing ~40 ccTLDs that actually have public RDAP endpoints (either via the IANA RDAP bootstrap or via `CCTLD_RDAP_OVERRIDES`). This forced all of them through the slower WHOIS path (2–6s) instead of the fast RDAP path (1–2s).

**1. `src/lib/whois/tld-rdap-skip.ts` — STATIC_NO_RDAP reduced from ~40 → 19 TLDs**

Previously listed as "no RDAP" (incorrectly — all have working RDAP):
- European ccTLDs: `.de`, `.it`, `.pl`, `.hu`, `.ro`, `.bg`, `.gr`, `.sk`, `.no`, `.fi`, `.lt`, `.lv`, `.ua`
- East/SE Asia: `.jp`, `.kr`, `.tw`, `.hk`, `.vn`, `.th`, `.sg`, `.my`, `.id`, `.ph`, `.in`
- ccTLDs with RDAP overrides: `.mm`, `.kh`, `.la`, `.np`, `.ke`, `.gh`, `.tz`, `.ug`, `.et`, `.sn`, `.iq`, `.ly`, `.tr`, `.ae`, `.il`, `.pe`, `.ph`, `.uy`
- Latin America: `.mx`, `.ar`, `.co`, `.cl`, `.pe`, `.za`

Now STATIC_NO_RDAP contains **only genuinely RDAP-less TLDs** (19 total):
`cn, mo, ru, by, kz, ir, sa, lb, eg, ma, dz, tn, bd, lk, ve, ec, bo, py, tl`

**Self-healing safety net:** If a TLD is wrongly absent from the list and RDAP fails at runtime, `markRdapSkipped()` is called automatically — it adds the TLD to the DB-backed runtime skip set, so all future requests go straight to WHOIS. No manual correction needed.

**2. `src/lib/whois/lookup.ts` — Timeout adjustments**

| Constant | Before | After | Reason |
|---|---|---|---|
| `RDAP_TIMEOUT` | 4 000 ms | 3 000 ms | HTTP/JSON servers respond in ≤2 s on Vercel; 3 s is generous |
| `WHOIS_TIMEOUT` | 8 000 ms | 7 000 ms | Reduce max wait time; legitimate slow servers still get 7 s |

**3. `src/lib/whois/rdap_client.ts` — `tryRdapOverride` internal timeout**

`AbortSignal.timeout(12000)` → `AbortSignal.timeout(2500)`. The outer `withTimeout(RDAP_TIMEOUT=3000)` already caps the entire RDAP flow; the internal 12-second signal was redundant and left dangling fetch connections alive for 12 s after the outer timeout fired.

**4. `src/lib/env.ts` — `LOOKUP_TIMEOUT` default aligned**

`8_000` → `7_000` ms — keeps the internal whoiser TCP timeout consistent with the new `WHOIS_TIMEOUT` outer cap.

**Measured results on Vercel-equivalent network (parallel RDAP + WHOIS):**

| TLD | Before | After | Source |
|---|---|---|---|
| `.sg` | ~3–4s (WHOIS) | **1.85s** | RDAP ✓ |
| `.tw` | ~3–4s (WHOIS) | **1.68s** | RDAP ✓ |
| `.jp` | ~3–4s (WHOIS) | **1.07s** (cached) | RDAP ✓ |
| `.de` | ~4.5s (WHOIS) | same | RDAP restricted by DENIC GDPR → auto-marked as rdap_skip |
| `.cn` | ~5–6s (WHOIS) | same | Kept in STATIC_NO_RDAP (no public RDAP) |

---

### v2.5 — Local-First Architecture: Bug Fixes + After-Native Fallback (2026-03-23)

**Three fixes in `src/lib/whois/lookup.ts`:**

1. **Critical bug: `UnhandledPromiseRejection` crash on RDAP-skipped TLDs (`.cn`, `.bf`, `.lu`, `.ye`, etc.)**
   - **Root cause:** `rdapPromise = Promise.reject(...)` when `skipRdap=true`, but no `.catch()` was ever attached. Node.js 15+ crashes the process on any unhandled rejection.
   - **Fix:** Changed to `Promise.resolve(null)` — safe because `rdapPromise` is excluded from `taggedRacers` and never read when `skipRdap=true`.

2. **Architecture overhaul: True "local-first" — third-party only fires after native fails**
   - **Old (broken) behavior:** A 3-second timer would fire `lookupTianhu()`/`lookupYisi()` even while WHOIS was still running (WHOIS timeout = 6s). If WHOIS takes 3–5s (common for legitimate WHOIS servers), third-party would race against it and win. Then `forceTldFallback()` would be called, permanently opening the early gate for that TLD — creating a feedback loop where the system increasingly bypassed native WHOIS in favour of third-party.
   - **New behavior:** `progressiveFallbackRacer` now uses `await Promise.allSettled([rdapPromise, whoisPromise])` — waits for ALL native lookups to genuinely settle (succeed, fail, or timeout) before calling `lookupTianhu()`/`lookupYisi()`. Third-party is truly a last resort.
   - **Bonus:** For TLDs with no WHOIS server, `getLookupWhois` rejects almost instantly ("No WHOIS server responded") so the fallback fires immediately without waiting — actually faster than the old 3s timer for quickly-failing TLDs.
   - **`nativeWon` flag:** Set to `true` when `firstNonNull()` resolves with a native result. The progressive async function checks this after `allSettled` and skips third-party calls if native already won.
   - **`forceTldFallback` preserved:** Still called when progressive wins, since with the new architecture this truly means native completely failed — justified to open the early gate for next time.

3. **WHOIS timeout increased: 6000ms → 8000ms**
   - Many legitimate WHOIS servers (especially for ccTLDs) need 5-7s to respond. Increasing the cap reduces false timeouts and unnecessary fallback gate triggers. RDAP timeout unchanged at 4000ms (HTTP/JSON is faster).

**Architecture summary:**
- `lookupTianhu`: only if `tianhu_enabled=true` in admin config (25/min, 300/day)
- `lookupYisi`: only if `yisi_enabled=true AND yisi_key` set in admin config
- Progressive path: after native settles (not on a timer)
- Early gate: after ≥3 recorded native failures for a TLD (`tld_fallback_stats` table)

---

### v2.4 — Premium Domain Pricing: Accurate API-Based Detection (2026-03-23)

**Two distinct concepts now properly separated:**
- `isPremium` (on pricing) = registry/API confirmed premium-priced TLD (price > $100 USD/EUR/CAD, OR `currencytype === "premium"` from API response)
- `negotiable` = domain name has high resale value (from domain value scoring engine — independent of TLD pricing)

**Changes:**

1. **`src/lib/pricing/client.ts` — `calcIsPremium` improved:**
   - Now also checks `r.currencytype.toLowerCase().includes("premium")` — detects registry-marked premium pricing from the Nazhumi API response field before the price-threshold fallback
   - Ensures both server-side (`getDomainPricing`) and client-side (`getTopRegistrars`) correctly propagate API-reported premium status

2. **`src/pages/[...query].tsx` — `rawPrices` client mapping updated:**
   - Now checks `r.currencytype.toLowerCase().includes("premium")` in addition to price threshold
   - Removed incorrect `result.negotiable === true` conflation from rawPrices

3. **UI — Register/Renew price badges (desktop + mobile):**
   - Normal domains: grey `text-muted-foreground` (unchanged)
   - Registry-premium TLD (isPremium = true): **amber** `text-amber-500` with amber icon
   - Renew price badge now also respects `isPremium` for amber coloring (previously had no isPremium styling)

4. **DomainReminderDialog mini card:**
   - Colors updated: `text-red-500` → `text-amber-500` for consistency with main badge row
   - 溢价 cell background: `bg-red-500/8` → `bg-amber-500/8`
   - 溢价 value: `text-red-500` → `text-amber-500`

**Result:** `ai.dev` — shows grey $4.99 register / $11.62 renew (correct: `.dev` is not a premium-priced TLD), amber "Negotiable: Yes" (correct: high-value domain name). A domain like `.ai` with $100+ registration price would show all pricing in amber.

---

### v2.3 — Full 8-Locale i18n Coverage (2026-03-23)

**Added missing translation keys to all 6 remaining locales (de, ja, ko, ru, fr, zh-tw):**
- `"search"` top-level key added to all 6 locales (was only in en + zh)
- All new nav keys added: `nav_tagline`, `nav_version_menu`, `nav_search_history`, `nav_toolbox`, `nav_login`, `nav_api_docs` + `_desc`, `nav_tlds` + `_desc`, `nav_domain_lookup` + `_desc`, `nav_dns` + `_desc`, `nav_ssl` + `_desc`, `nav_ip` + `_desc`, `nav_icp` + `_desc`, `nav_about` + `_desc`, `nav_sponsor` + `_desc` — all in native language (de/ja/ko/ru/fr/zh-tw)
- Complete `"icp"` section added to all 6 locales (32 keys each) with fully native-language translations: German, Japanese, Korean, Russian, French, Traditional Chinese
- All 8 locales (en, zh, de, ja, ko, ru, fr, zh-tw) now have 100% key coverage for navbar, ICP page, and search functionality — no more English fallbacks for known new keys

**Key count per locale:** each grew from ~402 to ~470 lines (68+ new keys per file)

---

### v2.2 — i18n Complete (2026-03-23)

**Navbar i18n (HistoryDrawer, NavDrawer, UserButton, Navbar):**
- `HistoryDrawer`: DrawerTitle, trigger `aria-label`, status label map (registered/unregistered/reserved/error/unknown), and empty-state title + description all use `t()` — no hardcoded Chinese
- `NavDrawer`: Removed `label`/`labelEn`/`description` fields; replaced with `labelKey`/`descKey` (TranslationKey) referencing `nav_api_docs`, `nav_tlds`, `nav_domain_lookup`, `nav_dns`, `nav_ssl`, `nav_ip`, `nav_icp`, `nav_about`, `nav_sponsor` and their `_desc` variants; version subtitle uses `t("nav_version_menu", {version})`; footer uses `t("nav_tagline")`
- `UserButton`: `aria-label` uses `t("nav_login")`
- `Navbar`: toolbox `aria-label` uses `t("nav_toolbox")`

**ICP page i18n (`src/pages/icp.tsx`):**
- `ICP_TYPES` array: replaced `label` with `tabKey` (`"icp.tab_web"` etc.) — rendered with `t(typeItem.tabKey)`
- `CopyButton`: `title` uses `t("icp.copy")`
- `BlackListBadge`: uses `t("icp.threat_none")` and `t("icp.threat_level", {level})`
- `RecordCard`: all `InfoRow` labels use `t("icp.field_*")` keys; "限制接入" badge uses `t("icp.field_limit")`
- `Pagination`: counter uses `t("icp.results_count", {count})`; page indicator uses `t("icp.page_of", {current, total})`
- `ApiStatusBadge`: all status text uses `t("icp.offline")` / `t("icp.check_status")`
- `IcpPage`: `<title>`, header h1/subtitle, offline banner, type-selector blacklist hint, search placeholder, search button (`t("search")`), loading overlay, error/empty states, results summary badge — all translated
- Added `t` dependency to `handleSearch` useCallback; renamed local `t`/`type` vars to `tp` to avoid shadowing

**Locale additions:**
- `locales/en.json` + `locales/zh.json`: Added `"search"` key at top level (`"Search"` / `"查询"`)

---

## Recent Changes (v2.0 → v2.1)

- **Page transitions**: y-axis slide (y:8→0 enter, y:0→-4 exit) with custom cubic-bezier [0.22,1,0.36,1] at 0.22s for silky-smooth feel
- **Result card stagger**: Main grid uses `CARD_CONTAINER_VARIANTS` (staggerChildren:0.06s) — left and right columns animate in sequence with `CARD_ITEM_VARIANTS` (y:12→0, duration:0.32s)
- **NS row animations**: Each nameserver row is a `motion.div` with spring tap (scale:0.97) and hover nudge (x:2px)
- **Domain title animation**: `motion.h2` with spring tap (scale:0.97) on click-to-copy
- **Search button**: Spring tap (scale:0.9) via `motion.div` wrapper around submit button
- **Hydration fix**: `ResultSkeleton` replaced `Math.random()` widths with deterministic fixed array `[85,72,90,65,80,70]`
- **Glass panel polish**: Added `box-shadow` for depth; dark mode shadow uses black/30
- **CSS utilities added**: `animate-fade-in-up`, `animate-fade-in`, `animate-scale-in`, `stagger-1` through `stagger-5` delay classes
- **DNS tool** (`dns.tsx`): CAA record type added; AnimatePresence for all states; MX priority badges; SOA structured display; 4×DoH resolvers; preset shortcuts (基础解析/邮件安全/域名服务器/证书授权)
- **SSL tool** (`ssl.tsx`): ValidityBar progress component; AnimatePresence for all states; quick examples (google.com/github.com/cloudflare.com); refresh button
- **IP/ASN tool** (`ip.tsx`): AnimatePresence for all states; Yandex static map preview; IPv6 + ASN examples
- **Sponsor page** (`sponsor.tsx`): Full redesign — animated heart hero with floating hearts; Alipay/WeChat QR cards; PayPal button; BTC/ETH/USDT/OKX crypto addresses (CopyButton); "已完成赞助" post-payment form with AnimatePresence; bouncing emoji thank-you section
- **Sponsor submit API** (`/api/sponsors/submit.ts`): Public endpoint — inserts with `is_visible=false` for admin approval
- **Admin settings**: Added PayPal URL + 4 crypto address fields to sponsor section
- **DNS API** (`/api/dns/records.ts`): CAA (type 257) added to RECORD_TYPES, TYPE_NUM, and parseDoHData
- **Docs page** (`docs.tsx`): Three new API sections — `/api/dns/records`, `/api/ssl/cert`, `/api/ip/lookup`

## Tech Stack

- **Framework**: Next.js 14 (Pages Router)
- **Styling**: Tailwind CSS + Shadcn UI + Framer Motion
- **WHOIS**: whoiser library + node-rdap for RDAP queries
- **Caching**: ioredis (Redis)
- **i18n**: next-i18next (EN, ZH, DE, RU, JA, FR, KO)
- **Fonts**: Geist

## Build / Deployment

- **Config**: `next.config.js` (CommonJS, `require`/`module.exports`) — converted from `.mjs` to be compatible with Vercel's `sed`-based build command which patches `next.config.js`
- **TypeScript errors**: `typescript: { ignoreBuildErrors: true }` is pre-applied in the config, so Vercel's sed patch is a harmless no-op
- **Vercel build command**: `sed -i '...' next.config.js && node scripts/migrate.js && pnpm run build`

## Key Files

- `src/lib/whois/lookup.ts` — WHOIS/RDAP orchestration, caching, error detection
- `src/lib/whois/common_parser.ts` — Raw WHOIS text parser, field extraction, data cleaning
- `src/lib/whois/epp_status.ts` — EPP status code mapping with Chinese translations
- `src/lib/whois/rdap_client.ts` — RDAP query client
- `src/pages/api/lookup.ts` — API endpoint
- `src/pages/[...query].tsx` — Result display page
- `src/lib/lifecycle.ts` — Shared TLD lifecycle table (65+ gTLD/ccTLD); used by both frontend and backend for grace/redemption/pendingDelete period computation
- `src/pages/api/remind/submit.ts` — Subscription submission API
- `src/pages/api/remind/process.ts` — Cron processor that fires pre-expiry AND phase-event reminders
- `src/lib/email.ts` — All email templates (welcome, subscription confirm, pre-expiry reminder, phase event)
- `src/lib/admin-shared.ts` — Client-safe admin helpers: `ADMIN_EMAIL` constant and `isAdmin()` function (no Node.js imports)
- `src/lib/admin-server.ts` — Server-only admin helpers: `getAdminEmail()` (reads DB `site_settings.admin_email`, falls back to `ADMIN_EMAIL`), `isAdminEmail()` (async DB-checked comparison)
- `src/lib/admin.ts` — Server-only admin middleware: `requireAdmin()` for API route protection (uses `admin-server.ts` for dynamic email check)
- `src/lib/site-settings.tsx` — Site settings context: `SiteSettingsProvider`, `useSiteSettings()` hook, `DEFAULT_SETTINGS`
- `src/components/admin-layout.tsx` — Shared admin backend layout with sidebar navigation and auth guard
- `src/pages/admin/index.tsx` — Admin dashboard with real-time stats (users, stamps, reminders, searches)
- `src/pages/admin/settings.tsx` — Site settings editor (title, logo, subtitle, description, footer, icon, announcement)
- `src/pages/admin/users.tsx` — User management (search, list, delete)
- `src/pages/admin/stamps.tsx` — Stamp management (search, verify/unverify, delete)
- `src/pages/admin/reminders.tsx` — Reminder management (search, deactivate)
- `src/pages/api/admin/settings.ts` — GET (public) / PUT (admin-only) site settings
- `src/pages/api/admin/stats.ts` — Admin stats endpoint
- `src/pages/api/admin/users.ts` — Admin user management API
- `src/pages/api/admin/stamps.ts` — Admin stamp management API
- `src/pages/api/admin/reminders.ts` — Admin reminder management API
- `src/pages/api/admin/feedback.ts` — Admin feedback management API (GET list, DELETE)
- `src/pages/admin/feedback.tsx` — Feedback viewer: expandable cards with issue type badges, search, delete
- `src/pages/admin/sponsors.tsx` — Sponsor management: add/edit/delete records, visibility toggle, stats, payment QR settings
- `src/pages/api/admin/sponsors.ts` — Sponsor CRUD API (GET public with visible_only, POST/PUT/DELETE admin-only)
- `src/pages/sponsor.tsx` — Public sponsor page: payment QR codes, sponsor list, cumulative stats
- `src/lib/server/rate-limit.ts` — In-process sliding-window rate limiter: `rateLimit(key, limit, windowMs)` + `getClientIp(req)`

## Architecture

The lookup flow: API request → try RDAP → fallback to WHOIS → merge results → if still empty try yisi.yun fallback → cache in Redis → return to client.

### Lookup fallback chain

1. **RDAP** (`node-rdap` + bootstrap) — primary, returns structured JSON
2. **WHOIS** (`whoiser` + custom servers) — secondary, raw text parsed by `common_parser.ts`
3. **yisi.yun API** (`src/lib/whois/yisi-fallback.ts`) — tertiary; only invoked when both RDAP and WHOIS fail or return empty/error data for a domain query. Supports unusual TLDs with no public RDAP/WHOIS server. Zero overhead when native lookups succeed.

## Version History (current: 1.9)

- **v1.9** — Page smoothness: page transition 0.28 s → 0.22 s + ease-out-expo curve, `will-change` GPU hint, `prefers-reduced-motion` full support, smooth scroll, preconnect hints for exchange-rate API / IANA RDAP in `_document.tsx`
- **v1.8** — Lookup speed: WHOIS merge-wait 600 → 350 ms, progressive-fallback trigger 3 500 → 3 000 ms, whoiser eager warm-up at module init, TLD DB calls halved for 2-part domains (tld === tldSuffix deduplication)
- **v1.7** — API security: IP sliding-window rate limiting 40 req/min, GET-only method check, query length ≤ 300 chars, control-char rejection, standard X-RateLimit-* headers; four access-control toggles (disable_login / maintenance_mode / query_only_mode / hide_raw_whois) enforced in navbar + login + _app.tsx + query page

## Data Cleaning Enhancements (2026-03)

Enhanced `common_parser.ts` with:
- **HTML entity decoding**: Handles ccTLD WHOIS servers that return HTML entities in field values (e.g., `Activ&eacute;` → `Activé`)
- **Dot-pattern cleaning**: Strips leading dot sequences used by some ccTLD WHOIS servers as privacy redaction markers (e.g., `............value` → `value`)
- **Redacted value filtering**: Skips contact fields (email, phone, org, country) that are privacy-redacted (high dot ratio, REDACTED/WITHHELD keywords)
- **Universal field cleaning**: Applied to all parsed values via `cleanFieldValue()`

Enhanced `epp_status.ts` with:
- **Expanded status map**: 50+ status codes covering standard EPP + ccTLD-specific variants
- **Multi-language status support**: French (Activé, Enregistré, Supprimé, Expiré), German (registriert, aktiv, gesperrt, gelöscht), Spanish/Portuguese (registrado, activo, ativo), Dutch (actief, geregistreerd), Italian (registrato), Turkish (kaydedildi), etc.
- **Robust normalization**: Two-pass lookup — first tries with accented characters preserved, then falls back to ASCII-folded form
- **New categories**: Added `unknown` category for unregistered/available status codes
- **More EPP statuses**: quarantine, dispute, abuse, withheld, pendingPurge, verificationFailed, courtOrder, etc.

## Custom WHOIS Server Management (2026-03)

Added local WHOIS server management without touching rdap/whoiser libraries:

- **`src/lib/whois/custom-servers.ts`** — Extended server entry types:
  - `string` → TCP hostname (legacy, port 43)
  - `{ type: "tcp", host, port? }` → TCP with optional custom port
  - `{ type: "http", url, method?, body? }` → HTTP GET/POST with `{{domain}}` placeholder
- **`src/lib/whois/lookup.ts`** — Added:
  - `queryWhoisTcp()` — raw Node.js `net` TCP connection for non-43 ports
  - `queryWhoisHttp()` — fetch-based HTTP WHOIS query with URL template substitution
  - Updated `getLookupWhois()` to dispatch based on entry type
- **`src/pages/api/whois-servers.ts`** — GET/POST/DELETE API for managing custom servers (no auth required)
- **`src/pages/whois-servers.tsx`** — Full UI management page accessible via navbar "Servers" link
- **`src/data/custom-tld-servers.json`** — User-editable server map (persisted on disk)

Priority order: user custom servers → built-in servers → ccTLD servers → whoiser default discovery.

### ScraperEntry type (2026-03)

Added `{ type: "scraper", name, registryUrl }` entry type for TLDs that require multi-step HTTP scraping (e.g. CSRF tokens + cookies):
- **`src/lib/whois/http-scrapers/nic-ba.ts`** — Dedicated scraper for .ba (Bosnia) via nic.ba. Performs GET+POST form submission; fails gracefully when reCAPTCHA v2 blocks automated access.
- **`ScraperRequiredError`** — Custom error class in `lookup.ts` that carries `registryUrl` for propagation to the API response.
- **`WhoisResult.registryUrl`** — New optional field on `WhoisResult` type passed through to the API `Data` type.
- **Frontend** — Shows "Look up at Registry" button (with external-link icon) in both the "registered but no WHOIS" panel and the generic error fallback panel whenever `registryUrl` is present.
- **`.ba` fix** — Removed wrong `"ba": "whois.ripe.net"` mapping from `cctld-whois-servers.json` (set to `null`). Now .ba domains correctly show DNS-probe–based registration status + registry link.
- **Null filter** — `getAllCustomServers()` now filters out null values from cctld-whois-servers.json so BUILTIN_SERVERS entries can take precedence.

## Vercel / Edge Platform Deployment

The app is production-ready for Vercel and similar serverless platforms.

### Key configuration files:
- **`vercel.json`** — Function maxDuration per route (30s for lookup, 10s for others)
- **`.env.example`** — All required environment variables documented

### Environment variables for production:
| Variable | Required | Default | Description |
|---|---|---|---|
| `POSTGRES_URL` | **Yes** | — | Supabase/Neon PostgreSQL pooling URL |
| `POSTGRES_URL_NON_POOLING` | **Yes** | — | Direct connection for migrations |
| `NEXTAUTH_SECRET` | **Yes** | — | Random secret for JWT signing (`openssl rand -base64 32`) |
| `NEXTAUTH_URL` | **Yes** | — | Production URL e.g. `https://your-app.vercel.app` |
| `RESEND_API_KEY` | **Yes** | — | Resend API key for sending emails |
| `RESEND_FROM_EMAIL` | **Yes** | `noreply@x.rw` | Verified sender address on Resend |
| `NEXT_PUBLIC_BASE_URL` | Recommended | NEXTAUTH_URL | Base URL used in email links |
| `CRON_SECRET` | Recommended | — | Protects cron jobs; Vercel sends as `Authorization: Bearer` |
| `WHOIS_TIMEOUT_MS` | No | 4000 | WHOIS query timeout in ms (keep ≤ 7000 on Hobby plan) |
| `RDAP_TIMEOUT_MS` | No | 5000 | RDAP query timeout in ms |
| `FALLBACK_START_MS` | No | 1200 | ms delay before 3rd-party fallback starts racing native lookups |
| `NEXT_PUBLIC_MAX_WHOIS_FOLLOW` | No | 0 | WHOIS follow depth (0 = fastest) |
| `REDIS_URL` | No | — | Redis connection URL (optional caching) |
| `REDIS_CACHE_TTL` | No | 3600 | Result cache TTL in seconds |

See `.env.example` for complete reference with comments.

### Redis storage:
- Lookup results cached at key `whois:{query}` with TTL from `REDIS_CACHE_TTL`
- User-managed custom WHOIS servers stored at key `whois:user-servers` (no TTL — persistent)
- Without Redis, custom servers fall back to `src/data/custom-tld-servers.json` (local only)

### Vercel plan considerations:
- **Hobby plan (10s limit)**: Default `WHOIS_TIMEOUT_MS=4000` + `RDAP_TIMEOUT_MS=5000` keeps total request time well under 10s.
- **Pro plan (300s limit)**: Can safely increase `WHOIS_TIMEOUT_MS=7000` for maximum ccTLD WHOIS coverage.

## Brand Claim (品牌认领) & Domain Subscription (域名订阅)

### New Pages
- `src/pages/stamp.tsx` — Brand Claim page with DNS TXT ownership verification (3-step flow: form → verify → done)
- `src/pages/remind/cancel.tsx` — Subscription cancellation page (reads `?token=` param, calls cancel API)

### New API Routes
- `src/pages/api/stamp/submit.ts` — Submit a stamp claim; returns `txtRecord` and `txtValue` for DNS TXT verification
- `src/pages/api/stamp/check.ts` — Query verified stamps for a domain
- `src/pages/api/stamp/verify.ts` — DNS TXT + HTTP file verification (multi-resolver, DoH fallback, fuzzy match)
- `src/pages/api/vercel/add-domain.ts` — Register domain with Vercel project; returns `_vercel` TXT record for ownership proof
- `src/pages/api/vercel/check-domain.ts` — Poll Vercel verify endpoint; updates stamp as verified if DNS propagated
- `src/pages/api/remind/submit.ts` — Subscribe to domain expiry reminders
- `src/pages/api/remind/cancel.ts` — Cancel a subscription via cancel token (returns JSON)
- `src/pages/api/remind/process.ts` — Cron job: sends reminder emails via Resend, marks sent records

### Libraries
- `src/lib/supabase.ts` — Supabase JS client singleton (REST-based, works from any network)
- `src/lib/db.ts` — Retained for pg Pool schema definitions (TABLES array); pg Pool only used on Vercel where TCP is allowed
- `src/lib/rate-limit.ts` — In-memory IP rate limiter (5 req/min per IP, auto-cleanup)

### Database Architecture
All API routes use `@supabase/supabase-js` (HTTP/REST) via `src/lib/supabase.ts`.
This allows the app to connect to Supabase from **any network** (Replit dev, Vercel production) 
without requiring direct TCP access to PostgreSQL port 5432/6543.

Required Supabase tables — **created automatically by `scripts/migrate.js` on each Vercel build**:
- `users` — user accounts for auth
- `password_reset_tokens` — password reset tokens (60-min expiry, single-use)
- `stamps` — brand claiming records
- `reminders` — domain expiry reminder subscriptions (`phase_flags TEXT` column required — run migration below)
- `reminder_logs` — tracking which reminder thresholds have been sent
- `tool_clicks` — global aggregate click counts per tool URL
- `user_tool_clicks` — per-user click counts for personalized sorting
- `search_history` — per-user search history (last 50 queries)

### Environment Variables Required
| Variable | Required | Description |
|---|---|---|
| `SUPABASE_URL` | Yes | Supabase project URL (e.g. `https://xxxx.supabase.co`) |
| `SUPABASE_SERVICE_KEY` | Yes | Supabase service role key (from project Settings → API) |
| `NEXTAUTH_SECRET` | Yes | Random secret for NextAuth JWT signing |
| `RESEND_API_KEY` | Yes | Resend API key for sending reminder/reset emails |
| `RESEND_FROM_EMAIL` | No | Sender address for emails (defaults to `noreply@x.rw`) |
| `NEXT_PUBLIC_BASE_URL` | Yes | Public URL for cancel/reset links in emails |
| `CRON_SECRET` | Recommended | Secret token to protect `POST /api/remind/process` |
| `VERCEL_API_TOKEN` | Yes (Vercel verify) | Vercel API token for domain verification |
| `VERCEL_PROJECT_ID` | Yes (Vercel verify) | Vercel project ID (`prj_...`) |
| `POSTGRES_URL_NON_POOLING` | Vercel only | Direct Supabase connection for pg Pool migrations |

### Pending DB Migrations
Run in **Supabase Dashboard → SQL Editor**:
```sql
-- Add phase_flags column to reminders table (phase event notification preferences)
ALTER TABLE reminders ADD COLUMN IF NOT EXISTS phase_flags text DEFAULT NULL;
```
The column is optional — the code defaults all phase flags to `true` if the column is missing or null, so existing subscriptions are unaffected until users re-subscribe.

### Cron Setup
To trigger reminder emails automatically, set up a cron job (e.g. daily) to call:
```
GET /api/remind/process?secret=<CRON_SECRET>
```
Or with a header:
```
GET /api/remind/process
x-cron-secret: <CRON_SECRET>
```

## IDN / Chinese Domain Handling

- **WHOIS punycode conversion**: `getLookupWhois` converts non-ASCII domains (e.g., `亲爱的.中国`) to their punycode equivalents (e.g., `xn--7lq487f54c.xn--fiqs8s`) via `domainToASCII()` before querying the WHOIS server
- **DNS probe punycode**: `probeDomain` similarly converts IDN inputs to punycode before DNS lookups
- **"No matching record" = available**: When WHOIS returns a "no match / not found" type response (pattern set `WHOIS_NOT_REGISTERED_PATTERNS`), the code treats this as "domain available" rather than a lookup failure — skipping the DNS fallback probe (which gives false positives for TLDs with wildcard A records like `.中国`). Yisi.yun is still tried first; if it fails, the domain is returned with `dnsProbe.registrationStatus: "unregistered", confidence: "high"` so the AvailableDomainCard is shown correctly.

## Dev Server

Runs on port 5000 via `pnpm run dev` (next dev -p 5000 -H 0.0.0.0).

## Tian.hu (田虎) Integration

Free public API (25 req/min, 300 req/day), no auth required.

### Integrated Features

| Feature | Endpoint | Usage |
|---------|----------|-------|
| WHOIS fallback | `/whois/{domain}` | `src/lib/whois/tianhu-fallback.ts` (tried before yisi.yun) |
| Domain pricing | `/tlds/pricing/{tld}` | `src/lib/pricing/client.ts` (3rd source, merged) |
| Translation | `/translate/{stem}` | `src/pages/api/tianhu/translate.ts` → shown on result page |
| DNS records | `/dns/{domain}` | `src/pages/api/tianhu/dns.ts` → shown on result page |

### Result Page Display

**Translation strip** (`[...query].tsx`):  
- Fetched client-side via `useEffect` when domain changes
- Displayed horizontally between "time·source" row and dates section
- Shows: "含义 **{zh translation}** {pos tag} {meaning}" in violet
- Only shown when `dst !== null` (omits pure-numeric domains, IPs)

**DNS Records card** (`[...query].tsx`):
- Shown after the WHOIS Name Servers card
- Displays A, NS, MX, SOA, TXT, AAAA records with TTL
- Skeleton loading animation while fetching
- Records animate in staggered with opacity

### Anti-Flicker Improvements

- ResultSkeleton now wrapped in `AnimatePresence` with opacity 0→1/0 transitions (no abrupt switch)
- Main result cards use pure `opacity` animation (no scale → no "pop" effect)
- Async-loaded sections (translation, DNS) animate in smoothly without layout shift

## Database Schema (Full Table List)

All persistent state lives in PostgreSQL (`src/lib/db.ts`). Tables auto-created on startup via `runMigrations()`.

| Table | Purpose |
|-------|---------|
| `users` | Registered accounts — email, password_hash, disabled, avatar_color, email_verified, etc. |
| `password_reset_tokens` | Secure time-limited reset links |
| `stamps` | Domain brand claims, awaiting admin verification |
| `reminders` | Domain expiry alert subscriptions |
| `reminder_logs` | Tracks which reminder phases have been sent (dedup) |
| `tool_clicks` | Aggregate link-click counts for Tools/Links pages |
| `user_tool_clicks` | Per-user link-click history |
| `search_history` | All queries (user_id nullable — anonymous queries also recorded) |
| `feedback` | User-submitted issue reports |
| `site_settings` | Key-value admin settings (title, OG, API keys, announcements) |
| `tld_fallback_stats` | Per-TLD failure tracking; enables 3rd-party fallback after 3 consecutive failures |
| `custom_whois_servers` | Admin-managed custom WHOIS server overrides (JSONB per TLD) |
| `rate_limit_records` | DB-backed rate limiting (key = IP, count + reset_at per 60s window) |

**Concurrent migration guard**: `getDbReady()` uses a shared Promise lock (`global.__pgMigrating`) so parallel Next.js requests on cold start never trigger duplicate migrations.

## Rate Limiting

`src/lib/rate-limit.ts` — DB-backed with in-memory fast-path:
- Hot path: in-memory Map for IPs seen within current server process window
- Cold path: atomic `INSERT … ON CONFLICT DO UPDATE` into `rate_limit_records`
- Fallback: pure in-memory if DB unavailable
- `checkRateLimit(ip, maxRequests)` is now `async` — all call sites use `await`

## TLD Smart Fallback Gate

`src/lib/whois/tld-fallback-gate.ts` — prevents over-reliance on paid 3rd-party APIs:
- Tracks per-TLD failure count in `tld_fallback_stats`
- Native RDAP/WHOIS failures increment count; success resets to 0
- Third-party APIs (tianhu / yisi) only invoked when `fail_count >= 3` AND `use_fallback = true`
- Admin UI: `/admin/tld-fallback` — view stats, toggle fallback per TLD, bulk clear

## v2.0 — UI Micro-Interactions

- **Button press feedback**: `Button` base class gains `active:scale-[0.96] touch-manipulation select-none` — all buttons scale slightly on press
- **Spring physics clicks**: `src/components/motion/clickable.tsx` — `<Clickable>` wraps any child with a Framer Motion spring (stiffness 600 / damping 32 / mass 0.6) for a natural squish-and-release feel
- **TLD page tab animation**: `AnimatePresence mode="wait"` with x-slide + fade between "TLD List" and "WHOIS Servers" tabs (0.22s ease-out-expo)
- **Server row edit expansion**: Inline edit form animates open/closed with `height: 0 → auto` via `motion.div`; row → form swap is wrapped in per-row `AnimatePresence mode="wait"`
- **Add-server form**: Same height animation via `AnimatePresence` wrapping the `showAdd` conditional
- **Global tap delay elimination**: `globals.css` adds `touch-action: manipulation` to all `button`, `a`, `[role="button"]`, `select` elements — removes 300 ms iOS tap delay everywhere

## Admin Backend Pages

| Page | Route |
|------|-------|
| Dashboard | `/admin` |
| Users | `/admin/users` |
| Brand Claims | `/admin/stamps` |
| Reminders | `/admin/reminders` |
| Search Records | `/admin/search-records` |
| User Feedback | `/admin/feedback` |
| TLD Fallback Stats | `/admin/tld-fallback` |
| System Status | `/admin/system` |
| API Keys | `/admin/api` |
| Site Settings | `/admin/settings` |
| Invite Codes | `/admin/invite-codes` |
| Friendly Links | `/admin/links` |

## Admin-Managed Content (v2.0)

### Friendly Links (`/links`)
- Fully DB-backed: `friendly_links` table (id, name, url, description, category, sort_order, active)
- Public API: `/api/links` (GET active links, sorted by sort_order then id)
- Admin CRUD: `/api/admin/links` (GET/POST/PUT/DELETE)
- Admin page: `/admin/links` — create/edit/delete/toggle visibility, optional category grouping
- Links page groups by category, shows empty state when no links added
- Subtitle and title customizable via `links_title` / `links_content` in site settings

### About Page (`/about`)
- Chinese intro (`about_content`), English intro (`about_intro_en`) — both editable in admin settings
- Contact email (`about_contact_email`) — shown as a mailto link on about + links pages
- GitHub URL (`about_github_url`) — shown in tech stack section
- Thanks/acknowledgements (`about_thanks`) — JSON array `[{name, url, desc, descEn}]`, falls back to hardcoded defaults
- All fields editable via Admin Settings → 关于页面 section

## Domain Subscription Enhancement (v2.0)

### DB-Configurable TLD Lifecycle Rules
- `tld_lifecycle_overrides` table: admin-set grace/redemption/pendingDelete days per TLD
- `src/lib/server/lifecycle-overrides.ts`: 5-minute in-memory cache; `loadLifecycleOverrides()` + `invalidateLifecycleOverridesCache()`
- `getTldLifecycle()` and `computeLifecycle()` in `lifecycle.ts` accept optional `overrides` dict; DB values take priority over hardcoded table
- Admin API: `/api/admin/tld-lifecycle` — GET list, POST create (id auto-gen), PATCH update, DELETE; all writes call `invalidateLifecycleOverridesCache()`
- Admin page: `/admin/tld-lifecycle` — searchable table, add/edit/delete dialog, shows TLD + days + registry + built-in comparison

### Drop Notifications (v2.0)
- `dropApproachingHtml` + `domainDroppedHtml` templates added to `src/lib/email.ts`
- `DROP_SOON_KEY = -4`: sent when `phase === pendingDelete` AND `daysToDropDate <= 7` (not already sent)
- `DROPPED_KEY = -5`: sent when `phase === dropped` → notification then deactivate subscription
- `process.ts` loads overrides once per cron run, passes to all `computeLifecycle()` calls

### Subscription API & Dashboard Upgrade
- `/api/user/subscriptions` GET now returns computed lifecycle fields per subscription: `drop_date`, `grace_end`, `redemption_end`, `phase`, `days_to_expiry`, `days_to_drop`, `tld_confidence`
- `dashboard.tsx` removed local 13-TLD `LIFECYCLE` table + `getDomainLifecycle()` — lifecycle data now comes from the API using the full 200+ TLD table
- `urgentSubs` now includes subscriptions where `days_to_drop <= 7` (approaching drop date)
- Subscription cards show purple "X天后可抢注" badge when approaching drop; drop date rendered in purple when urgent

## Registration Security (v2.0)

### Invite Code System
- `invite_codes` table: `XXXXXX-XXXXXX-XXXXXX` uppercase codes, single-use
- `require_invite_code = "1"` site setting gates registration behind invite codes
- `subscription_access` + `invite_code_used` columns on users
- Existing users can apply codes from Dashboard → Subscription tab
- Admin API: `/api/admin/invite-codes` (GET list, POST create, DELETE by id)

### Email OTP Verification
- `/api/user/send-verify-code` — sends 6-digit code via Resend, stored in Redis (`verify:register:{email}`)
- 10-minute TTL, 60-second resend rate limit (`verify:rate:{email}`)
- Register page shows email field + "发送验证码" button with 60s countdown
- OTP input appears after code is sent; register API validates before creating account

### CAPTCHA (Human Verification)
- Provider, site key, secret key stored in `site_settings` (`captcha_provider`, `captcha_site_key`, `captcha_secret_key`)
- `captcha_secret_key` filtered from public GET; returned only for admin session
- `src/lib/server/captcha.ts` — `getCaptchaConfig()` + `verifyCaptchaToken()` supporting Turnstile and hCaptcha
- Register page: loads CAPTCHA script dynamically (explicit render mode), shows widget after invite code field
- Register API: verifies token server-side before account creation
- Admin Settings → 人机验证: provider dropdown, site key input, secret key (password) input

## Admin Backend Comprehensive Enhancement (2026-03-24)

### Critical Bug Fixes
- **Refund auto-revokes subscription**: `mark_refunded` in `/api/admin/payment/orders.ts` now also sets `subscription_access=FALSE` on the user (by `user_id` first, then `user_email` fallback). Returns `subscriptionRevoked: true` flag so UI can show a relevant toast.

### Cross-Page Deep Links
- **Orders → Users**: User email/name in orders list is now a clickable button that navigates to `/admin/users?search=EMAIL`
- **Users → Orders**: Edit modal has a "订单" button that navigates to `/admin/payment/orders?search=EMAIL`
- **URL pre-population**: Both orders and users pages read `?search` query param on mount to pre-fill search input when navigated from cross-links

### Inline Confirm Dialogs (replace native browser `confirm()`)
- **Users page delete**: First click on trash icon shows inline "确认删除 | ✕" row. Second click executes. Auto-clears after 4 seconds.
- **Orders page actions**: First click on mark-paid / refund shows inline amber warning banner "再次点击确认". Auto-clears after 4 seconds.
- **Feedback page delete**: Same inline confirm pattern with 4-second auto-cancel.

### Users Page CSV Export
- "导出 CSV" button in header exports all currently-loaded users with UTF-8 BOM for Excel compatibility
- Fields: email, name, registration time, email_verified, subscription_access, disabled, search_count, stamp_count, reminder_count, admin_notes

### Orders Stats — Per-Currency Revenue
- Stats query now groups by currency; returns `byCurrency: [{currency, revenue, count}]`
- UI shows single value for single-currency setups, per-currency table for multi-currency
- Added "已退款" count stat card alongside total/paid

### Dashboard Refresh Button
- `/admin/index.tsx`: refresh icon button next to "系统概览" heading; triggers `loadStats()`; spins during load

### Missing AdminLayout Titles Fixed
- `changelog.tsx`: `<AdminLayout title="更新日志">`
- `og-styles.tsx`: `<AdminLayout title="OG 卡片样式">`

### OG Styles SSP Auth Fixed
- `og-styles.tsx` used `requireAdmin` (API-route style) from `getServerSideProps` causing `res.status is not a function` 500 error
- Fixed to use `getServerSession` + `isAdmin` directly with proper SSR `redirect` instead

### Feedback Page Enhancements
- Reply-by-email button (envelope icon) appears on hover next to delete; opens pre-filled mailto: with domain in subject
- Expanded panel now shows: user description + action buttons ("复制域名", "RDAP 查看", "回复 EMAIL")
- All in-place confirm dialogs replace native `confirm()` calls

### v3.3 — Hot Prefix System + Enhanced Admin Email Alerts

**Scope:** Hot prefix monitoring watchlist, AI analysis in admin email alerts, removal of domain value display from public frontend.

**Changes:**

| File | Change | Detail |
|---|---|---|
| `src/pages/[...query].tsx` | Removed AI panel and domain value score strip from `AvailableDomainCard` | Domain value scoring / AI analysis is admin-only; removed all state, functions, and JSX. Public users see no score. |
| `src/pages/api/admin/hot-prefixes.ts` | New CRUD API | `GET`/`POST`/`PATCH`/`DELETE`; auto-creates `hot_prefixes` table; `?action=seed` imports 90+ built-in prefixes; Redis cache invalidation. |
| `src/pages/admin/hot-prefixes.tsx` | New admin UI at `/admin/hot-prefixes` | CRUD table: add/edit/delete prefixes, enable/disable toggle, category filter pills, 30-day hit counter, seed button. |
| `src/components/admin-layout.tsx` | Added "热门前缀" nav item | Flame icon, Config group. |
| `src/lib/server/hot-prefix-cache.ts` | New server-side hot prefix cache | In-process 1-min + Redis 5-min cache; `checkHotPrefix(sld)` / `getHotPrefixBoost(name)`. |
| `src/lib/server/domain-value-ai.ts` | Fixed imports; AI analysis module working | `analyzeDomainWithAi(domain)` with 7-day Redis cache. |
| `src/lib/email.ts` | Enhanced alert email | Added `hotPrefix` match section (orange) and `aiSummary` section (violet) to `highValueAlertHtml`. |
| `src/pages/api/lookup.ts` | Enhanced `maybeSendHighValueAlert` | Hot prefix check + AI summary (8s timeout); alert for hot prefix even below score threshold. |
| `src/pages/api/user/search-history.ts` | Same alert enhancement | Mirrors lookup.ts logic. |

**Hot Prefix Table:** `hot_prefixes` (id, prefix, category, weight, source, sale_examples, notes, enabled, hit_count, created_at, updated_at)
**Alert subject prefixes:** 🔥 热门前缀可用 / ⚡ 特殊关键词可用 / 💎 高价值域名可用

## UI/UX Polish & i18n Hardening (2026-03-28)

### i18n Completeness

**Scope:** Eliminated all hardcoded Chinese/English strings across public-facing components.

| File | Change |
|---|---|
| `locales/{en,zh,zh-tw,de,fr,ja,ko,ru}.json` | Added `nav_faq`, `nav_privacy`, `nav_terms`, `maintenance_title`, `maintenance_refresh`, `maintenance_tip_0..4`, `close_announcement` keys to all 8 locale files |
| `src/pages/_app.tsx` | `AnnouncementBanner` close button uses `t("close_announcement")`; `MaintenanceGate` title/button/tips use `t()` |
| `src/pages/faq.tsx`, `privacy.tsx`, `terms.tsx` | Page `<title>` uses `t("nav_faq")`, `t("nav_privacy")`, `t("nav_terms")` |
| `src/lib/email.ts` | Email `lang="und"` (was "zh"), bilingual footer (中文 + English), Privacy + Terms links, cancel text bilingual |

### Navbar Animation

**File:** `src/components/navbar.tsx`
- `<nav>` → `<motion.nav>` using Framer Motion `animate` prop
- Custom cubic-bezier `[0.22, 1, 0.36, 1]` spring on y/opacity/scale
- Replaces CSS `transition-all` class toggling

### Auth Pages Visual Redesign

**Files:** `src/pages/login.tsx`, `src/pages/register.tsx`

Both pages share the same design language:
- **Ambient glow:** Absolute-positioned `violet-500/5` blur circle behind content
- **Icon:** `motion.div` with scale-in animation, `blur-xl` glow halo underneath, `w-16 h-16` rounded-2xl with gradient background
- **Form card:** `glass-panel` + `border-border/80` + `overflow-hidden` (for accent bar); thin `h-0.5` gradient accent bar (`from-transparent via-primary/40 to-transparent`) at card top
- **Entry animation:** `ease: [0.22, 1, 0.36, 1]` throughout (matching navbar)
- **Password toggle:** `aria-label` added for screen reader compatibility

### Maintenance Page Improvements

**File:** `src/pages/_app.tsx` (`MaintenanceGate`)
- All Chinese strings extracted to i18n keys
- Wrench icon: `maintenance-wrench` CSS keyframe (rotation) replaces `animate-bounce`
- Tips rendered from `MAINTENANCE_TIP_KEYS` array with `as const` for TypeScript compatibility

### AvailableDomainCard Design (query results page)

**File:** `src/pages/[...query].tsx`

Redesigned available/premium domain card:
- Gradient accent bar (emerald for available, amber for premium)
- Circular icon with colored ring and appropriate check/crown icon
- Status badge with animated dot indicator
- Bilingual descriptions support `isZh` locale detection
- Registrar price comparison table with "Best price" highlight
- Registration tips section with colored bullet dots

### Accessibility Improvements

- `src/pages/login.tsx`: Password visibility toggle button has `aria-label={showPwd ? "Hide password" : "Show password"}`
- `src/pages/register.tsx`: Same password visibility toggle aria-label
- `src/components/navbar.tsx`: Key nav buttons retain `aria-label` using i18n keys

## System Integration Audit & Fixes (2026-03-29)

### 7 Data-Flow Disconnects Fixed

A system-wide audit identified 7 disconnects where data was collected but never consumed, or admin tools existed without corresponding UIs. All have been resolved:

#### 1. `tld_registry_info.whois_server` now used in lookups
**File:** `src/lib/whois/custom-servers.ts`
- Added `readRegistryInfoServers()` that queries `tld_registry_info WHERE whois_server IS NOT NULL`
- Added as the lowest-priority layer in `getAllCustomServers()` — fills gaps for TLDs not in static files
- Server priority (highest wins): DB (`custom_whois_servers`) > BUILTIN > `cctld-whois-servers.json` > `tld_registry_info`
- Previously: admin scraped IANA registry info but the `whois_server` field was never used by the lookup engine

#### 2. Repair success now resets `tld_fallback_stats`
**File:** `src/lib/whois/server-failure-tracker.ts`
- `markTldRepaired()` now also runs `UPDATE tld_fallback_stats SET fail_count=0, use_fallback=false WHERE tld=$1`
- Previously: repair queue saved a working server but the TLD remained in "use_fallback" mode → next query still went to yisi/tianhu instead of the newly discovered native server

#### 3. Custom WHOIS Servers admin page created
**File:** `src/pages/admin/custom-servers.tsx`
- Shows all WHOIS servers with source badges: 数据库 / 内置 / ccTLD文件 / 注册局信息
- DB-managed entries can be added and deleted; other sources are read-only
- Stats cards filterable by source; search + filter bar
- Previously: `/api/admin/tld-servers.ts` existed but had no corresponding admin page

#### 4. TLD Probe now saves results to custom servers
**File:** `src/pages/admin/tld-probe.tsx`
- Per-row "保存" button for rdap/whois probe results → calls `/api/admin/tld-servers` POST
- "保存所有成功结果" batch button saves all rdap+whois results at once
- Previously: probe results were displayed but discarded; next lookup didn't benefit

#### 5. Admin API enhanced for source tracking
**File:** `src/pages/api/admin/tld-servers.ts`
- GET now returns `registryServers` (from `tld_registry_info`) + `builtinTlds` (BUILTIN_SERVERS keys)
- POST now accepts full `CustomServerEntry` objects (not just plain strings)
- Exported `BUILTIN_SERVER_TLDS` and `getRegistryInfoServers()` from `custom-servers.ts`

#### 6. Unified TLD tab navigation across all 7 admin pages
**Files:** `tld-fallback.tsx`, `tld-lifecycle.tsx`, `tld-rules.tsx`, `tld-lifecycle-feedback.tsx`, `repair-queue.tsx`, `tld-probe.tsx`, `tld-registry.tsx`
- All pages now share 8 tabs: 生命周期 / TLD规则 / 查询兜底 / 纠错反馈 / 服务器修复 / **自定义服务器** / TLD探测 / 注册局信息
- `tld-probe.tsx` and `tld-registry.tsx` had no tab navigation before; now unified

#### 7. Admin home page updated
**File:** `src/pages/admin/index.tsx`
- Added "自定义服务器" and "注册局数据库" to the admin navigation grid
- Both pages were previously inaccessible from the admin home

#### Bonus: Registry info → Custom servers one-click save
**File:** `src/pages/admin/tld-registry.tsx`
- Hover over any WHOIS server value in the registry table → shows "保存到自定义服务器" button
- Promotes scraped registry data to explicit DB entry (overrides the auto-derived registry layer)

### Data Flow After Integration

```
Lookup request
  → getCustomServerEntry(tld)
  → getAllCustomServers()
       1. readRegistryInfoServers()     ← tld_registry_info (NEW)
       2. BUILTIN_SERVERS              ← hard-coded
       3. cctld-whois-servers.json     ← static file
       4. custom_whois_servers DB      ← user/repair-queue managed (highest)

Repair queue finds server
  → setCustomServer(tld, server)       ← saves to custom_whois_servers
  → markTldRepaired(tld, server)
       → UPDATE tld_server_failures SET repair_status='found'
       → UPDATE tld_fallback_stats SET fail_count=0, use_fallback=false (NEW)
  → invalidateAllServersCache()        ← next lookup uses new server immediately

Admin: tld-probe → probe TLDs → [Save] → setCustomServer → next lookup uses it
Admin: tld-registry → see whois_server → [hover Save] → setCustomServer
Admin: custom-servers → view all sources → [Add/Delete] → DB entries
```

---

## Session — 2026-04-08: Captcha / Security / Redis-Fallback Fixes

### 1. CSP Unblocking Captcha Widgets (Root Cause Fix)
**File:** `next.config.js`

`script-src` and `frame-src` in the Content-Security-Policy did not include the captcha provider CDNs, so the browser silently blocked every captcha script and its verification iframe — the widget area appeared empty with only the hint text.

Updated CSP:
```
script-src: added https://challenges.cloudflare.com https://js.hcaptcha.com https://newassets.hcaptcha.com https://service.mtcaptcha.com
style-src:  added https://newassets.hcaptcha.com https://service.mtcaptcha.com
font-src:   added https://newassets.hcaptcha.com
frame-src:  added https://challenges.cloudflare.com https://newassets.hcaptcha.com https://hcaptcha.com https://service.mtcaptcha.com https://serviceworker.mtcaptcha.com
```

### 2. useCaptcha Hook — Error Detection + Retry (`src/lib/use-captcha.ts`)
- Added `captchaBlocked: boolean` state (exposed in return value)
- Added `retryLoad()` — removes old script tag, clears container, bumps retry counter to re-trigger effect
- Script uses `addEventListener("load/error")` instead of `onload` property to avoid overwriting handlers on re-renders
- Script error → `setCaptchaBlocked(true)` immediately
- Polling exhaustion (60 × 200 ms = 12 s) without widget → `setCaptchaBlocked(true)`
- Fixed `reset()` bug: was setting `widgetIdRef.current = null` before reading it in the Turnstile/hCaptcha reset branch

### 3. Register + Login Pages — Blocked Captcha UI
**Files:** `src/pages/register.tsx`, `src/pages/login.tsx`
- Destructure `captchaBlocked` and `retryLoad: retryCaptcha` from `useCaptcha`
- When `captchaBlocked`: show amber warning card instead of empty container
- Card includes: alert icon + localised explanation + "Retry" button
- Added `RiRefreshLine` icon import to both pages

### 4. All 8 Locale Files — New Translation Keys
**Files:** `locales/en.json`, `zh.json`, `zh-tw.json`, `de.json`, `ru.json`, `ja.json`, `fr.json`, `ko.json`
- `auth.captcha_blocked_hint` — explains why the captcha may not load (ad-blocker, extension)
- `auth.captcha_retry` — retry button label

### 5. Security Fix: Verification Code Bypass (`src/pages/api/user/register.ts`)
**Bug:** `if (storedCode !== null)` guarded the email verification check. When Redis is down, `getRedisValue` returns `null` (circuit breaker), so verification was silently skipped — any direct POST to `/api/user/register` bypassed email verification.

**Fix:**
- Reads code from Redis first, falls back to `verify_codes` DB table
- If both return null → 400 "请先发送验证码，或验证码已过期"
- Verification is now **always required** (no bypass path)
- On success: cleans up from both Redis and DB

### 6. DB Fallback for Verification Code Storage (`src/pages/api/user/send-verify-code.ts`)
Previously returned `503` when Redis was unavailable, blocking registration entirely.

**New behaviour:**
- Rate limiting: Redis preferred → `checkRateLimit` (DB-backed) fallback
- Code storage: writes to **both** Redis and `verify_codes` DB table simultaneously
- Fails only if neither store is reachable
- On email send failure: rolls back from both stores

### 7. New DB Table: `verify_codes` (`src/lib/db.ts`)
```sql
CREATE TABLE IF NOT EXISTS verify_codes (
  email      TEXT        NOT NULL,
  scope      TEXT        NOT NULL DEFAULT 'register',
  code       TEXT        NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (email, scope)
);
```
UPSERT pattern: one row per (email, scope) — re-sending code simply overwrites.

### 8. System Cleanup (`src/pages/api/admin/system.ts`)
Added `expired_verify_codes` cleanup to the `db_optimize` action:
```sql
DELETE FROM verify_codes WHERE expires_at < NOW()
```

---

## Session — 2026-04-08 (续): 竞态条件 + 安全修复

### Bug 1 (Security): reset-password.ts — TOCTOU 竞态条件
**原问题:** 先 SELECT 检查 `used = false`，再单独 `UPDATE SET used = true`。两步之间并发请求可重复使用同一密码重置令牌，双重执行密码重置。

**修复:** 单条原子 SQL:
```sql
UPDATE password_reset_tokens SET used = true
WHERE token = $1 AND used = false AND expires_at > NOW()
RETURNING id, user_id
```
返回 null → 令牌已使用/过期/不存在（再做一次 SELECT 提供具体错误消息）。
密码重置失败时回滚令牌状态。新增 IP 速率限制 (5次/15分钟)。

### Bug 2 (Security): redeem-code.ts — 激活码 TOCTOU 竞态条件
**原问题:** `SELECT used ... WHERE code = $1` → 检查通过 → `UPDATE SET used = true` 两步非原子。并发请求可双重兑换激活码（两人同时拿到订阅/余额）。

**修复:** 先 SELECT 取回 id 和具体状态（用于错误消息），再用原子 UPDATE:
```sql
UPDATE activation_codes SET used = true, used_by = $1, used_at = NOW()
WHERE id = $2 AND used = false AND (expires_at IS NULL OR expires_at > NOW())
RETURNING id, plan_name, ...
```
返回 null → 被并发抢先 → 409。

### Bug 3 (Security): apply-invite-code.ts — 邀请码 TOCTOU 竞态条件
**原问题:** `SELECT use_count, max_uses` → 检查 `use_count < max_uses` → `UPDATE use_count + 1`。并发请求可超出 max_uses 上限（多人同时用满额码）。

**修复:** 预检 SELECT 取 id + 状态 → 原子 UPDATE:
```sql
UPDATE invite_codes SET use_count = use_count + 1
WHERE id = $1 AND is_active = true AND use_count < max_uses
AND (expires_at IS NULL OR expires_at > NOW())
RETURNING id
```
返回 null → 并发抢先耗尽 → 400。

### Bug 4 (UX): send-email-change-code.ts — sendEmail 无 try/catch
**原问题:** `await sendEmail(...)` 未包裹，邮件服务异常时直接抛出导致 500 无友好提示，且已写入 Redis 的验证码和速率限制 key 不会被清理，用户需等 60 秒才能重试。

**修复:** 包裹 try/catch，发送失败时:
- 删除 `email-change:${currentEmail}:${cleanNew}` key
- 删除 `email-change-rate:${currentEmail}` key（让用户可立即重试）
- 返回 500 + 中文友好提示

### Bug 5 (Security): delete-account.ts — 管理员保护用编译时常量
**原问题:** `if (email === ADMIN_EMAIL)` 只比对 `process.env.ADMIN_EMAIL` 环境变量。若管理员邮箱已通过 DB (`site_settings.admin_email`) 更新为其他地址，该账户不受保护可被删除。

**修复:** 替换为 `await isAdminEmail(email)` — 同时检查 DB 值和环境变量，与其他鉴权逻辑一致。
