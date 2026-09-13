# 用户抢注中心与移动端优化 — 技术设计

Feature Name: user-snipe-center-mobile
Updated: 2026-09-13

## Description

将已实施的用户抢注能力（user-snipe-preorder）从订阅卡片的附属徽章升级为：订阅 Tab 内嵌"订阅 / 抢注"双视图 + 独立详情路由 `/snipe/[domain]`，并完善移动端布局与功能细节（流水中文标签、状态全覆盖、筛选/搜索、三态加载、下拉刷新、收费规则说明）。

复用既有能力（已实现）：`api/user/subscriptions.ts`（GET 已返回每订阅 `snipe` 字段）、`snipe-balance.ts`（freeze/settle/release、目标 CRUD、autoArm）、`snipe-pricing.ts`（服务价换算）、`remind/submit.ts`（snipe 三态创建）、`MembershipTab`（余额流水）、dashboard `SubscriptionsTab`。

## Architecture

```mermaid
graph TD
    subgraph 用户中心 subscriptions Tab
        A[SubscriptionsTab<br/>顶部「订阅/抢注」切换] --> B[订阅列表视图<br/>既有卡片+徽章]
        A --> C[抢注列表视图<br/>SnipeListView - 新增]
    end

    C --> D[api/user/snipe-targets.ts<br/>新增: 列表/状态筛选/搜索]
    C --> E["详情路由 /snipe/[domain]<br/>SnipeDetailPage - 新增"]

    E --> F[api/user/snipe-targets/[domain].ts<br/>新增: 详情/启停/取消订阅跳转]
    E --> G[流程引导 四步<br/>预定→冻结→竞速→扣费/解冻]
    E --> H[收费规则说明折叠区]

    C --> I[MembershipTab<br/>hold/unhold/snipe 流水中文标签]
    B --> J["订阅卡片徽章点击<br/>跳转 /snipe/[domain]"]
```

关键变化点：
1. **不新增导航 Tab**：抢注作为 `SubscriptionsTab` 内部状态（`viewMode: 'subscriptions' | 'snipe'`），顶部双按钮切换。
2. **独立数据源**：新增 `api/user/snipe-targets.ts` 列表接口，不再依赖订阅对象上的 `snipe` 字段；详情页单独拉取。
3. **详情页独立路由**：`/snipe/[domain]`，走 next/dynamic 或普通页面，移动端从列表卡片跳转、桌面可直接访问。

## Components and Interfaces

### 1. 后端列表接口（新增 `src/pages/api/user/snipe-targets.ts`）

`GET /api/user/snipe-targets?status=all|armed|blocked_balance|sniping|ended&q=<domain>`

- 鉴权：`getServerSession` + `session.user.email`。
- SQL：`SELECT id, domain, tld, status, service_price_cents, frozen_cents, fail_reason, notes, drop_eta, hunt_start, hunt_end, created_at, updated_at, registered_at FROM snipe_targets WHERE user_email=$1 [AND status 筛选] [AND domain ILIKE '%q%'] ORDER BY 进行中优先, created_at DESC`。
- 返回（每项）：
  ```ts
  {
    id, domain, tld, status,
    serviceCents, frozenCents, failReason,
    dropEta, huntStart, huntEnd, registeredAt, createdAt,
    hasSubscription: boolean,   // 该域名是否有现存订阅
  }
  ```
  `hasSubscription`：左侧联查 `reminders`（`WHERE email=$1 AND domain=ANY(...)`），存在即 true。

- 状态筛选归一化：`all` 全部；`armed` 竞速中；`blocked_balance` 待充值；`sniping` 抢注中；`ended`=succeeded/failed/cancelled。

### 2. 后端详情/操作接口（新增 `src/pages/api/user/snipe-targets/[domain].ts`）

- `GET /api/user/snipe-targets/[domain]`：返回单目标全字段 + `balanceCents`（该用户当前余额）+ `hasSubscription` + 关联订阅 id。
- `PATCH` body `{ action: 'enable' | 'disable' }`：
  - `enable`：`snipeServicePrice(domain)` → `withTransaction(createUserSnipeTarget + freezeForSnipe)` → `armed` / `blocked_balance`（含 balanceCents, serviceCents）/ `failed`；复用 `snipe-balance.ts` 与 `subscriptions.ts` PATCH 逻辑（响应形态一致）。
  - `disable`：`withTransaction(cancelUserSnipeTarget)` → 返回 `releasedCents`。
  - 409 `SNIPE_TAKEN`：域名被他人占坑。
- `DELETE /api/user/snipe-targets/[domain]`：停用并释放（与 disable 等价，可选）——本期仅 PATCH，不新增 DELETE。

### 3. 抢注列表视图（新增 `src/components/dashboard/SnipeListView.tsx`）

Props：`targets`, `loadingTargets`, `dashError`, `filter`, `search`, `callbacks`（onRefresh, onFilterChange, onSearch, onToggle）。

- 顶部：筛选 chips（全部/竞速中/待充值/抢注中/已结束）+ 搜索框 + 刷新按钮。
- 卡片（复用订阅卡片视觉语言）：
  - 首行：域名 + 状态徽章（`STATUS_META` 化：watching/armed/blocked_balance/sniping/succeeded/failed/cancelled 全中文标签）+ 关联订阅标记（小回形/铃铛图标，可点跳订阅）。
  - 次行：冻结进度条（`已冻结 ¥X / 服务价 ¥Y`）+ 状态文案（armed→"冻结完成，等待竞速"；blocked_balance→"需充值 ¥缺口"）；不足时按钮"去充值"。
  - 第三行：创建时间 + "查看详情 →"整卡点击跳 `/snipe/[domain]`。
- 空态：图标 + "还没有抢注预定" + "去查询页开始抢注"按钮（Link `/`）。
- 错误态：错误提示 + 重试按钮。
- 下拉刷新：移动端 `onTouchStart/onTouchEnd` 或 `usePullToRefresh`（若不存在则仅提供按钮；避免过度投入）。

### 4. 抢注详情页（新增 `src/pages/snipe/[domain].tsx` 或 `src/components/dashboard/SnipeDetailPage.tsx` + 路由封装）

- 数据：`GET /api/user/snipe-targets/[domain]`。
- 布局（窄屏单列、宽屏 ≤ max-w-lg）：
  1. 顶部返回栏（`← 返回抢注中心`） + 域名 + 状态大徽章。
  2. **四步流程引导**（`SnipeFlowSteps`）：预定 → 冻结 → 竞速 → 成功/解冻；`done`/`current`/`todo` 三态着色，右缀金额；当前步骤放大强调。
  3. 关键数值卡：服务价、已冻结、当前余额、缺口（blocked_balance 时），操作按钮：去充值 / 启用 / 停用（停用需确认 Dialog）。
  4. 时间线（如有历史字段）：created_at / 状态迁移 / registered_at。
  5. 订阅联动：存在订阅 → 按钮"管理订阅"（跳 dashboard subscriptions）；否则该栏隐藏。
  6. 折叠"抢注说明"：收费规则（4×预估注册价）、冻结/解冻机制、竞速窗口、域名归属与交付。
- 404/错态：目标不存在或非本人 → 友好提示 + 返回。

### 5. 订阅 Tab 顶部分段切换（`SubscriptionsTab.tsx`）

- 顶部新增状态栏：`订阅(计数) | 抢注(进行中计数)`，`viewMode` 本地 state；抢注计数 = 该用户 targets 中 `armed/blocked_balance/sniping` 之和。
- 每次进入 Tab 默认回到 `subscriptions` 视图；切换时拉取/复用 targets 数据（`useEffect` 按需）。
- 订阅卡片上的抢注徽章（armed/blocked_balance）与盾牌按钮保留，点击跳转对应 `/snipe/[domain]` 详情。
- 新增 prop `onOpenSnipeDetail(domain)` 或直接 `router.push`。

### 6. 订阅弹窗勾选入口（`DomainReminderDialog.tsx`）

- 提交区新增丝"同时预定抢注该域名"开关（默认关）；开启时内联展开：
  - 服务价预估价：`GET /api/snipe/quote?domain=...`（新增轻量报价接口，reuse `snipeServicePrice`，无需登录态渲染时已登录用户显示余额）。
  - 说明文案：冻结即扣余额、成功扣费、失败解冻、他人已占则失败。
- 提交时 payload 增 `snipe: true`；响应 `snipe` 三态（armed/blocked_balance/failed）分别 toast + 展示结果（沿用 submit.ts 现状）。
- 报价失败（null serviceCents）→ 开启开关时提示"当前无法获取报价，稍后再试"，允许提交但前端明确告知。

### 7. 报价接口（新增 `src/pages/api/snipe/quote.ts`）

`GET /api/snipe/quote?domain=example.com`
- 复用 `snipeServicePrice`；返回 `{ domain, serviceCents, cnyCost, fxRate, markup, isPremium, balanceCents(登录时) }`。
- 公开只读；无需登录（未登录 balanceCents=null）。

### 8. 余额流水中文标签（`MembershipTab.tsx`）

- `balanceTxs.type` 映射补充：`hold="抢注冻结"`、`unhold="抢注解冻"`、`snipe="抢注扣费"`；使用已有 `balance-transactions.ts` API。
- 若有 type 未映射，fallback 显示原始 type 字符串。

### 9. 移动端布局微调（dashboard + 卡片）

- 订阅/抢注卡片操作按钮区：窄屏下图标按钮 `w-9 h-9`（≥44px 触控）或 `min-w-[36px] min-h-[36px]` 保持一致，间距 gap-1。减少 `hover:` 依赖，按钮保证触控反馈。
- Tab 切换栏在订阅 Tab 内部：双按钮 `flex-1` 等宽，不挤压。
- 全局检查无横向溢出：dashboard 主容器 `max-w-2xl px-4` 已安全；卡片内长域名 `truncate` 已覆盖。

## Data Models

无新增表。仅复用/读取：

- `snipe_targets`（用户目标，`user_email IS NOT NULL`）：读取 status/service_price_cents/frozen_cents/fail_reason/drop_eta/hunt_start/hunt_end/registered_at/created_at/updated_at/notes。
- `reminders`：联查 `hasSubscription` / 订阅跳转。
- `users.balance_cents`：详情页展示当前余额。
- `balance_transactions`：前端流水标签（无字段变更）。

可能的轻量迁移（非必须，见 Correctness）：无。

## Correctness Properties

1. **数据归属隔离**：列表/详情/操作接口全部以 `session.user.email` 过滤 `user_email`；非本人目标返回 404。
2. **状态机一致性**：前端展示状态集合 ⊆ 后端 `snipe_targets.status` 枚举；`blocked_balance` 一定伴随余额不足，`armed` 一定 `frozen_cents == service_price_cents`（由引擎保证）。
3. **资金不变式**：`enable` 的定价/冻结复用服务端 `snipeServicePrice` + `snipe-balance`，客户端不可篡改价格；`disable` 幂等（cancelUserSnipeTarget 去重）。
4. **视图解耦**：抢注列表独立拉取，与订阅对象上的 `snipe` 字段互不依赖；`hasSubscription` 仅做提示，不出错影响主数据。
5. **移动端可用性**：任何操作按钮窄屏下 ≥ 36px 触控、域名字段 `truncate`、无横向溢出；弹窗/详情窄屏全屏化。

## Error Handling

| 场景 | 处理 |
|---|---|
| 列表/详情拉取失败 | 错误态 + 重试按钮；骨架屏 loading |
| 目标不存在或非本人 | 404 友好提示 + 返回按钮 |
| enable 时域名被占坑 | 409 `SNIPE_TAKEN` → toast"该域名已被其他用户预定抢注" |
| enable 时报价失败 | 提示"无法获取报价，稍后再试"；允许维持 disabled |
| blocked_balance 缺口 | 详情/列表展示缺口金额 + "去充值"（跳 `/payment/checkout`） |
| 停用确认 | 二次确认 Dialog，成功后 toast 解冻金额 |
| 空数据 | 空态引导（去查询页） |
| 下拉刷新失败 | toast 错误，保留原数据 |

## Test Strategy

1. **后端接口**：`api/user/snipe-targets` 列表（状态筛选、搜索、`hasSubscription` 联查、非本人隔离）；`/snipe/[domain]` 详情与 enable/disable（复用 snipe-balance 逻辑，覆盖 armed/blocked_balance/SNIPE_TAKEN）。
2. **报价接口**：`snipeServicePrice` 成功/失败已覆盖（snipe-pricing.test.ts）；新增 quote API 薄封装测试（可选）。
3. **组件**：`SnipeListView` 状态徽章/空态/筛选渲染；`SnipeFlowSteps` 四步骤各状态高亮（react-testing-lib 或静态渲染断言）。
4. **回归**：现有 snipe-engine / snipe-balance / subscriptions 测试保持全绿；`check:i18n` 通过（中文固定文案，不引 i18n key）。

## References

[^1]: (Filename#L572-L606) - `src/lib/db.ts` snipe_targets 表结构含用户目标列
[^2]: (Filename#L163-L258) - `src/pages/api/user/subscriptions.ts` PATCH snipe_action 逻辑（详情页复用 enable/disable 形态）
[^3]: (Filename#L388-L415) - `src/components/dashboard/SubscriptionsTab.tsx` 现有抢注徽章与按钮
[^4]: (Filename#L695-L1206) - `src/pages/remind/index.tsx` 订阅表单（弹窗勾选入口参照）
[^5]: (Filename#L78-L105) - `src/pages/admin/snipe-targets.tsx` STATUS_META 状态徽章视觉参照