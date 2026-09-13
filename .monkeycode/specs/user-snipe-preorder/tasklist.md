# 需求实施计划 — user-snipe-preorder

## 阶段一：数据层与余额接缝

- [ ] 1. db.ts 迁移扩展
  - `snipe_targets` 增加 `user_email TEXT`、`service_price_cents BIGINT`、`frozen_cents BIGINT NOT NULL DEFAULT 0`、`hold_keys TEXT`；索引 `idx_snipe_targets_user`（user_email）。
  - `balance_transactions` 增加 `target_id TEXT`；文档注明 type 新枚举 `hold|unhold|snipe`。
  - `site_settings` 默认写入 `snipe_eur_fx_rate`（8.0）与 `snipe_markup`（4）。
- [ ] 2. 定价服务 `src/lib/server/snipe-pricing.ts`
  - `getFxRate()`：从 site_settings 读 `snipe_eur_fx_rate`，缺省 8.0。
  - `snipeServicePrice(domain)`：复用 netim-client `netimQueryDomainPrice` 拿 EUR 注册价 → ×fxRate → ×markup → ×100 → 分；返回 `{ eurCost, cnyCost, serviceCents, fxRate, markdown }`；query 失败返回 null。
  - 对应需求 R5、设计第 2 节；EUR→CNY 固定汇率换算（决策④）。

## 阶段二：状态机与资金接边

- [ ] 3. 余额冻结/扣费服务 `src/lib/server/snipe-balance.ts`
  - `freezeForSnipe(tx, targetId, userEmail, amountCents)`：`UPDATE users SET balance_cents=balance_cents-$3, frozen_cents=frozen_cents+$3 WHERE id=$1 AND balance_cents>=$3`；成功写 `type='hold'` 流水（含 target_id），并在 snipe_targets 记 `frozen_cents`、`hold_keys`。
  - `settleSnipeCharge(tx, targetId, userEmail, amountCents)`：frozen→扣费，写 `type='snipe'` 流水，设幂等标识。
  - `releaseSnipeHold(tx, targetId, userEmail, amountCents)`：解冻返还，写 `type='unhold'` 流水，清 frozen。
  - 全部依赖入参 `tx`（from `withTransaction`），保证与状态迁移同事务。
- [ ] 4. 引擎状态机接入（`src/lib/server/snipe-engine.ts`）
  - `SnipeTargetRow` 扩展 `user_email/service_price_cents/frozen_cents/hold_keys` 字段。
  - `armPrecheck`（L428）：当 `user_email` 存在时，委托 `snipe-balance` 做冻结校验，冻结不足返回 `blocked_balance`（透传余额/差额）。
  - 注册成功收尾（`settleCreate` 成功后）：`user_email` 存在 → `settleSnipeCharge` 与 `notifySnipeSettled`（扣费金额）。
  - 确定性失败收尾（`failed_permanent`、取消）：`user_email` 存在 → `releaseSnipeHold` 与 `notifySnipeReleased`（返还金额）。
  - `runProbe` daily 分支对用户目标不新增 cron，沿用现有 daily/hunt 通道。
- [ ] 5. 用户维度目标 CRUD（`src/lib/server/snipe-balance.ts` + 复用引擎目标 SQL）
  - `createUserSnipeTarget(tx, {domain, tld, userEmail, serviceCents})`：写 `snipe_targets`（user_email、service_price_cents、frozen=0、status=watching）；`domain UNIQUE` 冲突抛 `SNIPE_TAKEN`，仅忽略 `cancelled/failed` 旧行可复用。
  - `cancelUserSnipeTarget(tx, domain, userEmail)`：软删 `cancelled` + 解冻。

## 阶段三：外部接口与前端

- [ ] 6. remind/submit.ts 扩展预定抢注
  - payload 增 `snipe: boolean`；`snipe=true` 时调用 `snipeServicePrice` + `createUserSnipeTarget` + `freezeForSnipe` 于同一事务。
  - 冻结成功 → `armed`（可竞速）；余额不足 → `blocked_balance` 并返回 `snipe:{status,serviceCents,balanceCents,neededCents}`。
  - 域名被占 → 409 `SNIPE_TAKEN`。
  - 对应需求 R1、R3、R5、R7。
- [ ] 7. 用户中心订阅列表（`src/pages/api/user/subscriptions.ts` + `SubscriptionsTab.tsx`）
  - GET 每项并入抢注状态：`snipe_status`（none/blocked_balance/armed/sniping/succeeded/failed/cancelled）、`service_cents`、`frozen_cents`、`snipe_fail_reason`。
  - 表格/卡片新增抢注状态列：文案徽章 + 余额不足「去充值」按钮（跳 `/payment/checkout`）。
  - PATCH 支持 `snipe_action: enable|disable`（enable 复用提交定价/冻结，disable 取消占坑）。
- [ ] 8. 充值入账自动武装（`src/lib/payment.ts` markOrderPaid 收尾）
  - 事务成功返回前调用 `autoArmBlockedTargets(userEmail)`：扫描 `blocked_balance` 且用户邮箱匹配的目标，对每个目标 `freezeForSnipe`，成功转 `armed` 并 `notifySnipeArmed`。
  - 对应需求 R4；Balance 不足的目标保持 `blocked_balance` 幂等，不重复冻结。

## 阶段四：通知与巡检

- [ ] 9. 抢注邮件/站内模板（`src/lib/email.ts` + notifications）
  - 新增模板：`snipeArmedHtml`（已冻结进入竞速）、`snipeSettledHtml`（成功扣费金额+订单号）、`snipeReleasedHtml`（未抢到解冻金额）、`snipeInsufficientHtml`（需充金额缺口）。
  - 复用现有黑白极简视觉、中文文案、无 emoji。
- [ ] 10. cron 重定价补冻结（`runDailyProbe` daily 分支扩展或独立函数）
  - 用户目标未 `succeeded/failed/cancelled` 时重算 `snipeServicePrice`；上调则补冻结（差额），不足回 `blocked_balance` 并发 `notifySnipeInsufficient`；下调不回退。
  - 对应需求 R6、设计第 9 节。

## 阶段五：测试与验证

- [ ]* 11. 单元测试
  - `snipe-pricing`：EUR→CNY×4 换算、汇率缺省 8.0、query 失败返回 null。
  - `snipe-balance`：冻结成功/不足、扣费幂等、解冻返还、事务回滚。
  - 状态机用户分支：注册前冻结校验、成功扣费、失败解冻（注入 fake db）。
  - remind/submit `snipe=true` 三态（成功/不足/占坑）与 409。
- [ ] 12. 检查点 — 确保 `npx tsc --noEmit`、`npx vitest run`、`npm run check:i18n` 全绿，如有疑问询问用户