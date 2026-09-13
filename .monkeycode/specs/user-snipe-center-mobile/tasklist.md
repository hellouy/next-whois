# 实施计划 — user-snipe-center-mobile

- [ ] 1. 后端报价接口（新增 `src/pages/api/snipe/quote.ts`）
  - `GET /api/snipe/quote?domain=` 复用 `snipeServicePrice`，返回 serviceCents/cnyCost/fxRate/markup/isPremium；已登录时附 balanceCents
  - 校验 domain 参数与非法输入 400；未登录不报错（balanceCents=null）

- [ ] 2. 后端抢注列表接口（新增 `src/pages/api/user/snipe-targets.ts`）
  - `GET ?status=all|armed|blocked_balance|sniping|ended&q=` 过滤 `user_email=$1`
  - 返回 id/domain/tld/status/serviceCents/frozenCents/failReason/dropEta/huntStart/huntEnd/registeredAt/createdAt
  - `hasSubscription` 联查 reminders（按 domain，阈值=存在即 true）；状态筛选归一化 ended={succeeded,failed,cancelled}
  - 排序：进行中优先（armed/blocked_balance/sniping 在前），其次 created_at DESC
  - 未登录 401；db 未就绪 503
  - 单元测试：列表基本形态、状态筛选、搜索 ILIKE、hasSubscription 联查、非本人隔离（mock db）

- [ ] 3. 后端详情/操作接口（新增 `src/pages/api/user/snipe-targets/[domain].ts`）
  - `GET`：单目标全字段 + balanceCents + hasSubscription + linkedReminderId；非本人/不存在 404
  - `PATCH { action: 'enable' | 'disable' }`：复用 snipeServicePrice + createUserSnipeTarget + freezeForSnipe / cancelUserSnipeTarget（响应形态与 subscriptions.ts PATCH 一致，含 blocked_balance 缺口）；`SNIPE_TAKEN`→409
  - 校验 domain 路径参数；enable 报价失败 502；未登录 401
  - 单元测试：enable→armed、enable→blocked_balance（含 balanceCents/neededCents）、SNIPE_TAKEN→409、非本人 GET→404、disable→releasedCents

- [ ] 4. 抢注列表视图（新增 `src/components/dashboard/SnipeListView.tsx`）
  - Props: targets/loadingTargets/error/filter/search + onRefresh/onFilterChange/onSearch/onToggle
  - 筛选 chips（全部/竞速中/待充值/抢注中/已结束）+ 搜索框 + 刷新
  - 卡片：域名 + STATUS_META 全状态中文徽章 + 订阅关联标记；冻结进度条（已冻结/服务价）+ 缺口提示与去充值按钮；创建时间 +「查看详情」
  - 空态（去查询页）/错误态（重试）/骨架屏三态；移动端卡片整卡点击跳 `/snipe/[domain]`

- [ ] 5. 抢注详情页（新增 `src/pages/snipe/[domain].tsx`，含 `src/components/dashboard/SnipeFlowSteps.tsx`）
  - 返回栏 + 域名 + 状态大徽章；SnipeFlowSteps 四步（预定→冻结→竞速→成功/解冻）done/current/todo 三态
  - 数值卡：服务价/已冻结/当前余额/缺口 + 去充值/启用/停用（停用二次确认 Dialog）
  - 订阅联动按钮（管理订阅）与折叠抢注说明（4×预估、冻结机制、竞速窗口、归属交付）
  - 404/14H 错态友好提示；loading 骨架屏

- [ ] 6. 订阅 Tab 顶部分段切换（`src/components/dashboard/SubscriptionsTab.tsx` 改造）
  - 顶部「订阅(计数) | 抢注(进行中计数)」等宽双按钮，`viewMode` 本地 state，默认 subscriptions
  - 抢注计数 = targets 中 armed/blocked_balance/sniping 之和；切换按需拉取 targets 数据
  - 订阅卡片抢注徽章（armed/blocked_balance）点击改跳 `/snipe/[domain]`；既有盾牌按钮同步

- [ ] 7. 订阅弹窗勾选入口（`src/components/query/DomainReminderDialog.tsx`）
  - 提交区新增「同时预定抢注该域名」开关（默认关）；开启时内联：预估价（调 quote API）+ 余额 + 说明文案
  - 提交 payload 增 `snipe: true`；响应 snipe 三态 toast；报价失败提示允许提交但不强转

- [ ] 8. 余额流水中文标签（`src/components/dashboard/MembershipTab.tsx`）
  - type 映射补充：hold=抢注冻结、unhold=抢注解冻、snipe=抢注扣费；未映射回退原始 type

- [ ] 9. 移动端布局微调（dashboard.tsx + SubscriptionsTab + SnipeListView）
  - 操作按钮窄屏 ≥36px 触控、等宽双按钮 flex-1、长域名 truncate、无横向溢出

- [ ] 10. 检查点 — 验证链全绿并提交
  - 分步执行 `npx tsc --noEmit` → `npx vitest run` → `npm run check:i18n`，全部通过
  - 新增/更新测试随各自功能提交；回归核对 snipe-engine / snipe-balance / subscriptions 测试
  - `git add` + commit 并 push main（文档已随上一提交入仓）