# Requirements Document — 用户抢注中心与移动端优化

Feature Name: user-snipe-center-mobile
Created: 2026-09-13

## Introduction

在「用户域名预定抢注」(user-snipe-preorder) 已实施的基础上，将抢注能力从用户中心订阅列表的附属组件中抽离，形成**独立的抢注中心入口**，提供完整的：域名列表、状态明细、服务价/冻结进度、操作流程引导与自助管理。同时系统性优化用户中心移动端布局，消除拥挤感，完善功能细节与空态/错误态。

背景事实（2026-09-13 已核实）：

- 用户抢注目前仅以订阅卡片内的小徽章形式存在（`SubscriptionsTab.tsx` 中的 armed/blocked_balance 徽章 + 一个盾牌开关按钮），无独立入口、无详情页、无操作流程说明。
- 订阅提交表单（`DomainReminderDialog.tsx`）尚未提供"同时预定抢注"的勾选入口（后端 `remind/submit.ts` 已支持 `snipe` 参数及三态返回）。
- 用户中心 `/dashboard` 为单列 `max-w-2xl` 布局，4 个 Tab 在窄屏下文字被隐藏、仅图标+角标，卡片操作按钮密集。
- 余额与流水展示在 `MembershipTab`，新增 `hold/unhold/snipe` 三类流水的中文标签有待补充。

## Glossary

- **抢注目标（SnipeTarget）**：用户对某域名提交的预定抢注记录，存于 `snipe_targets`（`user_email` 非空即用户目标），状态机：watching / armed / blocked_balance / sniping / succeeded / failed / cancelled。
- **服务价（Service Price）**：抢注收费标准 = 4 × 预估注册价（EUR×固定汇率换算 CNY），预定时冻结。
- **冻结进度（Hold Progress）**：已冻结金额 `frozen_cents` 对服务价 `service_price_cents` 的比值。
- **抢注中心（Snipe Center）**：用户中心内独立的抢注管理视图，与订阅 Tab 平级。
- **操作流程（Flow Guide）**：向用户解释"预定 → 冻结 → 竞速 → 成功扣费/失败解冻"四阶段的可视化引导。

## Requirements

### Requirement 1 — 独立抢注中心入口

**User Story:** AS 普通用户, I want 在我的用户中心看到独立的"抢注"入口, so that 我能集中管理所有预定抢注的域名而不是在订阅列表里找徽章。

#### Acceptance Criteria

1. THE 用户中心订阅 Tab SHALL 在上方提供「订阅 / 抢注」双状态切换，切换后展示抢注子视图，并展示进行中（armed/blocked_balance/sniping）目标的计数角标。
2. WHEN 用户切换至抢注子视图, THE system SHALL 展示该用户全部抢注目标：域名、当前状态、服务价、冻结进度、创建时间、失败原因。
3. THE 抢注子视图 SHALL 与订阅列表解耦：域名已取消订阅但抢注目标仍在进行时, 目标 SHALL 依旧独立展示与操作。
4. WHEN 用户没有任何抢注目标, THE 抢注子视图 SHALL 展示引导空态：说明什么是预定抢注、如何开始、入口跳转查询页。

#### Notes（明确界定）

- 入口形态采用「订阅 Tab 内嵌子视图」：在订阅 Tab 顶部提供「订阅 / 抢注」双状态切换，不新增导航 Tab，避免移动端 5 标签拥挤。
- 抢注子视图数据独立于订阅数据源，后端新增独立的用户抢注列表接口（见设计文档）。

### Requirement 2 — 抢注详情与操作流程引导

**User Story:** AS 普通用户, I want 能看到一个抢注目标从预定向到成功/失败的完整过程说明与当前所处阶段, so that 我理解系统在做什么、还差什么。

#### Acceptance Criteria

1. THE 每个抢注目标 SHALL 可进入独立详情页（`/snipe/[domain]`）查看：状态、服务价、已冻结金额、当前余额、创建时间、目标状态迁移时间线（如有）。
2. THE 详情页 SHALL 提供"预定 → 冻结 → 竞速 → 成功扣费 / 失败解冻"四步骤流程引导，并高亮当前所处步骤。
3. WHEN 目标处于 blocked_balance, THE 详情页 SHALL 显示缺口金额（服务价 − 冻结金额或 − 当前余额），并提供"去充值"按钮跳转充值页。
4. WHEN 目标处于 armed, THE 详情页 SHALL 显示冻结完成提示与预计竞速窗口（drop ETA 区间，如可获取）。
5. THE 详情页 SHALL 对目标提供明确的启停操作：启用（重新计算服务价并冻结）、停用（解冻并取消占坑），并二次确认后执行。
6. THE 详情页 SHALL 展示该域名是否关联现有订阅，并提供订阅详情跳转。

#### Notes（明确界定）

- 详情采用独立路由 `/snipe/[domain]`，移动端以下拉式抽屉载入或直接导航均可，但路由必须存在、可刷新直达。
- 底部提供"抢注说明"折叠区：收费规则（4×预估注册价）、冻结机制、竞速逻辑、域名归属与交付方式。
- 状态迁移时间线仅展示系统当前留存的历史字段；无历史则隐藏时间线节点。

### Requirement 3 — 抢注与订阅的双向联动

**User Story:** AS 普通用户, I want 抢注中心与订阅各自独立又能互相感知, so that 我不被强制二选一。

#### Acceptance Criteria

1. THE 抢注中心列表 SHALL 标注每个域名是否同时存在关联订阅（WHOIS 到期监控），存在则提供跳转订阅详情的入口。
2. THE 订阅卡片 SHALL 保留现有抢注状态徽章，点击徽章 SHALL 跳转抢注中心对应目标的详详情。
3. WHEN 用户在抢注中心停用目标, THE 关联订阅 SHALL 保持有效（订阅不受影响），仅取消抢注占坑。
4. WHEN 用户取消整个订阅, THE 关联抢注目标 SHALL 按现有规则同步取消（与 user-snipe-preorder 需求保持一致）。

### Requirement 4 — 预约入口完善

**User Story:** AS 普通用户, I want 在订阅/监控域名时能明确选择是否同时预定抢注, so that 预定与监控一次完成。

#### Acceptance Criteria

1. THE 订阅提交弹窗（DomainReminderDialog）SHALL 提供"同时预定抢注该域名"的可选勾选（默认关闭），勾选时 SHALL 立即展示服务价预估价、冻结机制说明与该操作的含义。
2. WHEN 用户勾选并提交且余额充足, THE system SHALL 返回"抢注已开启"的三态反馈（armed 表示已冻结进入竞速；blocked_balance 表示余额不足已暂停待充值；failed 表示域名已被他人占坑或报价失败）。
3. WHEN 域名已被他人占坑返回 409, THE 弹窗 SHALL 明确提示"该域名已被其他用户预定抢注"。
4. WHEN 用户未登录或会员权限不足打开弹窗, THE 弹窗 SHALL 保持现有登录/会员引导流程。
5. THE 抢注中心（订阅 Tab 抢注子视图 + 详情页）SHALL 提供完整的收费与冻结规则说明折叠区（4× 预估注册价、冻结机制、竞速逻辑、域名归属与交付方式）。

### Requirement 5 — 移动端布局适配

**User Story:** AS 移动端用户, I want 用户中心在手机上布局清晰不拥挤, so that 我能单手完成抢注与订阅的管理。

#### Acceptance Criteria

1. THE 用户中心主导航 SHALL 在窄屏（<640px）保持 4 个 Tab 不下沉，订阅 Tab 内部的「订阅 / 抢注」切换使用等宽双按钮状态栏，保证文字完整可读。
2. THE 订阅/抢注卡片 SHALL 在窄屏下合理换行：状态徽章、操作按钮 SHALL 不挤压域名文本，按钮区 SHALL 折叠为清晰的一行（图标按钮保持 44px 触控目标）。
3. THE 抢注目标卡/详情页 SHALL 在任意宽度下完整展示"已冻结/服务价"数值与进度条。
4. THE 余额、积分、流水等统计卡片 SHALL 在窄屏下改单列堆叠，宽屏保持多列。
5. THE 详情页（或详情抽屉）SHALL 在窄屏采用自顶部滑出的全屏式布局，内容 SHALL 可滚动不遮挡；宽屏保持正常文档流。
6. IF 任何操作按钮在窄屏下宽度不足, THE 系统 SHALL 优先保证操作可用性（可点、有反馈），禁止出现横向溢出裁切。

### Requirement 6 — 功能细节完善

**User Story:** AS 普通用户, I want 抢注与订阅管理的细节真实可用, so that 每一步状态都透明可追踪。

#### Acceptance Criteria

1. THE 余额流水区（MembershipTab）SHALL 为 `hold`（抢注定金冻结）、`unhold`（冻结解冻退回）、`snipe`（抢注成功扣费）新增中文标签。
2. THE 抢注目标状态 SHALL 全量覆盖并中文展示：未启用(watching)、竞速中(armed)、待充值(blocked_balance)、抢注中(sniping)、已抢到(succeeded)、未抢到(failed)、已取消(cancelled)。
3. THE 抢注视图 SHALL 提供状态筛选（全部/竞速中/待充值/待处理/已结束）与域名搜索。
4. WHEN 抢注引擎或后端返回失败, THE 视图 SHALL 展示人类可读的失败原因字段（替代裸技术错误串）。
5. THE 页面加载、请求失败、无数据 SHALL 分别提供骨架屏/错误重试/空态三态，禁止白屏。
6. THE 抢注中心 SHALL 支持下拉刷新（移动端）与手动刷新按钮（桌面），刷新 SHALL 不丢失当前筛选。

## Out of Scope（本期不做）

- 抢注结果的过户托管流程（交付方案另行设计）。
- 竞拍/出价或降价机制（保持固定 4× 服务价先到先得）。
- 抢注成功计费的发票/收据导。
- 多语言翻译扩展（沿用现有 i18n 机制，新增文案以中文为准）。