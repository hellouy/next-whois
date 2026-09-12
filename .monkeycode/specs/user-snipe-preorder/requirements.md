# Requirements Document — User Domain Preorder Sniping（用户域名预定抢注）

Feature Name: user-snipe-preorder
Updated: 2026-09-12

## Introduction

在现有「域名监控订阅」与「用户中心订阅」基础上，向普通用户开放过期域名预定抢注：用户在监控任意域名时可同时勾选预定抢注；域名进入掉落竞速窗口后由抢注引擎自动执行（Netim `domainCheck` 权威确认 + `domainCreate` 自动注册）。用户预定即冻结服务价（4 × 预估注册价）作为余额门槛，冻结成功后才进入竞速执行；抢注成功按冻结的服务价从余额扣费（差额为平台利润）并解冻抵用，未抢到则解冻退还可冻结金额。

前置条件（已实测，2026-09-12）：

- Netim 代理账户、SOAP 2.0 可用；`domainCheck` ~600ms；`.sb` 支持；无官方 backorder。
- 平台已有管理员级抢注引擎（`snipe-engine.ts`）、监控订阅体系（`reminders` 表 + `/remind` 表单 + 用户中心 `SubscriptionsTab`）、余额体系（`users.balance_cents` + `balance_transactions`）。
- 余额单位为分（CNY，`balance_cents`）；Netim 注册价（EUR）经**固定汇率**换算为人民币定价，汇率由平台配置。。

## Glossary

- **预定（Preorder）**：用户在监控订阅上勾选的"抢注意图"，包含预估 4 倍售价与冻结门槛。
- **充值门槛（Recharge Threshold）**：启用抢注所需余额 = 服务价 = 4 × 预估注册价；预定即冻结该金额，冻结成功后才进入竞速执行。
- **竞速窗口（Hunt Window）**：drop ETA −1d 至 +2d，期间高频探测。
- **占坑（Claim）**：同一域名只允许未被抢注占用时，第一个预定用户独占该域名抢注资格。
- **服务价（Service Price）**：向用户收取的售价 = 4 × 预估注册价；预定冻结、成功扣除的金额。
- **预估注册价（Estimated Cost）**：Netim `queryDomainPrice` 实时注册价（EUR）经固定汇率换算为 CNY 后的金额。
- **冻结（Hold）**：预定时将服务价从用户可用余额冻结，抢注成功扣费抵用，失败/退出解冻。冻结金额在 balance_transactions 记 `hold`/`unhold` 流水。

## Requirements

### Requirement 1 — 监控订阅扩展预定选项

**User Story:** AS 普通用户, I want 在我的域名监控订阅上勾选启用抢注预定, so that 同一个域名我既能收到到期提醒、又能自动参与竞速抢注。

#### Acceptance Criteria

1. THE 监控订阅提交表单 SHALL 提供"同时预定抢注该域名"的可选开关（默认关闭）。
2. WHEN 用户勾选预定, THE system SHALL 在提交监控订阅时同时创建一条抢注目标记录并与该订阅关联。
3. THE 用户中心订阅列表 SHALL 展示每个订阅的抢注状态（未启用 / 待充值 / 竞速中 / 已抢注 / 未抢到 / 已取消）。
4. WHEN 用户取消监控订阅, THE system SHALL 同时取消关联的抢注目标；取消后的目标 SHALL 停止一切探测与注册动作。

### Requirement 2 — 先到先得占坑

**User Story:** AS 普通用户, I want 我预定后的域名不被其他用户重复预定, so that 我的抢注机会有保证。

#### Acceptance Criteria

1. WHEN 用户在勾选预定时目标域名已被其他用户占坑（状态为启用/待充值/竞速中/已抢注）, THE system SHALL 拒绝提交并提示"该域名已被其他用户预定抢注"。
2. WHEN 域名跌破前一持有状态且无可抢注记录, THE system SHALL 允许第一个预定的用户独占占坑。
3. WHEN 用户的抢注目标因失败或已取消而释放, THE system SHALL 允许重新占坑。
4. THE 管理员 SHALL 拥有强制释放任意占坑的能力。

### Requirement 3 — 冻结门槛与执行开关

**User Story:** AS 普通用户, I want 冻结服务价后系统才开始执行抢注, so that 我不会在没备好资金时意外注册域名。

#### Acceptance Criteria

1. THE 系统 SHALL 在任意目标创建时依据 Netim `queryDomainPrice` 计算服务价（= 4 × 固定汇率换算后的预估注册价）。
2. WHEN 用户勾选预定, THE system SHALL 尝试冻结服务价金额；冻结成功则目标进入 `armed` 并开始竞速执行。
3. IF 用户可用余额不足服务价, 冻结 SHALL 失败, 目标状态 SHALL 保持 `blocked_balance`, 并在竞速窗口内跳过注册动作（探测继续）。
4. WHEN 用户余额达到或超过服务价（充值到账）, 目标 SHALL 被自动冻结并转为 `armed`。
5. WHEN 服务价上调（注册价上涨）导致已冻结金额低于新服务价, THE 目标 SHALL 补充冻结；余额不足则回到 `blocked_balance`。
6. THE 用户中心 SHALL 展示每个待充值目标的服务价、冻结金额与当前余额，并提供一键跳转充值入口。

### Requirement 4 — 充值后自动武装

**User Story:** AS 普通用户, I want 我充值到账后系统自动开始为我抢注, so that 我不需要手动操作切换。

#### Acceptance Criteria

1. WHEN 用户的充值订单支付成功到账, THE system SHALL 检核该用户所有 `blocked_balance` 抢注目标, 对余额充足的目标自动冻结服务价并迁移为 `armed`。
2. WHEN 目标迁移为 `armed`, THE system SHALL 发送站内通知与邮件告知用户"抢注已进入竞速阶段"。
3. WHILE 目标处于 `armed`, THE system SHALL 在竞速窗口内正常执行高频探测与注册。

### Requirement 5 — 竞速执行（复用抢注引擎）

**User Story:** AS 普通用户, I want 掉落瞬间系统自动完成权威确认与注册, so that 我不需要守着页面。

#### Acceptance Criteria

1. THE 抢注引擎 SHALL 对用户目标复用现有 `snipe-engine` 流程：WHOIS 疑释放判定 → Netim `domainCheck` 权威确认 → 预算守卫 → CAS → `domainCreate` → `queryOpe` 收尾。
2. WHEN 目标进入 `sniping`, THE system SHALL 使用 Netim 账户默认联系人/DNS、注册期 1 年执行注册。
3. WHEN `domainCreate` 返回成功, THE target SHALL 记录为 `succeeded` 并发送成功通知。
4. WHEN 抢注失败（已被他人注册等确定性失败）, THE target SHALL 记录为 `failed` 并释放占坑。

### Requirement 6 — 余额冻结与扣费

**User Story:** AS 普通用户, I want 抢到域名时才扣服务价, so that 没有抢到我不产生实际费用。

#### Acceptance Criteria

1. WHEN 目标的 `domainCreate` 返回成功, THE system SHALL 将冻结的服务价转为扣费（解冻抵用），写入一条 `type='snipe'` 的 `balance_transactions` 流水，流水金额等于服务价。
2. WHEN 目标以未抢到/失败/取消告终, THE system SHALL 解冻服务价，写入 `type='unhold'` 流水；用户可用余额恢复。
3. WHEN 目标因缴纳后再失败二次抢注不占坑, 解冻与冻结 SHALL 各记一条流水且金额一致。
4. IF 用户其余余额不足（服务价上调后的差额部分）, THE system SHALL 完成不足部分补冻结并通知；域名归属仍按交付方案处理。
5. THE 扣费/解冻 SHALL 具有幂等性：同一目标同类型流水已存在时 SHALL 不重复入账。
6. WHEN 余额不足以达到冻结门槛, THE system SHALL 不扣费、不产生任何流水。

### Requirement 7 — 审计与通知

**User Story:** AS 普通用户, I want 每次抢注尝试与结果可查, so that 我知道发生了什么、花了多少。

#### Acceptance Criteria

1. THE 系统 SHALL 为用户可见的每个抢注目标记录：预定时间、预估注册价、服务价、状态迁移、竞速期内探测摘要。
2. WHEN 目标发生 `blocked_balance → armed → sniping → succeeded/failed` 的状态迁移, THE system SHALL 对应发送通知。
3. THE 用户中心订阅列表 SHALL 展示目标状态、服务价、已扣费记录与失败原因。

### Requirement 8 — 安全与防滥用

**User Story:** AS 平台管理者, I want 抢注资格受余额与占坑约束, so that 资源不被滥用。

#### Acceptance Criteria

1. WHEN 用户的抢注目标未完成冻结, THE 注册动作 SHALL 永不执行。
2. THE 同一域名 SHALL 至多存在一个有效（未失败/未取消）的用户抢注占坑。
3. THE 认证与授权 SHALL 复用现有登录会话；仅登录用户 SHALL 能预定与查看自己的目标。
4. THE 用户 SHALL 无法通过参数篡改降低自己的服务价或跳过冻结；服务价 SHALL 总是由服务端按 `queryDomainPrice` 重新计算。

## Out of Scope（本期不做）

- 竞拍/出价模式（高价者得）；v1 为先到先得的固定 4 倍服务价。
- 抢到域名后的过户托管流程（域名注册在平台 Netim 账户，交付方案另行设计）。
- 用户自定义注册参数（联系人/DNS/注册年数）与多注册商价格对比。
- 多用户同域名的通知竞价。