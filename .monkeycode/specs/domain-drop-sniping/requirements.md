# Requirements Document — Domain Drop Sniping（域名掉落抢注）

Feature Name: domain-drop-sniping
Updated: 2026-09-12

## Introduction

系统对用户关注的即将掉落域名（如 f.sb）进行生命周期跟踪与多频段探测：常规期每日 WHOIS 跟踪，掉落日切换为高频竞速探测；当探测判定域名可能已释放时，调用 Netim `domainCheck` 做注册局级权威确认；确认 AVAILABLE 后立即调用 Netim `domainCreate` 自动注册。全流程记录审计日志并通过现有邮件系统通知结果。

前置条件（已实测验证，2026-09-12）：

- Netim 代理账户 LJ5551 有效，SOAP API 2.0 可用（sessionOpen/queryResellerAccount/queryDomainPrice/domainTldInfo/domainCheck 均实测通过）。
- Netim API 提供 `domainCreate`；Netim 无官方 backorder/预注册服务。
- Netim 支持 `.sb` 注册（基础价 €40.20）；f.sb 为 premium（€60.50/年，IsPremium=1）。
- Netim `domainCheck` 响应约 600ms，返回 AVAILABLE/NOT AVAILABLE + reason。
- 账户当前余额 €50.00，低于 f.sb 注册价 €60.50。
- 账户默认联系人已配置（Owner LJ5552、Admin/Tech/Billing LJ5551）、默认 DNS 已配置（ns1/ns2.nic.bn）。
- Vercel cron 为 Hobby 级（每天一次），竞速窗口需 GitHub Actions 触发。

## Glossary

- **目标（Target）**：被加入抢注 watchlist 的域名，含注册参数与预算上限。
- **掉落（Drop）**：注册局将域名从注册数据中移除、重新开放公众注册的时刻。
- **探测（Probe）**：一次 WHOIS/RDAP 或 Netim `domainCheck` 查询。
- **竞速窗口（Hunt Window）**：掉落预计日期前后 N 小时的时间段，期间以 30 秒级频率探测。
- **权威确认（Authoritative Confirmation）**：通过 Netim `domainCheck` 获得的注册局侧可用性结论。
- **武装（Armed）**：目标通过余额预检、注册参数就绪、可被自动注册的状态。

## Requirements

### Requirement 1 — 目标管理

**User Story:** AS 管理员, I want 在管理后台添加/管理抢注目标（域名、预算上限、备注）, so that 系统只对我关注的域名执行探测与注册。

#### Acceptance Criteria

1. THE system SHALL 提供管理接口用于新增目标，记录域名、预算上限（EUR）、备注、创建时间。
2. THE system SHALL 在新增目标时通过 WHOIS 查询初始化目标的到期日与 EPP 状态。
3. WHEN 目标已存在于 watchlist，THE system SHALL 拒绝重复添加并返回明确提示。
4. THE system SHALL 支持暂停（pause）、恢复（resume）、取消（cancel）单个目标；取消后的目标 SHALL 停止一切探测与注册动作。
5. IF 当前登录用户非管理员，THE system SHALL 拒绝所有目标管理操作。

### Requirement 2 — 武装预检（Arming Preflight）

**User Story:** AS 管理员, I want 系统在武装目标前自动完成注册可行性与预算预检, so that 掉落瞬间不会因配置或余额问题错失注册。

#### Acceptance Criteria

1. THE system SHALL 在武装目标前调用 Netim `queryResellerAccount` 读取当前余额。
2. IF 目标预估注册价（`queryDomainPrice` 结果）大于账户余额，THE system SHALL 将目标标记为 `blocked_balance` 并向管理员发送充值告警邮件。
3. THE system SHALL 在武装前通过 `queryDomainPrice` 缓存目标的预估注册价与 IsPremium 标记。
4. THE system SHALL 在武装前校验注册参数（联系人/DNS）已就绪；使用 Netim 账户默认配置时 SHALL 记录使用的默认值快照。
5. WHILE 目标处于 `blocked_balance` 状态，THE system SHALL 跳过该目标的自动注册动作，探测继续。

### Requirement 3 — 生命周期跟踪（常规期探测）

**User Story:** AS 管理员, I want 常规期每日跟踪目标的生命周期状态, so that 系统能持续修正掉落预计日期。

#### Acceptance Criteria

1. THE system SHALL 在每日 cron（复用 `/api/remind/process` 同期机制或独立 cron）中对每个 active 目标执行一次 WHOIS/RDAP 查询。
2. THE system SHALL 记录每次跟踪的 EPP 状态、到期日、探测时间到探测历史。
3. THE system SHALL 基于 `lifecycle.ts` 的 TLD 生命周期规则计算掉落预计日期（drop ETA），并在每次 WHOIS 结果更新后刷新。
4. WHEN WHOIS 返回到期日变化（如原持有人续费），THE system SHALL 更新 drop ETA 并相应推迟竞速窗口。
5. IF WHOIS 连续 3 次查询失败，THE system SHALL 保持上一次成功结果并向管理员发送探测异常告警。

### Requirement 4 — 竞速窗口与高频探测

**User Story:** AS 管理员, I want 掉落日自动切换到 30 秒级高频探测, so that 域名释放后能在最短时间内被发现。

#### Acceptance Criteria

1. THE system SHALL 在 drop ETA 前 24 小时至 ETA 后 48 小时定义为目标的多轮竞速窗口。
2. WHILE 竞速窗口内，THE system SHALL 通过 GitHub Actions 定时触发探测端点，探测间隔为 30 秒（±GitHub Actions 排队抖动）。
3. THE 竞速触发器 SHALL 携带 CRON_SECRET 调用 `/api/cron/snipe-probe`，与现有 cron 认证机制一致。
4. THE 探测端点 SHALL 单次调用内完成：WHOIS/RDAP 快速判定 → 疑似可用时立即 Netim `domainCheck` 权威确认。
5. WHILE 竞速窗口内同一目标的探测，THE system SHALL 保证同一时刻只有一个探测流程在执行（数据库行锁/claim 机制）。

### Requirement 5 — 释放判定与权威确认

**User Story:** AS 管理员, I want 探测判定"可能已释放"后用 Netim 注册局数据二次确认, so that 自动注册动作基于最权威的可用性结论。

#### Acceptance Criteria

1. WHEN WHOIS/RDAP 返回"未注册/无记录/AVAILABLE"或 EPP 状态从注册态消失，THE system SHALL 判定为疑似释放并立即发起 Netim `domainCheck`。
2. WHEN Netim `domainCheck` 返回 AVAILABLE，THE system SHALL 将目标置入 `sniping` 状态并立即触发自动注册流程。
3. WHEN Netim `domainCheck` 返回 NOT AVAILABLE（无论 reason），THE system SHALL 将结果记入探测历史并继续探测。
4. THE system SHALL 在释放判定与注册动作之间复用同一次 `domainCheck` 结论，保持判定与动作的原子性。

### Requirement 6 — 自动注册

**User Story:** AS 管理员, I want 系统确认 AVAILABLE 后自动调用 Netim `domainCreate` 完成注册, so that 无需人工值守即可完成抢注。

#### Acceptance Criteria

1. WHEN 目标进入 `sniping` 状态，THE system SHALL 使用预存参数（默认联系人 + 默认 DNS，注册期 1 年）调用 Netim `domainCreate`。
2. THE system SHALL 在发起 `domainCreate` 前二次校验：目标仍处于 `sniping`、预算上限 ≥ Netim 实时注册价。
3. WHEN `domainCreate` 返回成功（含操作号），THE system SHALL 将目标置为 `succeeded`，记录 Netim 操作号、成交价、时间，并发送成功邮件。
4. WHEN `domainCreate` 返回确定性失败（已被他人注册、参数被拒），THE system SHALL 将目标置为 `failed`，记录失败原因，并发送失败邮件；SHALL 终止对该目标的后续注册尝试。
5. WHEN `domainCreate` 返回瞬时错误（网络超时、会话失效），THE system SHALL 按指数退避重试，最多 3 次，成功或终态后停止。
6. IF 单次注册调用超过 30 秒未返回，THE system SHALL 通过 Netim `queryOpe`/`queryOpePending` 查询异步操作结果后归类为成功或失败。

### Requirement 7 — 审计与通知

**User Story:** AS 管理员, I want 全流程关键事件落库并通过邮件通知, so that 每次抢注的成败与原因可追溯。

#### Acceptance Criteria

1. THE system SHALL 为每次探测记录：目标、探测通道（whois/rdap/netim_check/netim_create）、结论、耗时、时间戳。
2. THE system SHALL 为每次注册尝试记录独立审计行：参数快照、Netim 响应原文、结果归类。
3. WHEN 目标发生状态迁移（armed→sniping→succeeded/failed），THE system SHALL 发送对应邮件至管理员邮箱（复用现有 sendEmail/email_queue 机制）。
4. WHEN 余额低于任一 active 武装目标的预估注册价，THE system SHALL 发送充值告警邮件，频率限制为每 24 小时至多一次。

### Requirement 8 — 安全与凭证

**User Story:** AS 管理员, I want Netim 凭证与注册动作受访问控制保护, so that 自动化资产不被未授权操作。

#### Acceptance Criteria

1. THE system SHALL 复用现有 `NETIM_LOGIN`/`NETIM_PASSWORD` 环境变量，凭证 SHALL 出现在日志、响应、审计记录的明文中。
2. THE 探测与注册端点 SHALL 仅接受 CRON_SECRET Bearer 认证或管理员会话（与 `/api/remind/process` 一致）。
3. THE 自动注册 SHALL 仅对 `sniping` 状态目标触发；任何外部请求 SHALL 无法直接指定"注册某域名"。

## Out of Scope（本期不做）

- Netim 之外的注册商抢注通道（Porkbun 等仅作价格参考）。
- 多注册期/多联系人参数自定义（v1 使用 Netim 账户默认值）。
- 域名掉落后的转售/挂牌功能。
- 公开用户侧的抢注订阅产品（本期仅管理员使用）。
