# Requirements Document — 用户中心订阅增强

Feature Name: user-center-subscription-enhancement
Created: 2026-09-05
Status: Draft

## Introduction

对 WHOIS 查询站的用户中心（/dashboard）进行系统性增强，覆盖四个方向：
- **A. 缺陷修复**：账户删除残留订阅、改邮箱丢失订阅、提醒阈值连发、WHOIS 刷新瓶颈
- **B. 订阅管理增强**：完整编辑能力（阈值/阶段开关/通知邮箱）、暂停恢复、批量导入、用量展示
- **C. 通知增强**：hold/保留状态事件通知、站内通知中心、会员到期提醒、iCal 日历导出
- **D. 过期域名发现**：掉落日历页（复用 expired_domain_leads 爬虫数据）、一键监控订阅

## Glossary

- **订阅（Subscription/Reminder）**：用户对某域名的到期监控记录，存储于 `reminders` 表，按 `email` 字段归属
- **阈值（Threshold）**：到期前提前 N 天发送提醒的档位，默认 [60, 30, 10, 5, 1]
- **阶段（Phase）**：域名生命周期状态：active / grace（宽限期）/ redemption（赎回期）/ pendingDelete（待删除）/ dropped（已掉落）
- **hold 事件**：WHOIS EPP 状态出现 clientHold/serverHold（域名被暂停解析）
- **保留状态**：WHOIS EPP 状态出现 serverProhibited/reserved 类标记（域名禁止注册/转移）
- **掉落（Drop）**：域名结束完整删除周期后重新变为可注册状态的时点
- **通知邮箱（notify_email）**：订阅实际接收提醒邮件的邮箱，独立于归属邮箱（新增字段）
- **站内通知（user_notifications）**：写入数据库的通知记录，登录后在用户中心查看（新增表）

## Requirements

### A 组：缺陷修复

#### R1 账户删除级联清理

**User Story:** AS 注册用户, I want 删除账户时自动清理所有关联数据, so that 注销后不再收到任何邮件且无数据残留。

**Acceptance Criteria:**
1. WHEN 用户确认删除账户, the system SHALL 将该归属邮箱下所有 `reminders` 记录置为 `active=false` 且 `cancel_reason='account_deleted'`。
2. WHEN 用户确认删除账户, the system SHALL 删除 `email_queue` 中该邮箱的全部待发邮件。
3. WHEN 用户确认删除账户, the system SHALL 删除该邮箱在 `stamps` 表中的全部品牌认证记录。
4. WHEN 账户删除完成, the system SHALL 返回清理统计（取消订阅数、清理邮件数、删除品牌数）。
5. IF 任一清理步骤失败, the system SHALL 中止删除并回滚，提示用户稍后重试。
6. WHEN 提醒引擎确认订阅域名进入 dropped 阶段, the system SHALL 删除该域名在 stamps 表的全部记录（域名掉落后品牌认证自然失效）。

#### R2 改邮箱迁移订阅

**User Story:** AS 注册用户, I want 变更账户邮箱时订阅与品牌记录同步迁移, so that 改邮箱后能继续管理既有订阅。

**Acceptance Criteria:**
1. WHEN 用户通过验证码确认变更邮箱, the system SHALL 将 `reminders` 表中旧邮箱更新为新邮箱（仅归属字段，已设置的独立通知邮箱保持不变）。
2. WHEN 用户通过验证码确认变更邮箱, the system SHALL 将 `stamps` 表中旧邮箱更新为新邮箱。
3. IF 迁移过程中任一更新失败, the system SHALL 回滚邮箱变更并提示用户稍后再试。

#### R3 提醒阈值区间化

**User Story:** AS 订阅用户, I want 每个阈值档位只在属于它的时间区间内触发, so that 晚订阅不会导致连续多日重复提醒。

**Acceptance Criteria:**
1. WHEN 提醒处理引擎评估阈值档位 t, the system SHALL 仅在剩余天数满足 `daysToExpiry <= t 且 daysToExpiry > 下一更小档位` 时触发该档（最小档位下界为 0）。
2. WHEN 用户订阅时剩余天数已落入某档区间, the system SHALL 在当日首次处理时发送一次该档提醒。
3. WHEN 各档区间边界值（如恰好剩余 30 天）到达, the system SHALL 恰好触发对应档位一次且仅一次。

#### R4 WHOIS 刷新容量与优先级

**User Story:** AS 多订阅用户, I want 近临期订阅的 WHOIS 数据优先且足量刷新, so that 提醒基于准确的到期日期。

**Acceptance Criteria:**
1. WHEN 提醒处理引擎选择 WHOIS 刷新候选, the system SHALL 按剩余天数升序排序候选（最紧急优先）。
2. WHEN 单次处理批次执行, the system SHALL 将刷新上限从 20 提升至 50。
3. WHEN 订阅记录缺少到期日期（批量导入待补）, the system SHALL 将其纳入 WHOIS 刷新候选。

### B 组：订阅管理增强

#### R5 订阅编辑完整化

**User Story:** AS 订阅用户, I want 在编辑弹窗中修改阈值、阶段开关和通知邮箱, so that 无需取消重订即可调整监控配置。

**Acceptance Criteria:**
1. WHEN 用户打开编辑弹窗, the system SHALL 展示到期日、提醒阈值（可选档位与自定义天数，1-365）、阶段通知开关（宽限/赎回/待删除/临近掉落/已掉落）、通知邮箱（默认为归属邮箱）四项配置。
2. WHEN 用户保存阈值或阶段开关, the system SHALL 更新 `thresholds_json` / `phase_flags` 并按新配置重算下次提醒时间。
3. WHEN 用户设置独立通知邮箱, the system SHALL 将其存入 `notify_email` 字段，后续提醒投递到该邮箱。
4. IF 通知邮箱格式非法, the system SHALL 拒绝保存并提示格式错误。

#### R6 暂停与恢复

**User Story:** AS 订阅用户, I want 暂停订阅而非取消, so that 度假期间免打扰且保留配置与提醒历史。

**Acceptance Criteria:**
1. WHEN 用户暂停订阅, the system SHALL 停止该订阅的一切邮件发送并保留全部配置与日志。
2. WHEN 用户恢复订阅, the system SHALL 按区间化规则继续处理，暂停期间错过的档位跳过。
3. WHEN 订阅处于暂停态, the system SHALL 在订阅列表以独立标识区分于"已取消"。

#### R7 批量导入订阅

**User Story:** AS 多域名持有者, I want 粘贴域名清单批量订阅, so that 无需逐个查询添加。

**Acceptance Criteria:**
1. WHEN 用户提交域名清单（换行或逗号分隔，单次上限 50 条）, the system SHALL 校验格式、去除重复（含已订阅）并逐条创建订阅。
2. WHEN 批量导入创建的订阅缺少 WHOIS 到期日期, the system SHALL 先落库并在 24 小时内由刷新引擎自动补齐（前端提示）。
3. IF 免费用户导入使活跃订阅总数超过 5, the system SHALL 只创建配额内条目并返回明确的跳过统计。
4. WHEN 批量导入完成, the system SHALL 返回统计（成功/跳过重复/格式错误/超配额各计数）。

#### R8 订阅用量展示

**User Story:** AS 免费用户, I want 在订阅页看到配额用量, so that 清楚还能添加几个域名。

**Acceptance Criteria:**
1. WHILE 用户为免费身份且已解锁订阅, the system SHALL 在订阅页顶部显示用量条（已用/5）。
2. WHEN 用量达到上限, the system SHALL 在用量条旁展示会员升级引导。

### C 组：通知增强

#### R9 hold 与保留状态事件通知

**User Story:** AS 订阅用户, I want 域名进入或解除 hold/保留状态时收到通知, so that 及时发现域名解析异常。

**Acceptance Criteria:**
1. WHEN 刷新引擎发现订阅域名 EPP 状态新出现 clientHold/serverHold, the system SHALL 发送"域名被暂停解析"通知（每域名每次 hold 进入仅一次）。
2. WHEN hold 状态解除, the system SHALL 发送恢复通知（要求此前已发过进入通知）。
3. WHEN 订阅域名 WHOIS 状态新出现保留/禁止注册类标记, the system SHALL 发送保留状态通知（每域名每次进入仅一次）。
4. WHEN 上述任一通知发送, the system SHALL 同步写入站内通知记录。

#### R10 站内通知中心

**User Story:** AS 注册用户, I want 在用户中心查看站内通知, so that 不依赖邮箱即可回顾提醒与系统消息。

**Acceptance Criteria:**
1. WHEN 任一提醒邮件/hold 事件/会员提醒发送成功, the system SHALL 写入 `user_notifications`（按归属邮箱关联）。
2. WHEN 用户登录用户中心, the system SHALL 在页面顶部显示铃铛入口与未读数徽章。
3. WHEN 用户打开铃铛下拉, the system SHALL 按时间倒序展示最近 20 条通知，并提供"查看全部"入口跳转独立通知页。
4. WHEN 用户访问独立通知页, the system SHALL 提供分页浏览（每页 20 条）与类型筛选（域名提醒/hold 事件/会员到期/系统公告），并提供全部标记已读操作。
5. WHEN 用户查看某条通知, the system SHALL 将该条标记为已读。
6. WHILE 未读数为 0, the system SHALL 隐藏徽章。

#### R11 会员到期提醒与续费引导

**User Story:** AS 付费会员, I want 会员到期前收到提醒并看到续费入口, so that 不会意外失去订阅权限。

**Acceptance Criteria:**
1. WHEN 会员到期前 7 天与 1 天（每日处理时判断）, the system SHALL 发送续费提醒邮件并写入站内通知。
2. WHEN 会员已过期, the system SHALL 在用户中心显示续费横幅（含购买入口按钮）。
3. WHEN 购买套餐叠加时长, the system SHALL 在会员页明示"购买即自动续期叠加"的文案说明。

#### R12 iCal 日历导出

**User Story:** AS 订阅用户, I want 将订阅导出为日历文件, so that 在 Google Calendar 等工具中获得提醒。

**Acceptance Criteria:**
1. WHEN 用户点击导出日历, the system SHALL 生成 .ics 文件，每个活跃订阅包含两个事件（到期日、预计掉落日），事件含域名与日期描述。
2. WHEN 订阅数量为 0, the system SHALL 禁用导出入口。

### D 组：过期域名发现

#### R13 掉落日历页

**User Story:** AS 域名投资者, I want 浏览即将掉落的域名日历, so that 发现抢注机会。

**Acceptance Criteria:**
1. WHEN 用户访问掉落日历页, the system SHALL 按日期分组展示未来 30 天预计掉落的域名，数据来源为用户自身订阅（pendingDelete/临近掉落）与 `expired_domain_leads` 公开爬虫数据。
2. WHEN 某日期无掉落记录, the system SHALL 显示空状态。
3. WHILE 未登录用户访问且后台开关 `drop_calendar_public` 为开（默认）, the system SHALL 展示公开爬虫数据部分（自身订阅部分隐藏）。
4. WHILE 后台开关 `drop_calendar_public` 为关, the system SHALL 要求登录后才展示掉落日历。

#### R14 掉落域名一键监控

**User Story:** AS 域名投资者, I want 在掉落日历一键订阅监控, so that 掉落时立即收到通知。

**Acceptance Criteria:**
1. WHEN 登录用户在掉落日历点击监控, the system SHALL 复用现有订阅流程为该域名创建订阅（含 WHOIS 同步与确认邮件）。
2. IF 该域名已在用户订阅列表, the system SHALL 提示已订阅并跳过创建。

## Resolved Decisions（已确认）

1. R1: 账户删除与域名掉落两种场景下，stamps 品牌记录均直接删除，展示端自然失效。
2. R10: 通知中心采用铃铛下拉（最近 20 条）+ 独立通知页（分页+筛选）双层形态。
3. R13: 掉落日历默认对未登录开放公开数据，管理员可通过后台开关 `drop_calendar_public` 关闭（强制登录）。
