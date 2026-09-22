# Requirements Document — Domain Drop Calendar（掉落日历）

Feature Name: domain-drop-calendar
Updated: 2026-09-22

## Introduction

将现有 `/drops` 页面从「历史已删除域名清单」升级为「未来掉落预告日历」，并建立多维度域名价值评分体系。

现状问题（2026-09-22 实测）：

- 公开数据来自 `expired_domain_leads`（源 `expireddomains.net/combinedexpired`），该视图返回的是**早已删除、当前可注册**的域名，而非未来将掉落的域名。
- `available_date` 共 50 条中 48 条仅有年份（如 `"2018"`），无精确日期，按天分组失去意义。
- 数据总量 50 条，最后抓取 2026-09-13，数据源单一。
- 价值评分 `scoreDomain` 已有长度/TLD/静态关键词/模式四维，但缺少**通用英文单词**与**中文双拼拼音**两个维度，且未接入动态热门前缀表 `hot_prefixes`。

本特性引入多源「未来掉落」采集、复用 `lifecycle.ts` 推算精确掉落日与时刻、扩展现有价值评分为七维模型，并提供真正的日历视图与订阅/抢注衔接。

## Glossary

- **掉落（Drop）**：注册局将域名从注册数据中移除并重新开放公众注册的时刻。
- **掉落日期（Drop Date）**：域名预计掉落的日历日期（`YYYY-MM-DD`）。
- **掉落时刻（Drop Time）**：注册局释放域名的当日具体时刻，含时区，来自 `tld_rules` 的 `drop_hour/drop_minute/drop_second/drop_timezone`。
- **掉落线索（Drop Lead）**：一条待掉落域名记录，含域名、掉落日期、来源、价值属性。
- **待删除视图（Pending-Delete View）**：数据源中列出已进入 pendingDelete 状态、数日内将掉落的域名列表，日期精确到日。
- **即将过期列表（Expiring List）**：数据源中列出即将到期但尚未删除的域名列表。
- **已删除列表（Deleted List）**：数据源中列出当日刚被删除、已可注册的域名列表。
- **源提供日期（Source Date）**：数据源直接给出的掉落日期。
- **推算日期（Derived Date）**：由域名到期日 + TLD 生命周期规则计算出的掉落日期。
- **生命周期引擎（Lifecycle Engine）**：`src/lib/lifecycle.ts` 的 `computeLifecycle`，基于 TLD 宽限/赎回/待删除天数与 EPP 状态计算掉落日期与时刻。
- **TLD 规则（TLD Rule）**：`tld_rules` 表中每个后缀的 grace / redemption / pending_delete / pre_expiry / drop 时刻 / 时区字段。
- **价值分（Value Score）**：0-100 的多维域名价值评分，维度含长度、后缀、词性、热门前缀、字符模式、市场数据。
- **单词域名（Dictionary Word）**：SLD 为完整英文词典单词的域名，如 `car.com`。
- **双拼域名（Pinyin Domain）**：SLD 可切分为有效汉语拼音音节组合的域名，如 `qiche`（汽车）。
- **热门前缀（Hot Prefix）**：`hot_prefixes` 表中登记的当前趋势高价值 SLD 片段，含权重与分类。
- **数据新鲜度（Freshness）**：线索来源数据最近一次成功抓取的时间距当前时长。

## Requirements

### R1 未来掉落数据源采集

**User Story:** AS 管理员, I want 系统从多个可靠数据源采集未来掉落与当日掉落列表, so that 日历展示的是即将掉落的域名而非历史删除清单。

#### Acceptance Criteria

1. THE system SHALL 支持从以下数据源采集，每个源以独立标识登记：
   - `expireddomains.net` 的待删除视图（复用现有登录凭证与爬虫框架）
   - `whoisds.com` 的每日已删除与即将过期列表（公开下载，无需登录）
2. THE system SHALL 将采集内容按掉落阶段归类：待删除（未来数日）、即将过期（未来数周）、当日已删除。
3. THE system SHALL 为每条线索记录来源标识（`source`）、来源阶段（`stage`）与抓取时间（`crawled_at`）。
4. WHEN 采集到已存在的域名, THE system SHALL 以最新日期与属性更新该线索，不产生重复行。
5. IF 某数据源连续失败, THE system SHALL 保留该源上一次成功的数据并在管理端标记该源异常。
6. THE system SHALL 将无法解析的行计入错误计数并跳过，不影响同批次其他行。
7. THE system SHALL 以配置项控制各数据源的启用状态与抓取频率。

### R2 掉落日期解析与标准化

**User Story:** AS 管理员, I want 掉落日期统一为标准 ISO 日期并标明来源类型, so that 日历分组与倒计时基于可靠日期。

#### Acceptance Criteria

1. WHEN 采集到日期文本, THE system SHALL 解析为 `YYYY-MM-DD` 标准格式；解析失败的行 SHALL 跳过并计入错误计数。
2. THE system SHALL 为每条线索标注日期类型：源提供日期或推算日期。
3. WHEN 源提供的日期早于当前日期, THE system SHALL 将该线索标记为已掉落，不纳入未来日历窗口。
4. WHEN 同一域名同时存在源提供日期与推算日期, THE system SHALL 以源提供日期为准并记录推算偏差。

### R3 生命周期推算与校准

**User Story:** AS 管理员, I want 对缺少精确日期的域名用 TLD 生命周期规则推算掉落日与掉落时刻, so that 日历能覆盖即将过期列表并显示精确到时刻的倒计时。

#### Acceptance Criteria

1. WHEN 线索域名具有到期日且所属 TLD 存在生命周期规则, THE system SHALL 通过 `computeLifecycle` 推算掉落日期。
2. WHEN 线索所属 TLD 配置了掉落时刻与时区, THE system SHALL 在日历中展示该时刻与时区。
3. THE system SHALL 依据 TLD 规则的置信度标注推算日期的可信级别，并在界面区分展示源提供日期与推算日期。
4. WHEN 域名 EPP 状态包含 hold / prohibited / disputed / suspicious, THE system SHALL 不将其作为未来掉落展示。
5. WHEN 推算日期与源提供日期偏差超过阈值, THE system SHALL 记录偏差供管理员核对，并以源提供日期展示。

### R4 多维价值评分

**User Story:** AS 访客, I want 每条掉落线索带多维度价值评分, so that 能快速识别值得抢注的域名。

#### Acceptance Criteria

1. THE system SHALL 计算 0-100 的价值分，并返回各维度得分与人类可读的评分理由。
2. THE system SHALL 在现有 `scoreDomain` 的长度、后缀、关键词、字符模式四维基础上扩展以下维度：
   - **单词维度**：SLD 为完整英文词典单词时加分，单词越短分值越高
   - **双拼维度**：SLD 可切分为有效汉语拼音音节组合时加分，音节数越少分值越高
   - **热门前缀维度**：SLD 命中 `hot_prefixes` 表（`enabled=true`）时按该前缀权重加分
   - **市场数据维度**：依据外链数（BL）与域名流行度（DP）加分
3. THE system SHALL 对单字符与双字符 SLD 给予最高长度档分值，并标注「单字符/双字符」理由。
4. WHEN SLD 含连字符或数字与字母混合, THE system SHALL 降低价值分并标注降分理由。
5. THE system SHALL 依据价值分划分等级（极高/高/中高/普通/低），等级阈值可通过配置调整。
6. THE system SHALL 对价值分达到阈值的线索触发管理员告警（复用现有 `shouldAlertAdmin` 语义）。
7. WHEN 单条线索请求深度估值, THE system SHALL 复用 `domain-value-ai` 返回市场价格区间与品牌潜力，并缓存结果。
8. THE system SHALL 保证评分函数对同一输入返回稳定结果，且不因数据源顺序变化而改变。

### R5 日历查询接口

**User Story:** AS 访客或登录用户, I want 按时间窗口查询按日期分组的掉落线索, so that 日历能高效渲染每日条目。

#### Acceptance Criteria

1. WHEN 请求 `/api/drops`, THE system SHALL 接受日历窗口参数（默认 30 天，范围 1 至 90 天）。
2. THE system SHALL 仅返回窗口内掉落日期不早于今日的线索。
3. THE system SHALL 按掉落日期分组返回，并附每日线索总数与当日最高价值分。
4. WHEN 请求携带筛选参数（后缀、长度区间、最小价值分、来源、日期类型）, THE system SHALL 在服务端应用筛选。
5. THE system SHALL 为每条线索返回域名、掉落日期、掉落时刻、来源、日期类型、价值分与评分理由。
6. WHEN 请求来自匿名访客, THE system SHALL 返回可缓存的公开响应；WHEN 请求携带登录会话, THE system SHALL 返回 `private, no-store` 响应。
7. THE system SHALL 为单次响应设置条数上限，超出时按价值分降序截断。

### R6 日历视图界面

**User Story:** AS 访客, I want 以月历网格浏览每日掉落并展开当日列表, so that 能直观看到未来哪些天有掉落。

#### Acceptance Criteria

1. THE system SHALL 提供月历网格视图，每个日期格显示当日掉落线索数量与最高价值等级。
2. WHEN 用户点击某一日期, THE system SHALL 展开该日的线索列表，按价值分降序排列。
3. THE system SHALL 支持切换上一个/下一个日历月，并限制可浏览范围与日历窗口一致。
4. THE system SHALL 高亮当前日期，并对有掉落的日期按数量或价值显示视觉区分。
5. THE system SHALL 在移动端视口下提供可用布局。
6. WHEN 日历窗口内无任何线索, THE system SHALL 显示空状态提示与最近一次数据更新时间。

### R7 筛选与排序

**User Story:** AS 访客, I want 按价值分排序并多条件筛选, so that 能优先关注更值得抢注的域名。

#### Acceptance Criteria

1. WHEN 用户选择排序方式, THE system SHALL 支持按掉落日期、价值分、外链数三种排序。
2. THE system SHALL 提供后缀、长度区间、最小价值分、来源、日期类型五类筛选器。
3. WHEN 筛选条件变更, THE system SHALL 保留已选日历窗口并重新查询。
4. THE system SHALL 在界面展示价值分的维度构成，供用户理解排序依据。
5. WHEN 筛选结果为空, THE system SHALL 提示可放宽的条件项。

### R8 订阅与抢注衔接

**User Story:** AS 用户, I want 从日历直接订阅提醒或加入抢注目标, so that 看到有价值域名后无需切换页面即可行动。

#### Acceptance Criteria

1. THE system SHALL 为每条线索提供「监控提醒」操作，复用现有 `/api/remind/submit` 接口。
2. WHEN 用户已订阅某域名, THE system SHALL 在日历中标记为已监控状态。
3. WHEN 当前用户为管理员, THE system SHALL 提供从日历将域名加入抢注目标的入口，复用现有抢注目标接口。
4. IF 未登录用户点击监控提醒, THE system SHALL 引导至登录页。
5. WHEN 订阅达到用户配额上限, THE system SHALL 展示明确提示并保持日历可用。

### R9 数据新鲜度与来源标注

**User Story:** AS 访客, I want 看到每条线索的来源与数据更新时间, so that 能判断数据的时效与可信度。

#### Acceptance Criteria

1. THE system SHALL 在页面展示各数据源标识与最近一次成功抓取时间。
2. WHEN 数据新鲜度超过配置阈值（默认 48 小时）, THE system SHALL 展示数据可能过期的提示。
3. THE system SHALL 在每条线索上提供来源标识，界面可区分源提供日期与推算日期。
4. WHEN 采集源异常, THE system SHALL 在管理端展示源状态与最近错误。

### R10 访问控制

**User Story:** AS 管理员, I want 控制日历对匿名访客的可见性, so that 能按运营策略决定公开范围。

#### Acceptance Criteria

1. WHILE `drop_calendar_public` 为开启, THE system SHALL 允许匿名访客浏览公开日历。
2. WHILE `drop_calendar_public` 为关闭, THE system SHALL 要求登录后访问，匿名请求返回锁定状态而非数据。
3. WHEN 匿名访客访问锁定日历, THE system SHALL 展示登录引导，不泄露任何线索数据。

### R11 统计概览

**User Story:** AS 访客, I want 看到窗口内的掉落统计概览, so that 能快速把握整体情况。

#### Acceptance Criteria

1. THE system SHALL 展示日历窗口内的线索总数与今日掉落数。
2. THE system SHALL 展示窗口内按后缀分布的前 N 个后缀及计数。
3. THE system SHALL 展示窗口内价值分最高的 N 条线索。
4. THE system SHALL 展示各数据源的贡献量与新鲜度。
5. WHEN 窗口或筛选变更, THE system SHALL 重新计算概览指标。

## Out of Scope

- ICANN CZDS zone file 接入（需审批，作为后续长期数据源）。
- 自动抢注执行流程（已由 `domain-drop-sniping` 规范覆盖，本特性仅提供入口）。
- 域名掉落后的转售与挂牌功能。
- 面向公开用户的付费抢注订阅产品。
- 引入新的图表依赖库；统计展示复用现有轻量 DOM/CSS 方案。
- 对全量线索批量调用 AI 深度估值（仅按需触发单条）。
