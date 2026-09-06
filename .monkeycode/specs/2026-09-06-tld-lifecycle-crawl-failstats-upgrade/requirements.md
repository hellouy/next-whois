# Requirements Document — TLD 生命周期 AI 抓取与查询失败统计升级

Feature Name: tld-lifecycle-crawl-failstats-upgrade
Created: 2026-09-06
Status: Draft

## Introduction

对后台的 TLD 生命周期规则（AI 自动抓取）与域名后缀查询失败统计两套子系统进行增强：

**A. TLD 生命周期 AI 抓取**（现状 `tld-rules.ts` + `cron/tld-scrape.ts` + `ai-providers.ts`）：抓取注册局页面、多模型 AI（GLM/Groq/Gemini/DeepSeek 自动回退）提取宽限期/赎回期/精确掉落时间与时区，IANA 页面自动发现注册局生命周期子页。本次增强：统一抓取服务层、AI 字段来源置信度、时区严格校验、动态 IANA 计数、Provider 熔断降权、用量审计、并行抓取与限流退避、数据 TTL 刷新与批量刷新。

**B. 域名后缀查询失败统计**（现状 `tld_fallback_stats` + `tld-failures.ts` + `tld-failures.tsx`）：本次重构为「失败事件明细表 + query_logs 计量」双事实源，修复周对比失效缺陷，实现成功率健康度、原因归因、窗口统计仪表盘与双表职责分离。

## Glossary

- **TLD 生命周期规则（tld_rules）**：每个后缀的宽限期/赎回期/待删除期/提前删除天数/掉落时刻字段，`scrape_status` 取值 pending / ok / warn_defaults / failed / no_data
- **AI 提供商（Provider）**：`ai-providers.ts` 中注册的模型编排单元（智谱 GLM / Groq / Gemini / DeepSeek / DashScope / Moonshot / 千帆 / SiliconFlow），按 priority 排序，失败回退
- **发现策略（Discovery Strategy）**：从 IANA 页定位注册局生命周期子页的手段：direct（主页直含数据）/ registry_paths（常见路径探测）/ link_crawl（主页链接爬两级）/ jina（Jina Reader 渲染 JS 站点）/ registry_cached（注册局 URL 缓存命中）
- **字段来源（Field Source）**：AI 返回字段值的可信度标记：`page_explicit`（页面原文明确数值）/ `page_hint`（页面上下文推算）/ `industry_default`（ICANN 行业默认猜测）
- **失败事件表（tld_failure_events）**：新表明细记录每次查询失败（时间戳/后缀/原因枚举/查询域名/错误样本），是失败诊断的事实源
- **query_logs**：现有查询日志表，含 `success` 列与 `duration_ms`，是查询计量（总量/成功率/延迟）的事实源
- **tld_fallback_stats**：现有表，本次之后专管「该后缀的 WHOIS/RDAP 服务器配置与修复状态」（含 whoiser 旁路、第三方 API 来源、repair_status）
- **熔断（Circuit Breaking）**：Provider 连续失败达到阈值后短路跳过，到期进入半开试连恢复
- **TTL 刷新**：`scrape_status='ok'` 超过刷新周期后重新入队抓取

## Requirements

### A 组：域名后缀查询失败统计重构

#### R1 失败事件明细表

**User Story:** AS 后台管理员, I want 每次查询失败以明细事件落库, so that 能按时间窗口统计失败趋势与原因分布。

**Acceptance Criteria:**
1. WHEN 一次 WHOIS/RDAP 查询对某后缀失败, the system SHALL 向 `tld_failure_events` 写入一条事件，包含后缀、原因枚举、查询域名、错误样本（截断 300 字符）与时间戳。
2. WHEN 查询主路径仍在执行, the system SHALL 以 best-effort 方式异步写入失败事件，不阻塞查询响应。
3. WHEN 事件表数据超过保留期（90 天）, the system SHALL 清理并仅保留统计聚合所需的最少数据。
4. WHEN 该后缀在同一秒内发生多次同类失败, the system SHALL 继续逐条记录而非覆盖。

#### R2 成功率与健康度

**User Story:** AS 后台管理员, I want 查看每个失败后缀的成功率与健康度, so that 能区分全挂故障与偶发抖动。

**Acceptance Criteria:**
1. WHEN 管理员查看失败列表, the system SHALL 基于 `query_logs` 展示最近窗口内该后缀的查询总量、成功数、失败数与成功率。
2. WHEN 查询量达到最小采样数（默认 5）, the system SHALL 才展示健康判定（健康/波动/故障）。
3. WHEN 采样不足的后缀出现, the system SHALL 展示成功率原始值并标注采样不足，不作出健康判定。
4. WHEN 管理员调整窗口（7/30 天）, the system SHALL 以所选窗口重算全部健康指标。

#### R3 失败原因枚举扩展与归因归一

**User Story:** AS 后台管理员, I want 失败原因使用统一分类枚举, so that 能批量归因定位根因。

**Acceptance Criteria:**
1. WHEN 查询失败被捕获, the system SHALL 将失败原因归类至扩展枚举：`no_server` / `dns_failure` / `connect_timeout` / `socket_error` / `http_blocked` / `http_not_found` / `http_server_error` / `rdap_error` / `empty_response` / `parse_error` / `rate_limited` / `third_party_failed`。
2. WHEN 底层错误消息可匹配（如 ETIMEDOUT、Cloudflare、404、空响应）, the system SHALL 应用规则映射到枚举，未匹配的归类为 `unknown`。
3. WHEN 归类器无匹配, the system SHALL 保留原始错误文本于 `fail_reason_detail`，并以 `unknown` 枚举值记录。
4. WHEN 失败事件写入, the system SHALL 同时记录归类使用的上下文（API 路径与查询阶段：lookup/whois/rdap/api）。

#### R4 窗口统计仪表盘

**User Story:** AS 后台管理员, I want 一个可切换窗口的失败统计仪表盘, so that 能看到失败趋势、原因分布与 Top 故障后缀。

**Acceptance Criteria:**
1. WHEN 管理员打开失败统计页, the system SHALL 展示聚合卡片：窗口内失败总数、成功总数、成功率、与上一窗口的失败增量。
2. WHEN 管理员查看原因分布, the system SHALL 以柱状图或条形图展示各原因枚举计数及占比。
3. WHEN 管理员查看趋势, the system SHALL 以按日（或按小时）失败计数渲染趋势图，窗口为 7 天或 30 天。
4. WHEN 管理员查看 Top 失败后缀, the system SHALL 按窗口内失败事件数降序排列，并附成功率与最近失败样本。
5. WHEN 全部指标聚合, the system SHALL 允许请求方指定窗口参数（默认 7 天），且不依赖全历史累加计数。

#### R5 双表职责分离

**User Story:** AS 后台管理员, I want 失败计量与服务器配置互不干扰, so that 统计准确且配置独立维护。

**Acceptance Criteria:**
1. WHEN 查询失败发生, the system SHALL 将计量口径写入 `tld_failure_events`，不再向 `tld_fallback_stats.fail_count` 累加。
2. WHEN 管理员配置后缀的 WHOIS/RDAP 服务器、whoiser 旁路或第三方 API 来源, the system SHALL 维持写入 `tld_fallback_stats`。
3. WHEN 统计数据被清除或重置, the system SHALL 不影响 `tld_fallback_stats` 中的服务器配置与修复状态。
4. WHEN 发现重复或过期的统计列, the system SHALL 在前端移除对该列的依赖。

### B 组：TLD 生命周期 AI 抓取重构

#### R6 统一抓取服务层

**User Story:** AS 后台管理员, I want 手动抓取与定时批量抓取走同一保存管线, so that 字段一致且手动失败也能留痕。

**Acceptance Criteria:**
1. WHEN 任一入口（手动 POST 或 cron 队列）触发抓取, the system SHALL 调用统一的 `scrapeTld` 服务函数完成发现、AI 提取、落库与缓存失效。
2. WHEN 手动抓取失败, the system SHALL 将 `tld_rules` 中该后缀置为 `failed` 并记录失败原因。
3. WHEN 保存抓取结果, the system SHALL 记录 `fetch_strategy`（实际命中的发现策略）与 `raw_excerpt`（原文片段）。
4. WHEN cron 与手动共享同一条保存 SQL, the system SHALL 对 `needs_admin_review`、`scrape_attempts`、`failure_reason` 实行一致语义。

#### R7 AI 字段来源标记与置信度

**User Story:** AS 后台管理员, I want AI 输出标明每个字段是页面明确值还是默认猜测, so that 能判断数据可信度并改进队列判定。

**Acceptance Criteria:**
1. WHEN AI 返回结构体, the system SHALL 为 grace/redemption/pending_delete/pre_expiry/drop 系列字段携带来源标记（`page_explicit` / `page_hint` / `industry_default`）与原文佐证引用。
2. WHEN AI 未提供来源标记或解析失败, the system SHALL 回退为仅提取数值并将该 TLD 置信度标为 low。
3. WHEN 后端计算置信度, the system SHALL 依据明确值字段数量分级：至少一个 `page_explicit` 字段为 medium，grace 与 redemption 均 `page_explicit` 为 high，全字段非明确为 very_low。
4. WHEN 判定 `warn_defaults`, the system SHALL 依据字段来源（无任何明确值即需复核），基于数值是否等于 30/30/5。

#### R8 时区与掉落字段严格校验

**User Story:** AS 后台管理员, I want 掉落时刻与时区经过合法性校验才入库, so that 页面不会被 `GMT+2` 等非法时区污染。

**Acceptance Criteria:**
1. WHEN AI 返回 `drop_timezone`, the system SHALL 以 IANA 时区白名单（`Intl.supportedValuesOf('timeZone')` 加 UTC/GMT）校验，非法值时置 null。
2. WHEN 掉落时刻字段同时缺失来源标记, the system SHALL 将 `drop_hour` / `drop_minute` / `drop_second` / `drop_timezone` 整体置 null。
3. WHEN 数值越界（day 超 365 等）, the system SHALL 将字段裁到合理范围或置 null。
4. WHEN 页面明确标注完整时刻, the system SHALL 保留三件套并附 `page_explicit` 标记。

#### R9 IANA 总数动态化

**User Story:** AS 后台管理员, I want 抓取进度以真实 IANA 根区数量计算, so that 剩余待抓数不再依赖硬编码常量。

**Acceptance Criteria:**
1. WHEN 统计页加载, the system SHALL 从 IANA 根区权威清单（`tlds-alpha-by-domain.txt` 或等价来源）获取非 IDN 后缀总数，并缓存 1 天。
2. WHEN 根区数据获取失败, the system SHALL 回退到现有值并标注缓存时间，不中断页面。
3. WHEN 展示剩余数, the system SHALL 以「动态总数 − 已完成数」计算。

#### R10 Provider 熔断降权

**User Story:** AS 后台管理员, I want 故障 Provider 被短路跳过, so that 回退不再每次白等故障模型超时。

**Acceptance Criteria:**
1. WHEN 某 Provider 在滑窗（5 分钟）内连续失败达到阈值（3 次）, the system SHALL 熔断该 Provider 并跳过其调用。
2. WHEN 熔断达冷却期（10 分钟）, the system SHALL 放行单次探测请求进入半开状态。
3. WHEN 半开探测成功, the system SHALL 恢复该 Provider 正常参与排序。
4. WHEN 全部可用 Provider 均处于熔断, the system SHALL 即时失败并返回熔断汇总，跳过逐毫秒等待。

#### R11 用量统计与审计

**User Story:** AS 后台管理员, I want 查看各 AI Provider 调用量与成功率, so that 能评估配额消耗与模型质量。

**Acceptance Criteria:**
1. WHEN 每次 AI 调用完成或失败, the system SHALL 写入 `ai_call_log`（Provider/模型/用途/后缀/是否成功/耗时/错误摘录/时间戳）。
2. WHEN 管理员打开用量页, the system SHALL 聚合展示各 Provider 的成功数、失败数、平均耗时与最近错误。
3. WHEN 展示单条抓取记录, the system SHALL 附所用模型与调用耗时。
4. WHEN 熔断状态变化, the system SHALL 记录状态转移（open/half-open/closed）于审计日志。

#### R12 并行抓取与限流退避

**User Story:** AS 后台管理员, I want 页面发现过程更快且对注册局友好, so that 批量抓取不易触限熔断。

**Acceptance Criteria:**
1. WHEN `findRegistryLifecyclePage` 遍历候选链接, the system SHALL 以并发 3 的受限队列并行解析，而非串行等待。
2. WHEN Jina Reader 在某 TLD 连续失败 2 次, the system SHALL 对该 TLD 跳过剩余 Jina 策略并标记。
3. WHEN 调用方显式提供非 IANA `source_url`, the system SHALL 跳过生命周期子页发现阶段，直接抓取该 URL。
4. WHEN 抓取命中 Redis 或本地缓存且未过期, the system SHALL 复用缓存结果，跳过网络请求。

#### R13 TTL 刷新与批量刷新

**User Story:** AS 后台管理员, I want 已抓取成功的规则也能定期重抓与批量刷新, so that 注册局政策变更能被自动跟上。

**Acceptance Criteria:**
1. WHEN cron 挑选队列, the system SHALL 将 `scrape_status='ok'` 且 `updated_at` 超过刷新周期（180 天）的后缀以 stale 优先级纳入队列。
2. WHEN 管理员选择多行并触发批量重抓, the system SHALL 将所选已 ok 后缀重置为 `pending` 并逐个走 `scrapeTld`。
3. WHEN 批量重抓途中出现失败, the system SHALL 单条记录失败状态，其余后缀继续处理。
4. WHEN 手动编辑过的后缀参与刷新判断, the system SHALL 始终跳过 `manually_edited=true` 的后缀。

## Out of Scope

- 不改变 Next.js / next-auth 版本（按 MEMORY 中已确认的升级暂缓决策）。
- 不引入新的可视化图表依赖库；仪表盘图表使用轻量 DOM/CSS 实现。
- 不改变 Vercel 调度频率（tld-scrape cron 维持每日一次），仅优化批内处理。
- 不实现跨进程共享熔断状态；熔断与 Provider 统计保持函数实例级（与现有限流一致）。