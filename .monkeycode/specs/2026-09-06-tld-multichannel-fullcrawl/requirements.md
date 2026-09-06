# Requirements Document — TLD 生命周期多渠道全量抓取

Feature Name: tld-multichannel-fullcrawl
Created: 2026-09-06
Status: Draft

## Introduction

将 TLD 生命周期抓取从「补 90 个缺失记录」升级为「IANA 根区全量 TLD + 多渠道交叉验证」：

**问题现状**：`tld_rules` 仅 237 条（含 146 no_data、43 warn_defaults、48 ok），而 IANA 根区有 1400+ TLD，缺口约 1200+。且当前抓取只走「IANA 页 → 注册局生命周期页 → 单一 AI」一条渠道，注册局官网常因反爬、JS 渲染、页面缺失而拿不到数据，大量 TLD 只能落到 ICANN 默认值 30/30/5，准确度不足、几乎无 TLD 有精确掉落时间。

**改造目标**：以 IANA 根区文件为全量清单，对一个 TLD 并行采集多数据源（注册局官网 / 大型注册商政策页 / ICANN Registry Agreement / 百科与第三方表格 / 搜索引擎补 URL / Wayback 快照回退），全部原文汇入 AI 综合裁决，按权威源加权输出最终宽限/赎回/待删/掉落时间并记录渠道引用与置信度。全量直接后台跑，可断点续传。

## Glossary

- **TLD 生命周期规则（tld_rules）**：每个后缀的宽限期/赎回期/待删除期/提前删除天数/掉落瞬间字段，`scrape_status` 取值 pending / ok / warn_defaults / failed / no_data
- **渠道（Channel）**：单一数据来源，取值 `registry`（注册局官网）/ `registrar`（大型注册商政策页）/ `icann`（ICANN Registry Agreement）/ `wiki`（Wikipedia 等第三方表格）/ `search`（搜索引擎检索正文）/ `wayback`（Wayback Machine 快照）/ `iana`（IANA 委托页本身）
- **权威优先级（Authority）**：来源可信度顺序：`registry` > `registrar` > `icann` > `wiki` > `search` > `wayback` > `iana`
- **AI 综合裁决（AI Arbitration）**：把多个渠道的抓取原文汇总到单个 AI 调用，要求 AI 按权威优先级加权输出统一生命周期数值 + 每个字段的来源渠道引用
- **字段来源标记（Field Source）**：各实际生效字段来自哪个渠道：`registry_explicit` / `registrar_explicit` / `registry_inferred` / `industry_default`
- **IANA 根区文件**：`https://data.iana.org/TLD/tlds-alpha-by-domain.txt`，权威的全量后缀清单（约 1450+ ASCII 非 IDN）

## Requirements

### R1 全量 TLD 清单

**User Story:** AS 后台管理员, I want 以 IANA 根区文件为全量清单补齐全部后缀, so that tld_rules 不再只有 237 条而覆盖 IANA 全量。

**Acceptance Criteria:**
1. WHEN 批量抓取开始, the system SHALL 从 IANA 根区文件读取全部 ASCII 非 IDN TLD 作为目标清单，并在网络失败时回退到内置 CC_TLDS + gTLD 种子列表。
2. WHEN 目标清单中的 TLD 不在 `tld_rules`, the system SHALL 先以默认值 30/30/5 种子入库（`scrape_status=pending`）再走抓取流程。
3. WHEN 抓取结束后, the system SHALL 对每个 TLD 留下 `needs_admin_review` 标记，明确区分「真实数据 / 默认值兜底 / 无数据」。

### R2 多渠道数据采集

**User Story:** AS 后台管理员, I want 同一 TLD 从多个独立数据源采集原文, so that 单一来源缺失或错误时仍能交叉验证。

**Acceptance Criteria:**
1. WHEN 抓取一个 TLD, the system SHALL 至少尝试下列渠道：注册局生命周期页（既有 IANA 发现）、大型注册商政策页（Namecheap/GoDaddy/Cloudflare/Ionos 等 TLD 政策 URL 模板）、ICANN Registry Agreement（对 gTLD）、Wikipedia 生命周期段。
2. WHEN 注册局官网或注册商页面抓取失败（反爬/JS/404）, the system SHALL 依次回退搜索引擎检索（Bing，补生命周期页 URL）、Wayback Machine 快照。
3. WHEN 任一渠道原文命中生命周期关键词, the system SHALL 保留该渠道 `{channel, url, text_excerpt}` 快照用于交叉验证。
4. WHEN 全部渠道均在规定超时（默认每渠道 5-15s）内无结果, the system SHALL 标记该 TLD 失败或降级为默认值，不阻塞其余 TLD。

### R3 注册商渠道

**User Story:** AS 后台管理员, I want 从大型注册商政策页与 ICANN 协议获取各 TLD 生命周期, so that 注册局官网缺数据时仍有权威来源。

**Acceptance Criteria:**
1. WHEN TLD 属于 gTLD, the system SHALL 尝试 ICANN Registry Agreement 生命周期条款（Registry Agreement 统一规定 Add/Renew/Transfer/Delete 宽限期）。
2. WHEN 注册局官网无数据, the system SHALL 依次尝试下列注册商公开 TLD 政策页 URL 模板（按 TLD 动态构造，抓取限频）：
   - Namecheap: `https://www.namecheap.com/domains/registration/gtld/{tld}/`
   - GoDaddy: `https://www.godaddy.com/en-ie/tlds/{tld}-domain`
   - Cloudflare: `https://www.cloudflare.com/tld-policy/`
   - Ionos: `https://www.ionos.com/domains/domain-offers/{tld}-domain`
3. WHEN 任一注册商渠道返回 HTTP 403/429, the system SHALL 记录该渠道失败并继续下一渠道/回退，不共享已失败的降频惩罚。
4. WHEN 渠道采集到数值字段（grace/redemption/pending/drop）, the system SHALL 在 AI 裁决时附带明确来源标识，供权威加权使用。

### R4 浏览器/检索渠道

**User Story:** AS 后台管理员, I want 通过搜索引擎与存档回退补齐注册局官网抓不到的数据, so that 反爬和 JS 站点仍有数据可采。

**Acceptance Criteria:**
1. WHEN 注册局官网与已知渠道均未命中, the system SHALL 优先用 Bing 检索 `"{tld} domain grace period redemption"` 类查询，从结果正文提取生命周期信息，正式页用 `https://www.bing.com/search?q=...` 带合规 UA；Bing 失败回退 Google（失败较多，仅条件调用）。
2. WHEN 原始注册局页面抓取失败但 Wayback 可用, the system SHALL 尝试 `https://web.archive.org/web/{href}/{targetUrl}` 快照。
3. WHEN 搜索结果或快照命中生命周期关键词, the system SHALL 将对应渠道文本纳入 AI 裁决，并标记 `fetch_via=search|wayback`。

### R5 AI 综合裁决与权威加权

**User Story:** AS 后台管理员, I want 多来源数据经 AI 综合并加权, so that 冲突时以权威来源为准而非随机单源。

**Acceptance Criteria:**
1. WHEN 一个 TLD 有 ≥1 个渠道原文, the system SHALL 将全部渠道原文（含渠道名与 URL）汇总进一次 AI 调用，要求 AI 输出统一的 grace/redemption/pending/drop 数值，并对每个字段注明来源渠道。
2. WHEN 多个渠道数值冲突, the system SHALL 按权威优先级 `registry > registrar > icann > wiki > search > wayback > iana` 裁决，高优先级渠道值优先。
3. WHEN 裁决结果中 3 个核心字段（grace/redemption/pending）与 ICANN 默认值 30/30/5 完全一致且无任何渠道显式支撑, the system SHALL 标记 `warn_defaults` 并 `needs_admin_review=TRUE`。
4. WHEN 已有 `scrape_status='ok'` 记录其值来源于人工编辑或 curat-database, the system SHALL 在非 `--force` 模式下保护该值不被单一条新渠道覆盖。

### R6 掉落时间与时区校验

**User Story:** AS 后台管理员, I want 精确掉落时间只在有意义时落库, so that 无时区数据不污染 drop 字段。

**Acceptance Criteria:**
1. WHEN AI 返回 `drop_hour/drop_minute`，the system SHALL 校验 0-23 / 0-59 范围内；越界置 null。
2. WHEN AI 返回 `drop_timezone`, the system SHALL 使用 IANA 时区白名单（`Intl.supportedValuesOf('timeZone')`）校验；非白名单（如 GMT+2、CET、垃圾值）置 null。
3. WHEN 至少一个渠道通过 `page_explicit` 来源支撑 drop 三件套, the system SHALL 才保留 drop 值；否则置 null。

### R7 全量后台执行与断点续传

**User Story:** AS 后台管理员, I want 全量抓取可中断、可续传、可监控, so that 1400+ TLD 长时间运行安全可靠。

**Acceptance Criteria:**
1. WHEN 全量抓取启动, the system SHALL 支持 `--concurrency`（默认 2）、渠道间超时、整体限时，并在 SIGTERM/SIGINT 时优雅结束当前批次。
2. WHEN 抓取中断后重新运行同命令（不带 --force）, the system SHALL 依据 `scrape_status` 跳过已成功与已穷尽的 TLD，仅重试失败/默认值/未处理项。
3. WHEN 每个 TLD 抓取结束, the system SHALL 输出进度（done/skip/err）、耗时与默认值计数。
4. WHEN 一个 TLD 连续多次（默认 3 次）仅得到默认值或失败, the system SHALL 升级标记为 `no_data`，待人工核查，避免无限重试。

### R8 数据落库与置信度

**User Story:** AS 后台管理员, I want 落库数据包含渠道引用与置信度, so that 前台与后台可区分可信来源。

**Acceptance Criteria:**
1. WHEN 抓取结果写回 `tld_rules`, the system SHALL 记录 `source_url`（AI 判定主来源）、`confidence`（curated=high / 多渠道路由中>=2 来源一致=high / 单渠道明确=medium / 默认值=low）、`ai_reasoning`（含渠道引用摘要）、`fetch_strategy`（渠道路由说明）。
2. WHEN 同一 TLD 有多渠道数据, the system SHALL 将渠道快照写入新增 `channels JSONB` 列，结构 `[{channel,url,text_excerpt,status}]`（text_excerpt 截断 1200 字符），供后台展示与核查。
3. WHEN 写库成功后, the system SHALL 缓存失效（若存在 lifecycle-overrides 缓存）以确保 /dashboard 展示一致。

## Out of Scope

- 改动对外查询链路（WHOIS/RDAP 查询不受影响）。
- 引入新的前端 UI 页面（渠道详情展示属后续增强）。
- IDN（xn--）后缀的国际化生命周期抓取。