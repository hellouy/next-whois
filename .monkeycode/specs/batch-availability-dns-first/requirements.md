# Requirements Document — 批量前缀可用性检测增强（DNS 优先）

Feature Name: batch-availability-dns-first
Created: 2026-09-10
Status: Draft

## Introduction

批量查询页 `/batch-check`（`src/pages/batch-check.tsx`）当前只支持「单个前缀 × 按分组（popular/gtld/cctld/all/custom）选定的 TLD 列表」，且每个域名的可用性判定完全依赖 WHOIS/RDAP 双通道（`src/lib/whois/lookup.ts` 的 `lookupWhois` → `lookupWhoisWithCache`），DNS 探测（`src/lib/whois/dns-check.ts` 的 `probeDomain`）仅作为成功/失败响应里的附加信息，不参与判定。

本功能将该批量场景升级为「多前缀 × 多后缀」的笛卡尔积组合，并改为 DNS 优先的可用性探测：DNS 给出确定性结论（含停放/通配符判别）时不再走 WHOIS/RDAP；仅当 DNS 无信息或置信度不足（超时、ESERVFAIL、ambiguous）时，才用 WHOIS + RDAP 兜底，以提升批量检测的准确性与速度。

三个明确的准确性痛点：

1. **通配符 DNS 误判**：部分 TLD 对未注册域名返回 wildcard A 记录（无 NS），当前 `probeDomain` 会把「有 A/AAAA/MX 但无 NS」判为已注册（medium），导致大量本可注册域名被误标为已注册。
2. **已注册域名被判可注册**：DNS 探测因各查询全部超时返回 `unknown`，后续若误当作「可注册」展示即为误报。
3. **真未注册却被误以为可注册**：DNS 层看似空记录，但域名实际已被注册而只是未配置 DNS（NXDOMAIN 且无记录的域名有时已被注册或处于保留/溢价状态），只能靠 WHOIS/RDAP 二次确认，不能只凭 DNS 空记录就断言可注册。

## Glossary

- **前缀（Prefix）**：批量输入中的域名主体部分，可多个；组合后即为 `{prefix}.{tld}` 的 SLD。
- **后缀（Suffix/TLD）**：域名后缀，来自现有分组（popular/gtld/cctld/all）或自定义输入，可多个。
- **笛卡尔积（Cartesian Product）**：前缀集合 × 后缀集合的全组合域名列表。
- **DNS 探测（DNS Probe）**：`probeDomain`，并行查询 NS/A/AAAA/MX（+ 停放 NS 检测），输出 `registrationStatus: registered | unregistered | unknown` 与 `confidence: high | medium | low`。
- **停放/溢价（Parking/Premium）**：域名虽未配置自建 DNS 但 NS 指向停放平台（Sedo/Afternic/Bodis 等），或注册局以溢价标价。
- **通配符 DNS（Wildcard DNS）**：注册局/主机商对未注册（或任意）子域返回的应答（通常只有 A/AAAA、无 NS），干扰「无记录 = 未注册」的推断。
- **兜底（Fallback）**：DNS 无法给出确定性可用性结论时，回退到 WHOIS + RDAP 通道（沿用现有 `lookupWhois` 的未注册判定：RDAP 404、`isNotRegisteredWhoisResponse`、`WHOIS_NOT_REGISTERED_PATTERNS`）。

## Requirements

### R1 输入拆分为前缀与后缀，支持笛卡尔积组合

**User Story:** AS 域名批量检测用户, I want 同时输入多个前缀和多个后缀并两两组合检测, so that 一次批量操作覆盖所有候选组合。

**Acceptance Criteria:**

1. WHEN 批量页加载, the system SHALL 提供两个输入区：前缀区与后缀区，各自允许输入多个值（逗号/换行/空白分隔）。
2. WHEN 用户选择后缀分组（popular/gtld/cctld/all）, the system SHALL 将分组展开为对应的 TLD 列表，与任意数量的自定义后缀合并去重后参与组合。
3. WHEN 用户切换到自定义后缀, the system SHALL 将自定义后缀与已选分组后缀合并，共同参与与全部前缀的笛卡尔积组合。
4. WHEN 前缀或后缀解析完成, the system SHALL 生成去重后的域名列表 `prefix × tld`，并给出组合总数提示。
5. IF 组合总数超过（匿名 10 / 登录 500）上限, the system SHALL 在发起请求前拦截并提示用户缩减前缀或后缀数量，不得静默截断。

### R2 DNS 优先探测，有确定性注册证据直接判定并跳过 WHOIS

**User Story:** AS 批量检测用户, I want DNS 已确认被注册的域名直接标为已注册且不再发起慢速 WHOIS, so that 批量检测更快。

**Acceptance Criteria:**

1. WHEN 批量检测某域名, the system SHALL 先并行执行 DNS 探测（NS/A/AAAA/MX + 停放 NS 检测）。
2. WHEN DNS 返回强注册证据（存在 NS 记录）, the system SHALL 直接判定该域名「已注册」（high 置信），且不发起 WHOIS/RDAP。
3. WHEN DNS 返回停放平台 NS（Sedo/Afternic/Bodis 等）, the system SHALL 判定「已注册」并标注为停放/溢价，且不发起 WHOIS/RDAP。
4. WHEN DNS 返回「无任何记录且非超时」（NXDOMAIN/ENODATA 应答）, the system SHALL 判定「可注册（高置信候选）」，并通过 RDAP 快速确认（复用 RDAP 404 = 未注册 / 有数据 = 按数据判定），不发起慢速 WHOIS。
5. IF DNS 无记录且该 TLD 无 RDAP 服务（bootstrap 404）, the system SHALL 以 WHOIS 兜底确认后才最终标记「可注册」。
6. WHEN DNS 探测无法给出确定性结论（全部超时/ESERVFAIL/ambiguous）, the system SHALL 进入 R3 的 WHOIS+RDAP 兜底路径。

### R3 DNS 无确定性结论时以 WHOIS + RDAP 兜底

**User Story:** AS 批量检测用户, I want DNS 说不清的域名由 WHOIS/RDAP 兜底判定, so that 尽量减少漏判与误判。

**Acceptance Criteria:**

1. WHEN DNS 探测为 `unknown` 或置信不足, the system SHALL 回退到现有 `lookupWhois` / `lookupWhoisWithCache` 链路，复用其全部未注册判定（RDAP 404、WHOIS not-registered 文本、注册局保留/溢价状态）。
2. WHEN 兜底完成且判定为「可注册」, the system SHALL 在结果中标记判定来源（dns | whois | rdap）以便前端展示提示文案。
3. WHEN 兜底判定失败（超时/无服务器）且 DNS 亦无可注册证据, the system SHALL 标记该条为「不确定/错误」而不得标记为「可注册」。

### R4 通配符（wildcard）DNS 识别，避免把可注册域名误标为已注册

**User Story:** AS 批量检测用户, I want 系统识别通配符 DNS 应答, so that 仅返回 A/AAAA 而无 NS 的未注册域名不被误判为已注册。

**Acceptance Criteria:**

1. WHEN DNS 探测发现存在 A/AAAA/MX 记录但没有任何 NS 记录, the system SHALL NOT 直接判定已注册，而将其视为 ambiguous（低置信注册证据）。
2. WHEN ambiguous 状态出现, the system SHALL 通过解析该域名下一个随机子域作对照：若随机子域返回与目标相同的 A/AAAA 记录，则确认该 TLD 对未注册域名启用通配应答，判定为 wildcard。
3. WHEN 判定为 wildcard 通配应答, the system SHALL 将该域名归入「可注册（需兜底确认）」候选集，进入 WHOIS/RDAP 兜底而非直接标为已注册。
4. WHEN 后续兜底确认该域名确实无注册记录, the system SHALL 最终标记为「可注册」。

### R5 保留/溢价/注册局状态域名不得标为可注册

**User Story:** AS 批量检测用户, I want 保留、溢价与注册局特殊状态域名不被误标为可注册, so that 我可注册的结论可信。

**Acceptance Criteria:**

1. WHEN DNS 判定未注册但 WHOIS/RDAP 兜底发现 `registry-reserved` / `registry-premium` / 阻止 / 其他注册局保留状态, the system SHALL 按对应状态标记（reserved / premium），不得标记为可注册。
2. WHEN 域名落入现有 `.cn` 保留词（`getCnReservedSldInfo`）或前端 `getDomainStatus` 已识别的预留状态, the system SHALL 保持既有 reserved/premium 展示，不受 DNS 优先路径改写。

### R6 结果展示与导出保持既有语义，额外标注检测结论来源

**User Story:** AS 批量检测用户, I want 结果表格与 CSV 导出继续给出可注册/已注册/保留/溢价/错误分类, so that 我无需学习新交互。

**Acceptance Criteria:**

1. WHEN 批量结果返回, the system SHALL 沿用现有可注册（available）/ 已注册（registered）/ 保留（reserved）/ 溢价（premium）/ 错误（error）状态分类与徽标样式。
2. WHEN 某条结果为 DNS 判定, the system SHALL 在行内以轻量徽标标注「DNS」，兜底结果标注「WHOIS/RDAP」或「混合」，展示给用户以说明依据。
3. WHEN 导出 CSV, the system SHALL 在现有字段基础上新增「判定来源」列（dns / whois / rdap / mixed / unknown）。
4. WHEN 存在 DNS 含无记录应答（NXDOMAIN）但尚未完成兜底的中间态, the system SHALL 以「检测中（DNS 已应答，WHOIS 兜底中）」状态呈现，不得预标为可注册。

### R7 批量接口与限流保持兼容

**User Story:** AS 平台运营者, I want 新探测路径接入现有 `/api/lookup-batch` 且不破坏限流、日志与缓存, so that 治理与统计能力不退化。

**Acceptance Criteria:**

1. WHEN 批量请求到达 `/api/lookup-batch`, the system SHALL 沿用现有鉴权、速率限制（anon 5/auth 15/sub 40 per 60s）、`require_login` 门控与批大小上限（anon 10 / auth 500）。
2. WHEN 每条域名完成探测, the system SHALL 照常写入 `query_logs` 与 `search_history`（统计口径不变），`source` 字段补充 `dns` 取值。
3. WHEN DNS 判定成功省略 WHOIS/RDAP, the system SHALL 使用较短的缓存 TTL（避免 WHOIS 与 DNS 结论长期冲突），并继续遵守既有缓存分层（L1/L2/L3）与 SWR 机制。

## Out of Scope

- 单域名结果页 `src/pages/[...query].tsx` 的查询链路与可用性判定风格：本功能只改动批量通道；单查仍沿用 RDAP/WHOIS 双通道。
- 修改现有 TLD 生命周期抓取、后台批量扫描脚本（`scripts/batch-scrape.mjs`）等运营功能。