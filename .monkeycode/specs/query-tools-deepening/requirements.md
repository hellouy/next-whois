# Requirements Document — 查询工具深度增强（DNS / IP / SSL / ICP / HTTP）

Feature Name: query-tools-deepening
Created: 2026-09-10
Status: Confirmed

确认范围（2026-09-10）：
- R1 DNS：DS/DNSKEY/NSEC/NSEC3/NAPTR/TLSA/SMIMEA 全部加入
- R4/R5 IP：DNSBL 黑名单 + 反向 DNS 多解析器对照 全做
- R9 ICP：批量导出采用标准 6 列（查询词/单位/备案号/服务名称/更新时间/性质），不含负责人与地址
- R6/R7/R8 SSL：CT 日志 + OCSP 吊销 + TLS 协议/密码套件详情 全做
- R10/R11/R12 HTTP：分阶段计时 + Cookie 安全分析 + TLS/证书摘要 全做

## Introduction

本站提供五个独立的查询工具，各自当前能力有限：

1. **DNS Lookup**（`/dns`，后端 `/api/dns/records.ts` + `/api/dns/txt.ts`）：支持 11 种记录类型（A/AAAA/MX/NS/CNAME/TXT/SOA/CAA/PTR/SRV/HTTPS），4 个 DoH 解析器并发对照但结果合并去重展示，缺少 DNSSEC 相关类型（DS/DNSKEY/NSEC）、缺少传播一致性视图、缺少 DMARC/SPF 专项解析。
2. **IP / ASN**（`/ip`，后端 `/api/ip/lookup.ts`）：ip-api.com 地理 + RDAP 网段/ASN 信息，10 分钟缓存；缺少黑名单/信誉情报、缺少反向 DNS 多解析器对照。
3. **SSL Cert**（`/ssl`，后端 `/api/ssl/cert.ts`）：直连 TLS 握手，返回证书详情/SAN/证书链；缺少证书透明日志（CT）查询、缺少 OCSP 吊销状态、缺少 TLS 协议版本/密码套件详情。
4. **ICP Filing**（`/icp`，后端 `/api/icp/query.ts`）：MIIT 直连 + legacy 兜底，支持分页；仅支持单查询关键词、缺少批量查询与结果导出。
5. **HTTP Check**（`/http`，后端 `/api/http/check.ts`）：状态码/重定向链/响应时间/7 个安全头评分；缺少 TLS 握手详情（协议/证书）、缺少分阶段计时（连接/TTFB/下载）、缺少 Cookie 安全属性分析。

本功能对五个工具做深度增强：补充缺失的记录类型与专项解析、加入信誉情报与传播视图、加入 CT/OCSP/TLS 详情、加入批量与导出、加入分阶段计时与 Cookie 分析。所有增强保持既有技术栈（Next.js pages API + DoH/RDAP/公开 API + Redis 缓存 + 8 语言 i18n）与限流/SSRF 防护模式。

## Glossary

- **传播视图（Propagation View）**：按解析器逐一展示 DNS 应答并标注差异，用于观察 DNS 传播不一致。
- **DNSSEC 状态**：通过 DS（父区）与 DNSKEY（子区）记录存在性判断域名是否启用 DNSSEC。
- **DMARC 专项**：自动查询 `_dmarc.{domain}` TXT 记录并解析 `v=DMARC1` 策略（p/sp/rua/ruf/pct）。
- **SPF 专项**：从 `{domain}` TXT 记录中筛选 `v=spf1` 并解析机制（include/ip4/all 等）。
- **黑名单/信誉（DNSBL/Threat）**：通过常见 DNSBL（Spamhaus ZEN/SBL/XBL/PBL、Barracuda、SpamCop、SORBS 等）查询 IP，判定是否被列为垃圾邮件/恶意来源。
- **证书透明日志（CT）**：从公开 CT 日志（crt.sh）查询某域名下被签发的全部证书。
- **吊销状态（OCSP）**：通过 OCSP responder 查询证书吊销状态（good/revoked/unknown）。
- **分阶段计时（Timing Breakdown）**：一次 HTTP 请求拆分为 DNS 解析、TCP 连接、TLS 握手、首字节（TTFB）、总耗时。
- **Cookie 安全分析**：检查每个 Set-Cookie 的 Secure/HttpOnly/SameSite 属性并给出风险评级。

## Requirements

### R1 DNS Lookup 补充 DNSSEC 相关记录类型

**User Story:** AS 域名技术用户, I want 查询 DS/DNSKEY/NSEC/NSEC3 等 DNSSEC 记录, so that 我能判断域名是否启用并验证 DNSSEC 链。

**Acceptance Criteria:**

1. WHEN 用户在 DNS 页面选择记录类型, the system SHALL 在现有 11 种类型基础上新增 `DS`、`DNSKEY`、`NSEC`、`NSEC3`、`NAPTR`、`TLSA`、`SMIMEA`、`CAA`（若缺失）等类型的解析。
2. WHEN 用户查询 DS 或 DNSKEY, the system SHALL 解析标准字段（DS: key tag/algorithm/digest type/digest；DNSKEY: flags/protocol/algorithm/key）并结构化展示。
3. WHEN 用户查询任一类型且至少一个解析器返回记录, the system SHALL 展示该类型的存在性；WHEN 域名同时存在 DS 与 DNSKEY, the system SHALL 标注「DNSSEC 已启用」。
4. IF 查询的域名无任何记录, the system SHALL 返回 `found:false` 并提示未查询到记录，不得误报错误。

### R2 DNS Lookup 增加传播视图与解析器一致性

**User Story:** AS 域名技术用户, I want 查看每个解析器各自的应答及差异, so that 我判断 DNS 是否已全球传播一致。

**Acceptance Criteria:**

1. WHEN 用户查询成功, the system SHALL 在合并结果之外，按解析器逐一展示原始应答与往返延迟。
2. WHEN 不同解析器返回不同记录集合, the system SHALL 将不一致的解析器标注「不一致」，并列出仅在部分解析器出现的记录。
3. WHEN 所有解析器返回完全一致, the system SHALL 标注「各解析器结果一致」。
4. IF 某解析器超时/失败, the system SHALL 单独标注该解析器错误，不参与合并结果。

### R3 DNS Lookup 增加 SPF / DMARC 专项解析

**User Story:** AS 邮件域名管理员, I want 一键查看 SPF 与 DMARC 配置, so that 我确认邮箱认证策略配置正确。

**Acceptance Criteria:**

1. WHEN 用户在 DNS 页面选择「邮件认证（SPF/DMARC）」预设, the system SHALL 自动查询 `{domain}` 的 TXT（SPF）与 `_dmarc.{domain}` 的 TXT（DMARC）。
2. WHEN 查询到 SPF 记录, the system SHALL 解析并结构化展示 `v=spf1` 机制（ip4/ip6/include/mx/redirect/all 等）并给出通过/软失败/失败策略结论。
3. WHEN 查询到 DMARC 记录, the system SHALL 解析并展示 `p`（none/quarantine/reject）、`sp`、`rua`、`ruf`、`pct` 字段，并给出策略强度评级。
4. IF 域名无 SPF 或 DMARC 记录, the system SHALL 明确提示「未配置」，不得把空结果误当配置存在。

### R4 IP / ASN 增加黑名单信誉检测

**User Story:** AS 安全分析用户, I want 查看 IP 是否在常见黑名单中, so that 我评估该 IP 的信任度。

**Acceptance Criteria:**

1. WHEN 用户查询 IPv4 地址, the system SHALL 在返回地理信息的同时查询一组常用 DNSBL（Spamhaus ZEN/SBL/XBL/PBL、Barracuda、SpamCop、SORBS 等）。
2. WHEN DNSBL 返回命中的 A 记录, the system SHALL 展示黑名单名称、返回码（127.0.0.x）、对应类型（垃圾邮件/僵尸网络/开放代理等）与查询延迟。
3. WHEN 所有 DNSBL 均未命中, the system SHALL 展示「未在黑名单中」并标注检测覆盖的黑名单数量。
4. IF DNSBL 查询超时或服务不可达, the system SHALL 单独标注该黑名单「不可达」并继续检测其余，不得中断整体结果。
5. WHEN 用户查询的是 IPv6 或 ASN, the system SHALL 跳过 DNSBL 检测并展示说明文字。

### R5 IP / ASN 增加反向 DNS 多解析器对照

**User Story:** AS 网络管理员, I want 查看 PTR 反向解析在多个 DNS 服务商的差异, so that 我确认 rDNS 配置一致。

**Acceptance Criteria:**

1. WHEN 用户查询 IP 地址, the system SHALL 并发查询该 IP 在至少 2 个解析器上的 PTR 反向解析结果。
2. WHEN 反向解析存在, the system SHALL 展示解析到的域名；WHEN 不同解析器返回不同结果, the system SHALL 标注不一致。
3. IF 某解析器查询失败, the system SHALL 单独标注错误，不影响其他结果展示。

### R6 SSL Cert 增加证书透明日志（CT）查询

**User Story:** AS 安全审计用户, I want 查看某域名在公开 CT 日志中的全部证书, so that 我审计历史与子域证书签发。

**Acceptance Criteria:**

1. WHEN 用户查询域名的 SSL 证书, the system SHALL 额外调用 crt.sh 查询该域名的 CT 日志记录。
2. WHEN CT 查询成功, the system SHALL 展示证书列表（名称值、签发时间、证书编号），数量超过阈值时分页展示。
3. WHEN CT 查询失败或超时, the system SHALL 将 CT 区块标记为不可用并保持证书详情可查看，不得整体失败。
4. IF 用户查询的是裸 IP, the system SHALL 跳过 CT 查询。

### R7 SSL Cert 增加 OCSP 吊销状态

**User Story:** AS 安全审计用户, I want 查看证书当前吊销状态, so that 我确认证书仍有效未吊销。

**Acceptance Criteria:**

1. WHEN 证书详情返回, the system SHALL 尝试从证书 OCSP 服务器查询吊销状态。
2. WHEN OCSP 返回, the system SHALL 展示状态（good/revoked/unknown）与查询延迟；WHEN 状态为 revoked, the system SHALL 高亮警示。
3. IF 证书无 OCSP 服务器或查询失败, the system SHALL 标注「OCSP 不可用」并保持其他字段正常展示。

### R8 SSL Cert 增加 TLS 协议与密码套件详情

**User Story:** AS 安全审计用户, I want 查看服务器支持的 TLS 版本与握手密码套件, so that 我评估 TLS 配置安全性。

**Acceptance Criteria:**

1. WHEN 证书查询完成, the system SHALL 展示本次握手使用的 TLS 协议版本、密码套件名称、密钥交换与强度。
2. IF 服务器支持, the system SHALL 额外探测 TLS 1.0/1.1/1.2/1.3 可用性并标注各版本是否支持，供安全评级。
3. WHEN 探测结果汇总, the system SHALL 给出 TLS 配置安全评级（安全/需关注/不安全）与说明。

### R9 ICP Filing 增加批量查询与结果导出

**User Story:** AS 网站运营者, I want 一次查询多个域名/关键词并导出结果, so that 我高效核对备案信息。

**Acceptance Criteria:**

1. WHEN 用户在 ICP 页面输入多个查询词（逗号/换行/空格分隔）, the system SHALL 逐词调用现有查询通道并合并展示结果。
2. WHEN 批量结果返回, the system SHALL 保留每条结果的来源（MIIT/legacy）、命中条数、查询状态（成功/失败）。
3. WHEN 批量查询完成, the system SHALL 提供 CSV 导出（UTF-8 BOM），列含查询词、单位名称、备案号、服务名称、更新时间等。
4. IF 批量中部分查询失败, the system SHALL 在结果中标注失败项并允许单独重试，不得丢弃成功项。
5. WHEN 批量查询的并发请求发起, the system SHALL 遵守现有 `queryMiitIcp` 的 12 秒超时与限流（页面并发 ≤ 3）。

### R10 HTTP Check 增加分阶段计时

**User Story:** AS 性能分析用户, I want 查看一次请求的分阶段耗时, so that 我定位性能瓶颈。

**Acceptance Criteria:**

1. WHEN 用户发起 HTTP 检查, the system SHALL 拆解并展示 DNS 解析、TCP 连接、TLS 握手（若 HTTPS）、首字节（TTFB）、内容传输、总耗时。
2. WHEN 目标为 HTTPS, the system SHALL 额外展示 TLS 握手耗时与使用的协议版本、密码套件。
3. IF 任一分阶段失败, the system SHALL 标注该阶段为失败并给出剩余阶段耗时，不得整体失败。
4. IF 用户查询的是纯 IP, the system SHALL 将 DNS 阶段标注为「不适用」。

### R11 HTTP Check 增加 Cookie 安全属性分析

**User Story:** AS Web 安全用户, I want 查看 Set-Cookie 的安全属性, so that 我识别不安全 Cookie。

**Acceptance Criteria:**

1. WHEN 响应头包含 Set-Cookie, the system SHALL 解析每个 Cookie 的 name、domain、path、expires、Secure、HttpOnly、SameSite 属性。
2. WHEN Cookie 缺失 Secure 或 HttpOnly 或 SameSite, the system SHALL 分别标注风险（缺失项名称）并给出整体 Cookie 安全评级。
3. IF 响应无任何 Set-Cookie, the system SHALL 标注「无 Cookie」。

### R12 HTTP Check 增加 TLS 握手与证书摘要

**User Story:** AS Web 安全用户, I want 在 HTTP 检查中同时看到 TLS 与证书摘要, so that 我不必跳转到 SSL 工具。

**Acceptance Criteria:**

1. WHEN 目标为 HTTPS, the system SHALL 展示握手协议版本、证书 CN/SAN、有效期、是否已过期与是否受信任。
2. IF 证书已过期或不受信任, the system SHALL 在结果中高亮警示。
3. IF 目标是 HTTP, the system SHALL 展示「非 HTTPS」提示且不执行 TLS 相关检测。

### R13 增强后的缓存与限流保持兼容

**User Story:** AS 平台运营者, I want 所有增强沿用既有缓存与限流, so that 治理与稳定性不退化。

**Acceptance Criteria:**

1. WHEN 各增强 API 被调用, the system SHALL 沿用现有 `checkRateLimit` 限流与 SSRF 防护（`isBlockedHost`）。
2. WHEN IP/CT 等结果产生, the system SHALL 复用 Redis 缓存（TTL：DNSBL 10 分钟、CT 1 小时、OCSP 30 分钟、反向解析 10 分钟）。
3. IF 上游（crt.sh / OCSP / DNSBL）不可达, the system SHALL 降级返回局部结果并标注不可用项，不得阻塞主查询。

### R14 多语言与展示一致

**User Story:** AS 平台用户, I want 新增内容在 8 种语言下正常显示, so that 展示无缺漏。

**Acceptance Criteria:**

1. WHEN 新增任何界面文案, the system SHALL 同步更新全部 8 个 locale 文件，`en.json` 优先作为键源。
2. WHEN 状态徽标（DNSSEC/DNSBL/OCSP/TLS 评级）出现, the system SHALL 采用与现有 `StatusBadge`/`SourceBadge` 一致的样式体系。

## Out of Scope

- 不改动单域名结果页（`[...query].tsx`）查询链路与判定风格。
- 不做端口扫描（除 HTTPS 常规端口探测外）、不新增任何网络攻击类检测。
- 不改动 MIIT 上游查询协议本身（`queryMiitIcp` 接口签名保持兼容）。
- 不引入需付费/需注册的新第三方 API（全部使用免费公开接口）。
