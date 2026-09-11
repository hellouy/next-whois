# Tasklist — 批量前缀可用性检测增强（DNS 优先）

Feature Name: batch-availability-dns-first
Created: 2026-09-10

## 实施任务

- [x] **T1 扩展 dns-check.ts（DNS 快速探测 + wildcard 识别）**
  - 新增 `FastProbeResult` 类型与 `probeDomainFast(domain)`：并行 NS/A/AAAA/MX，`DNS_TIMEOUT_MS` 降至 2500ms，省略 SSL 探测，输出 registrationStatus/confidence/nameservers/ipv4/ipv6/mx/parked/parkingProvider/isWildcardA/allTimedOut
  - 新增 `detectWildcardA(domain)`：解析随机子域 `{random}.{domain}`，A/AAAA 与目标一致且非空 → true
  - 复用现有 `withDnsTimeout` 语义（NXDOMAIN/ENODATA → []，超时/ESERVFAIL → null）
  - 导出新增函数供 lookup-batch 复用；`probeDomain` 原样保留供单查链路使用

- [x] **T1.1 单元测试 dns-check.ts**
  - mock `dns/promises` 覆盖：有 NS、仅 A 无 NS（wildcard 真/假）、NXDOMAIN 全空、全超时、ESERVFAIL
  - 验证 parking 判定（Sedo/Afternic NS 命中）与 wildcard 随机子域对照逻辑

- [x] **T2 新增 lookupBatchAvailability（lookup.ts DNS 优先两段式判定）**
  - 新增 `BatchAvailability` 类型（registration/confidence/source/dnsProbe/result/error）
  - 实现阶段A：`probeDomainFast` → 有 NS/parked 直判 registered（source=dns）；仅 A/AAAA/MX 无 NS → `detectWildcardA` 分流；NXDOMAIN/ENODATA 全空 → 未注册候选；allTimedOut/unknown → 全通道兜底
  - 实现阶段B：未注册候选 → `lookupRdap`（404=available / 有数据按 status[] 判 reserved/premium/registered）；bootstrap 无服务 → `lookupWhoisWithCache` 守卫
  - 全通道兜底：调用 `lookupWhoisWithCache` 并将 dnsProbe/status/error 归一化为 BatchAvailability（`unregisteredResult` → available）
  - 修正缺陷：`lookupWhois` 的 unregistered 结果 `status:false` 归一化为 available（source 保留 whois/mixed）

- [x] **T2.1 单元测试 lookupBatchAvailability**
  - mock probeDomainFast/lookupRdap/lookupWhoisWithCache/缓存层：DNS registered 短路、RDAP 404 → available、RDAP reserved/premium → 对应状态、bootstrap 404 → WHOIS 守卫、allTimedOut → unknown、缓存命中与不缓存 unknown

- [x] **T3 批量 DNS 结论缓存（batchdns: 前缀短 TTL）**
  - 在 lookup.ts 实现 `batchdns:` 缓存读写（available/registered 缓存 15s；unknown/error 不缓存）
  - 复用现有 L1/L2/L3 缓存基础设施（l1Get/l1Set、getJsonRedisValueWithTtl、setJsonRedisValue）
  - 缓存键 `batchdns:{asciiDomain}`，与既有 `whois:` 键隔离

- [x] **T4 改造 /api/lookup-batch 后端**
  - `BatchItem` 类型扩展：`availability`、`confidence`、`source` 增加 `"dns"|"mixed"`，`dnsProbe` 类型换为 `FastProbeResult`
  - 任务函数由 `lookupWhoisWithCache` 换为 `lookupBatchAvailability`；`status` 归并为「有结论」（available/registered/reserved/premium → true）
  - 日志适配：`source` 透传 dns/rdap/whois/mixed；`classifyQueryOutcome` 沿用；`saveSearchRecord` 仅在 status && result 时写
  - 保持 CONCURRENCY=5、限流、批大小上限、require_login 门控不变

- [x] **T5 前端 batch-check.tsx（多前缀×多后缀 + 结果增强）**
  - 前缀区改多值输入（逗号/换行/空白分隔、去点小写化）；后缀分组与自定义后缀合并去重
  - 新增纯函数 `buildDomainMatrix(prefixes, tlds)`（去重、排序、总数）并做发起前上限拦截（anon 10 / 登录 500）
  - `getDomainStatus` 优先读 `item.availability`；`StatusBadge` 保留既有分类
  - 行内新增来源徽标（DNS/RDAP/WHOIS/混合）；CSV 导出新增「判定来源」列（含 UTF-8 BOM）

- [x] **T5.1 前端组合逻辑单元测试**
  - 单测 `buildDomainMatrix`：多前缀×多后缀去重、大小写归一、总数计算、空输入

- [x] **T6 验证回归**
  - `npx tsc --noEmit` 通过；`npx vitest run` 全量通过（含既有 260 tests）
  - dev server 5000 手动冒烟：多前缀+多后缀组合数、DNS 徽标、CSV 新列、example.com（DNS registered）/ example.bb（兜底 available）抽查

## 备注

- 判定链路：DNS 优先 → 有 NS/停放直判已注册；NXDOMAIN 走 RDAP 404 确认；仅 A 无 NS 用随机子域对照识别 wildcard；全超时退全通道兜底
- `probeDomain`（单查在用）与 `lookupWhois` 均不改动语义，仅新增 `probeDomainFast`/`lookupBatchAvailability`
- 保留/溢价（含 `.cn` 保留词 getCnReservedSldInfo）路径优先，禁止覆盖为 available
- `available` 必有 source，前端靠它显示依据徽标