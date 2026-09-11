# Tasklist — 查询工具深度增强（DNS / IP / SSL / ICP / HTTP）

Feature Name: query-tools-deepening
Created: 2026-09-10

## 实施任务

- [x] **T1 DNS 后端新增记录类型 + 传播一致性**
  - `/api/dns/records.ts`：`RECORD_TYPES` 增加 DS/DNSKEY/NSEC/NSEC3/NAPTR/TLSA/SMIMEA；`TYPE_NUM` 补映射；`parseDoHData`/`normalizeToString` 新增分支
  - 响应新增 `propagation`（各解析器 flat 对比，`consistent` + `differing[]`）与 `consistent` 简写

- [x] **T1.1 DNS 传播一致性单元测试**
  - mock DoH：一致/不一致/部分解析器失败三态，验证 `propagation` 输出

- [x] **T2 DNS 前端：新类型 + 传播视图 + DNSSEC 徽标**
  - `dns.tsx`：类型网格自动含新 7 类；结果卡渲染传播一致性小节（一致绿标/差异逐解析器列出）
  - 查询时附带一次 DS+DNSKEY 探测，两者均有 → 「DNSSEC 已启用」徽标
  - locale：dns.* 新键（8 语言）

- [x] **T3 DNS 邮件认证专项（SPF/DMARC）**
  - 新增 `src/lib/dns-email.ts`：纯函数 `parseSpf`/`parseDmarc`（SPF 机制拆分 + 结论；DMARC p/sp/rua/ruf/pct + 强度评级）
  - `dns.tsx` 新增「邮件认证」预设：并行查 `{domain}` TXT 与 `_dmarc.{domain}` TXT，结构化展示；无记录明确「未配置」
  - 新增 `src/lib/dns-email.test.ts`

- [x] **T4 IP 后端 DNSBL + rDNS**
  - 新增 `src/lib/dnsbl.ts`（zone 常量表、反转 IP、resolve4 3s 超时、returnCode→type 映射）
  - 新增 `src/lib/rdns.ts`（8.8.8.8/1.1.1.1 PTR 对照、一致性判定）
  - `/api/ip/lookup.ts`：仅 IPv4 附带 `dnsbl`/`rdns` 字段，随主 payload 缓存
  - 新增 `src/lib/dnsbl.test.ts`、`src/lib/rdns.test.ts`

- [x] **T5 IP 前端：信誉 + rDNS 展示**
  - `ip.tsx`：新增「信誉检查」卡（每 zone 命中徽标 + 汇总 x/N 命中）+「反向 DNS」卡（解析器/PTR/延迟/不一致警示）
  - locale：ip.* 新键（8 语言）

- [x] **T6 SSL 后端 CT + OCSP + TLS 详情**
  - 新增 `src/lib/ct-crt.sh.ts`（crt.sh JSON 查询、去重、前 50 条、8s 超时、降级 available:false；IP 跳过）
  - 新增 `src/lib/ocsp.ts`（从 cert.raw 构造 OCSP 请求、AIA responder、4s 超时；无 responder/失败 → unknown）
  - `cert.ts`：`tlsVersions`（1.0~1.3 探测，并发 ≤2）、`tlsRating`、`ct`、`ocsp` 字段；主握手与附加探测 `Promise.allSettled`
  - 新增 `src/lib/ct-crt.sh.test.ts`、`src/lib/ocsp.test.ts`

- [x] **T7 SSL 前端：CT / OCSP / TLS 三卡**
  - `ssl.tsx`：CT 卡（数量徽标 + 列表 / 不可用态）、OCSP 卡（good 绿 / revoked 红警示 / unknown 灰）、TLS 配置卡（版本徽标行 + 密码套件 + 评级）
  - locale：ssl.* 新键（8 语言）

- [x] **T8 ICP 后端批量查询**
  - `/api/icp/query.ts`：`batch=1` 模式，`search` 逗号分隔多词，并发 ≤3，逐词复用 `queryMiitIcp`（含 legacy 兜底）；响应 `{ ok, batch, results[], failed, elapsedMs }`；单条模式形状不变
  - 新增 `src/lib/icp-batch.test.ts`（拆分/聚合/失败计数）

- [x] **T9 ICP 前端批量 + CSV 导出**
  - `icp.tsx`：搜索框多词（逗号/换行/空格）；结果分组展示 + 单条重试；「导出 CSV」（UTF-8 BOM，标准 6 列：查询词/单位/备案号/服务名称/更新时间/性质，不含负责人与地址）
  - locale：icp.* 新键（8 语言）

- [x] **T10 HTTP 后端分阶段计时 + Cookie + TLS 摘要**
  - `/api/http/check.ts`：改用 http/https 模块 + socket 事件打点（lookup/connect/secureConnect/headersEnd）拆分 dns/connect/tls/ttfb/total，重定向每跳独立计时；新增可选字段 `timing`/`cookies`/`cookieRating`/`tls`，既有字段与错误分支形状不变
  - Cookie 分析：解析 set-cookie 属性，`cookies[]` + `cookieRating`（缺 Secure/HttpOnly→关注，缺 SameSite→提示）
  - TLS 摘要：HTTPS 目标短 tls.connect 取证书 CN/SAN/valid_to/authorized → `tls` 字段；HTTP 目标 null
  - 新增 `src/lib/http-timing.test.ts`（timings 映射 + cookie 解析/评分，14 过）

- [x] **T11 HTTP 前端：耗时 / Cookie / TLS 三卡**
  - `http.tsx`：耗时分析卡（DNS/TCP/TLS/TTFB/Total，失败灰标）、Cookie 分析卡（Secure/HttpOnly/SameSite 徽标 + 缺失问题计数）、TLS/证书摘要卡（协议/密码套件/CN/SAN/有效期/信任状态）
  - locale：http.* 新键（8 语言）

- [x] **T12 验证回归**
  - `npx tsc --noEmit` 通过；`npx vitest run` 全量通过（23 文件 350 测试）
  - locale 校验：全部 8 个 locale 文件 168 keys 同步（`check-locale-keys.mjs`）
  - dev server 冒烟：DNS(google.com DS/DNSKEY 探测 + 传播视图)、IP(8.8.8.8 DNSBL 9 zones + rDNS)、SSL(github.com OCSP good + TLS 1.0~1.3 探测 + rating secure；crt.sh 沙箱不可达已降级 available:false)、ICP(批量拆分/聚合/失败计数 + 单条重试)、HTTP(github.com 分阶段计时 + Cookie 分析 + TLS 摘要；example.com HTTP 分支 tls null)

## 备注

- 所有增强走「主查询优先、上游降级」结构，任一上游失败只影响对应区块
- 不引入付费/注册第三方服务；所有新增探测用免费公开接口（crt.sh / DNSBL / OCSP / DoH）
- `queryMiitIcp` 签名、五个 API 的限流与 SSRF 防护、单域名结果页均不改动
- locale 新键一律先加 `en.json`（TranslationKey 类型源），再同步其余 7 个
- 新增依赖（若有）须登记 `pnpm-workspace.yaml` allowBuilds 并验证本地构建
