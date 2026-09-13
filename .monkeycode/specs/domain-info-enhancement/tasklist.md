# Tasklist: domain-info-enhancement

## 背景

对 WHOIS/RDAP 查询结果做三层增强：停放/出售检测层（NS 白名单 10→20+ 平台）、注册商/注册人提取补全（多语言 key + IANA 补全 + 脱敏标记）、域名综合信息（NS 归属、whois 服务器归属、DNSSEC/DS、日期校验）。所有增强结果落库 `domain_enrichments` 供复用。不改变查询主流程/缓存键/TTL，不新增前端卡片。

## 实施步骤

- [x] **T1 创建停放平台静态库** `src/data/query-page/parking-platforms.ts`
  - 定义 `ParkingPlatform` 类型与 `PARKING_PLATFORMS` 数据（20+ 平台，含 4.cn/Voodoo/Undirected/Parklogic/Parked.com/DomainSponsor 等），每平台带 `kind`（parking/aftermarket/both）。
  - dns-check.ts 的 `detectParkingProvider` 改为从该库读取，接口签名不变。
  - 测试 `parking-platforms.test.ts`：20+ 平台后缀匹配、多 NS 命中取首、无匹配 null。

- [x] **T2 扩充 NS 品牌归属库** `src/data/query-page/ns-brands.ts`
  - 现有 561 行基础上补充缺失主流品牌并新增 `kind` 字段（dns-hosting/parking/registrar）。
  - 保持向后兼容（`brand/domains/slug/color` 字段保留，`kind` 可选新增）。

- [x] **T3 创建域名增强服务** `src/lib/server/domain-enrichment.ts`
  - `NsAttribution`/`DomainEnrichment` 类型 + `enrichDomainInfo()`：NS 归属分类、whois 服务器归属（`WHOIS_SERVER_OWNERS` 内置映射）、停放平台合并、`forSale` 三源判定、`sanityCheckDates` 日期校验。
  - 测试 `domain-enrichment.test.ts`：NS 归属四分类、日期 4 种异常、三源优先级、脱敏标记。

- [x] **T4 落库迁移** `domain_enrichments` 表
  - db.ts runMigrations 新增表 + `generated_at` 索引；`ENRICHMENT_TTL_MS=7d`。
  - `src/lib/server/domain-enrichment-db.ts`：readEnrichment / writeEnrichment / 后台刷新，best-effort 不阻塞主流程。
  - 测试 `domain-enrichment-db.test.ts`：UPSERT 幂等、TTL 过期后台刷新、DB 不可用降级（mock run 抛错）。

- [x] **T5 common_parser 多语言提取补全**
  - 中文 key：注册商（注册商/注册服务商）、注册者（注册者/注册人/持有人/主办单位名称）、邮箱（电子邮件/联系人邮箱）等。
  - 多语言 ccTLD：.vn/.br/.kr/.ru 注册商与注册者变体。
  - `isRedactedValue` 扩展 PrivacyGuard / Whois Privacy 等模式；产出 `registrantPrivacy` 附加字段。
  - 测试：中文/.vn/.br/.kr/.ru 解析用例、脱敏标记用例。

- [x] **T6 RDAP 注册商 handle / publicIds 提取**
  - rdap_client.ts 提取注册商 handle 与 publicIds，供 T7 注册商库补全 IANA ID。

- [x] **T7 注册商库补全与结果模型扩展**
  - 内置注册商库（名称→IANA ID/官网）在 rdap_client.ts 或新文件；registrar 提取成功但 ianaId 缺失时按名称补全，置 `ianaIdFromLibrary`。
  - `WhoisAnalyzeResult` 新增可选字段：`nsAttributions`/`whoisServerAttribution`/`parkingProvider`/`forSale`/`dateSanity`/`registrantPrivacy`/`ianaIdFromLibrary`。

- [x] **T8 接入查询主流程**
  - lookup.ts：成功路径调用 `enrichDomainInfo`，合并进 result；写库 best-effort；读缓存路径优先从 `domain_enrichments` 读取（Redis 未命中时）。
  - 不改变缓存键与 TTL 语义，增强结果作为附加字段。

- [x] **T9 验证链与端到端**
  - `npx tsc --noEmit`、`npx vitest run`（既有 438 + 新增全绿）、`npm run check:i18n`。
  - dev server 查询已知停放域名验证 `parkingProvider`/`nsAttributions`；查询 .cn 域名验证中文提取；二次查询确认落库。

## 完成标准

- [x] 所有测试通过（新用例 + 既有 438 无回归）
- [x] tsc 0 错误、i18n 检查通过
- [x] 查询结果包含增强字段，落库可复用
- [x] tasklist 全部勾选
