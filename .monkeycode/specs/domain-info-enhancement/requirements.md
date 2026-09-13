# Requirements Document

## Introduction

本规格针对域名 WHOIS/RDAP 查询结果的**信息深度**进行增强，覆盖三个维度：域名停放/出售状态检测、注册商/注册人信息提取补全、以及域名综合信息（NS 归属、whois 服务器归属、安全信息、数据完整性校验）。目标是在不改变现有查询主流程与缓存策略的前提下，提高已注册域名结果的信息丰富度与准确性，让用户快速判断一个域名当前处于什么状态、由谁托管、注册商与注册人信息是否完整可信。

## Glossary

- **停放（Parking）**：域名已注册但未部署实际网站，NS 指向域名停放平台（如 Sedo、Afternic、Bodis、4.cn），用于展示广告或挂牌出售。
- **出售（For Sale / Aftermarket）**：域名注册人或注册局将域名挂牌出售，WHOIS/RDAP 文本或注册局状态码明确表达"可购买"。
- **NS 归属（NS Brand）**：根据 nameserver 域名判断其运营方（如 domaincontrol.com → GoDaddy）。
- **注册商（Registrar）**：域名当前注册商，含名称、官网、IANA ID、WHOIS 服务器、滥用联系。
- **注册人（Registrant）**：域名持有人，含名称、机构、国家、省份、城市、地址、电话、邮箱等。
- **数据完整性校验（Field Sanity）**：对 WHOIS 各字段做交叉合理性检查，标记明显矛盾或异常（如创建日期晚于更新日期、过期日期早于创建日期）。

## Requirements

### Requirement 1: 停放/出售检测层增强

**User Story:** AS 域名查询用户, I want 停放/出售检测覆盖更多平台与更多信号来源, so that 能准确识别一个已注册域名是否处于停放/出售状态。

#### Acceptance Criteria

1. WHEN 域名的 NS 指向任一已知停放平台, 系统 SHALL 在 DnsProbeResult 中返回该平台名称。
2. WHEN 已知停放平台的 NS 白名单扩充至不少于 20 家平台, 系统 SHALL 通过 NS 后缀匹配识别平台归属。
3. WHEN RDAP 返回的 status 数组或 WHOIS 文本包含出售/停放相关状态码或关键词, 系统 SHALL 将对应状态注入结果 status 数组。
4. WHEN DNS、RDAP、WHOIS 三个来源的停放/出售信号相互矛盾, 系统 SHALL 优先采信注册局权威来源（RDAP status > WHOIS 文本 > NS 推断）。
5. IF 域名同时命中多个停放平台 NS, 系统 SHALL 返回首个匹配平台名称。
6. IF NS 查询超时或失败, 系统 SHALL 标记停放信息为"未确认"而不断言域名未停放。

### Requirement 2: 注册商/注册人信息提取补全

**User Story:** AS 域名查询用户, I want 注册商与注册人信息能从更多 WHOIS 格式中被完整提取, so that 结果不再因格式陌生而大面积显示 Unknown。

#### Acceptance Criteria

1. WHEN WHOIS 原始文本来自中文注册局（CNNIC 系、.cn/.com.cn/.net.cn 等）, 系统 SHALL 识别中文 key（注册商、注册者、联系人、主办单位名称 等）并填充对应字段。
2. WHEN WHOIS 原始文本来自多语言 ccTLD（如 .vn/.br/.kr/.ru/.de 等）, 系统 SHALL 按 common_parser 现有规范化 key 结构补全缺失语言变体。
3. WHEN 注册商字段提取成功但 IANA ID 缺失, 系统 SHALL 通过注册商名称匹配内置注册商库补全 IANA ID 与官网 URL。
4. IF 注册人字段值命中已知隐私代理/脱敏标记（如 "PrivacyGuard"/"REDACTED FOR PRIVACY"/"Whois Privacy"）, 系统 SHALL 将字段值标记为脱敏而非简单留空。
5. IF 同一字段在 WHOIS 多段中重复出现且值不同, 系统 SHALL 优先采用非脱敏、非 Unknown 的值。
6. WHEN 解析完成, 系统 SHALL 输出注册商与注册人字段的完整集合, 保持与 WhoisAnalyzeResult 现有 schema 兼容。

### Requirement 2.5: 增强结果落库可复用

**User Story:** AS 系统运营者, I want NS 归属与停放判定结果持久化到数据库, so that 重复查询可直接复用已计算的结构化结果, 减少对上游查询的重复依赖。

#### Acceptance Criteria

1. WHEN 系统完成一次域名的 NS 归属或停放判定, 系统 SHALL 将结果写入数据库表（如 domain_enrichments）。
2. WHEN 同一域名再次被查询且其缓存结果已过期, 系统 SHALL 优先读取数据库中的增强结果, 仅当记录缺失或超过刷新窗口时才重新计算。
3. WHEN 数据库写入失败（表缺失/连接异常）, 系统 SHALL 不影响查询主流程, 返回即时计算结果并降级为不落库。
4. IF 数据库中存在过期（超过 TTL 阈值）的增强记录, 系统 SHALL 在后台刷新后回写, 不阻塞当前查询响应。
5. WHEN 新增数据库表或列, 系统 SHALL 通过现有 runMigrations 惰性迁移机制创建, 不要求手工建表。

### Requirement 3: 域名综合信息增强

**User Story:** AS 域名查询用户, I want 结果页能展示 NS 归属、whois 服务器归属、安全信息与数据完整性校验, so that 一个域名从注册、托管到安全配置的整体画像一屏可读。

#### Acceptance Criteria

1. WHEN 域名的 nameserver 列表非空, 系统 SHALL 对每台 NS 通过内置品牌库（NS_BRANDS 及扩充）匹配托管/平台归属, 匹配失败时标记为"未识别"。
2. WHEN whois 服务器字段有效, 系统 SHALL 展示其归属信息（注册局/注册商/第三方）, 归属未知时显示原始服务器地址。
3. WHEN DNSSEC 状态已知, 系统 SHALL 输出 dnssec 字段；WHEN DS 记录可查, 系统 SHALL 尝试补充 DS 记录信息, 查询失败不阻断结果。
4. WHEN 解析出的日期字段满足以下任一异常条件：过期日期早于创建日期、更新日期早于创建日期、创建日期在未来, 系统 SHALL 将对应字段标记为异常。
5. WHEN 域名状态码或注册商表明该域曾被注册局保留/持有（registry-hold 等）, 系统 SHALL 保持现有生命周期相位判定不受影响。
6. WHILE 综合信息增强执行, 系统 SHALL 不改变现有查询主流程、缓存键与缓存 TTL 语义。

## 验收边界（Out of Scope）

- 不新增前端信息卡片或页面布局改动（用户明确仅增强检测层/提取层/数据层）。
- 不改变注册商图标映射表（REGISTRAR_ICONS）的现有展示逻辑。
- 不引入新的外部付费 API 或爬虫；NS 归属与注册商库以本地内置数据为主。
- 不改动 snipe/订阅/提醒等既有模块的生命周期判定。
