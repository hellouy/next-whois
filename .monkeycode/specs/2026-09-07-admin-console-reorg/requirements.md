# Requirements Document — 后台管理控制台重构

Feature Name: admin-console-reorg
Created: 2026-09-07
Status: Draft

## Introduction

后台管理端当前 30+ 页面功能分散、职责重叠，用户对三处体验不满：

1. **TLD 生命周期规划页的「AI 批量抓取进度」与实际不符**：页面顶部展示 `{inDb} / 1285`，分母是写死的历史快照常量（`src/pages/api/admin/tld-rules.ts` 内 `IANA_TOTAL = 1285`），而批量抓取脚本运行时实时下载 IANA 根区清单（当前实际为 1287 个非 IDN TLD）；分子是 `tld_rules` 表总行数，且该覆盖率数字不随抓取实时变化，与 BatchRunner 的真实批处理进度（idx/total）混为一谈。
2. **功能分散重复**：`/admin/tld-rules` 一个页面承载 5 个 tab + 顶部总览 + 规则总表等 9 大区块，还被后台首页拆成 3 个入口（`tld-rules` / `?inner=failures` / `?inner=lifecycle`）；失败记录在 `tld-rules`（简览）与 `tld-failures`（完整统计）重复实现；`whois-servers` 游离在首页入口之外。
3. **访问控制杂乱重复**：`/admin/access-control`（access_keys 访问密钥 + invite_codes 邀请码 + activation_codes 激活码）与 `/admin/api`（site_settings 中第三方 AI/数据源凭据）命名高度相似（api-keys vs access-keys）且分属两页；邀请码与激活码的生成/有效期逻辑完全重复；`require_api_key` 开关的过期清理同时在 access-control 与 system.ts 中出现。

**改造目标**：按功能域合并管理页面 —— 新建统一的「域名与 TLD」管理中枢页收纳生命周期规划、AI 批量抓取（真实进度）、失败记录、WHOIS 服务器等；将 `/admin/api` 的凭据管理并入 `/admin/access-control` 成为「访问与密钥」单页；修正进度分母为实时 IANA 清单并区分覆盖率与真实批处理进度；删除重复实现与冗余清理入口。其他域（用户/支付/通知/品牌/系统）保持现状。

## Glossary

- **TLD 生命周期规划**：`/admin/tld-rules` 页「生命周期设置」tab（`LifecycleTabInline`）——AI 抓取数据导入、订阅 WHOIS 批量同步、生命周期覆盖规则表、用户纠错反馈审核
- **覆盖率（Coverage）**：`tld_rules` 表已入库记录数 / 实时 IANA 根区非 IDN TLD 总数，反映全量采集覆盖面
- **批处理进度（Batch Progress）**：BatchRunner 或后台脚本实际正在处理的任务 `(当前 idx / 总数)`，反映实时抓取状态
- **访问凭证（Access Credential）**：`access_keys` 表（本站出站 API 鉴权，rwh_ 前缀）+ 全局 `require_api_key` 开关
- **第三方凭据（Third-Party Credential）**：`site_settings` 表中 `api_%` 键，即 AI 提供商（GLM/Groq/Gemini/DeepSeek/豆包等）与数据源（亿思云等）的入站凭据
- **邀请码 / 激活码**：`invite_codes` 表（注册邀请）、`activation_codes` 表（付费激活），两者生成与有效期逻辑当前重复

## Requirements

### R1 抓取进度展示修正

**User Story:** AS 后台管理员, I want 「AI 批量抓取进度」展示与后台脚本实际进度一致, so that 页面数字真实可信、不再误导。

**Acceptance Criteria:**
1. WHEN 页面加载 TLD 管理页, the system SHALL 将进度分母从写死常量 1285 改为实时 IANA 根区非 IDN TLD 总数（与 `scripts/batch-scrape.mjs` 的 `fetchAllIanaTlds` 同源；脚本运行时获取的实际清单数若可得则优先展示）。
2. WHEN 展示覆盖率, the system SHALL 明确标注为「已入库 / IANA 总数（覆盖率）」, 并区分 `scrape_status` 明细（ok / warn_defaults / failed / pending / no_data / 手动编辑）。
3. WHEN 存在正在运行的批处理, the system SHALL 在 BatchPanel 内展示真实 `(当前 idx / 总数)` 进度, 且不再与覆盖率数字混用。
4. WHEN 后台脚本 `batch-scrape.mjs` 正在后台运行时, the system SHALL 提供该脚本进度的持久化查看方式（脚本定期将进度写入 DB，页面轮询展示），替代仅存在于浏览器内存的 BatchRunner singleton（刷新即重置）。
5. IF IANA 根区文件拉取失败, the system SHALL 回退到最后一次已知总数并标注「缓存」，同时不阻塞页面其余功能。

### R2 「域名与 TLD」管理中枢页

**User Story:** AS 后台管理员, I want 把 TLD 生命周期、AI 抓取进度、失败记录、WHOIS 服务器整合到一个管理中枢页, so that 不再跨多个页面往返。

**Acceptance Criteria:**
1. WHEN 管理员访问后台域名与 TLD 域, the system SHALL 提供统一的「域名与 TLD」中枢页，以 tab/分区收纳下列功能：TLD 生命周期规划、AI 批量抓取（覆盖率 + 真实进度）、失败记录统计、WHOIS 服务器管理、生命周期对比分析。
2. WHEN 用户在失败记录区, the system SHALL 移除 `tld-rules` 内的失败简览与 `/admin/tld-failures` 完整版的重复实现，只保留一份完整功能。
3. WHEN 管理员需要管理自定义 WHOIS 服务器, the system SHALL 在中枢页内提供完整 CRUD（原 `/admin/whois-servers` 全部能力），并将其加入后台首页快捷入口。
4. WHEN 原 `/admin/tld-rules?inner=failures` 与 `?inner=lifecycle` 三个独立入口存在, the system SHALL 收敛为中枢页单一入口，保留深链可达（如 `?tab=failures` 仍可直达子 tab）。
5. WHEN 页面变更完成, the system SHALL 确保原 `/admin/tld-rules`、`/admin/tld-failures`、`/admin/whois-servers` 路由不 404，旧路由可重定向至中枢页对应 tab。

### R3 「访问与密钥」单页整合

**User Story:** AS 后台管理员, I want 访问控制与第三方凭据在一个页面统一管理, so that 「API 密钥」不再有两处易混淆的入口。

**Acceptance Criteria:**
1. WHEN 管理员访问访问与密钥域, the system SHALL 将 `/admin/access-control`（访问密钥 / 邀请码 / 激活码）与 `/admin/api`（AI 提供商 Key + 第三方数据源凭据）合并为单一「访问与密钥」页。
2. WHEN 页面内存在 API 相关命名, the system SHALL 明确区分「访问密钥（本站出站鉴权 rwh_）」与「AI/数据源凭据（第三方入站）」，消除 api-keys 与 access-keys 的混淆。
3. WHEN 邀请码或激活码生成/解析有效期, the system SHALL 使用公共工具函数（抽取 `randomBytes(3)` 的 `XXX-XXX-XXX` 生成逻辑与 `parseExpiresAt`），删除两份重复实现。
4. WHEN `require_api_key` 开关的过期密钥清理存在多处（access-control 与 system.ts）, the system SHALL 只保留访问与密钥页内一处入口，system.ts 移除重复清理逻辑。
5. WHEN 页面整合完成, the system SHALL 确保原 `/admin/api` 路由不 404，旧路由重定向至访问与密钥页对应 tab。

### R4 后台首页入口收敛

**User Story:** AS 后台管理员, I want 后台首页快捷入口与实际页面结构一致, so that 不再出现同一页面三个入口的冗余导航。

**Acceptance Criteria:**
1. WHEN 首页展示「域名与接入」分组, the system SHALL 将 `/admin/tld-rules`、`?inner=failures`、`?inner=lifecycle`、`/admin/tld-failures` 收敛为单一「域名与 TLD」入口（+ 可选 whois-servers）。
2. WHEN 首页展示「访问与 API」分组, the system SHALL 将 `/admin/access-control` 与 `/admin/api` 收敛为单一「访问与密钥」入口。
3. WHEN 分组描述更新, the system SHALL 用准确文案区分访问密钥、第三方凭据、邀请码、激活码，避免「API 密钥」歧义。

### R5 非重构域保持兼容

**User Story:** AS 后台管理员, I want 其余管理域不受本次重构影响, so that 回归风险可控。

**Acceptance Criteria:**
1. WHEN 用户/支付/通知/品牌/系统等管理页存在, the system SHALL 保持其路由与功能不变。
2. WHEN 页面重构涉及共享组件或 API 路由调整, the system SHALL 保证既有页面（dashboard、tlds.tsx、drops.tsx 等）引用的 API 响应结构不变或同步更新。

## Out of Scope

- `access_keys` / `invite_codes` / `activation_codes` 三张表合并不做（保留各自表结构，仅页面与逻辑去重）。
- 非域名/非访问域的其他 20+ 管理页不做结构性改动。
- 不迁移 `batch-scrape.mjs` 运行环境（仍在后台终端跑），只增加其进度落库与页面轮询展示。
