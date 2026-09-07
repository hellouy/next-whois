# Tasklist — 后台管理控制台重构

Feature Name: admin-console-reorg
Created: 2026-09-07

## 实施任务

- [ ] **T1 抓取进度落库**: 新建 `tld_crawl_progress` 表（migrate.js）；`batch-scrape.mjs` 主循环每批次 upsert 进度、启动/结束/SIGTERM 写状态
- [ ] **T2 进度读取 API**: 新建 `/api/admin/tld-crawl-progress` GET（进度行 + tld_rules 覆盖率统计）；`tld-rules.ts` 的 `ianaTotal` 改为实时值
- [ ] **T3 code 工具抽取**: 新建 `src/lib/code-utils.ts`（genHumanCode/parseExpiresAt）；invite-codes/activation-codes 改用之；移除 system.ts 重复清理
- [ ] **T4 「访问与密钥」页**: access.tsx 四 tab（访问密钥/AI数据源凭据/邀请码/激活码）；access-control 与 api 改重定向壳
- [ ] **T5 「域名与 TLD」中枢页**: tlds-hub.tsx 五 tab（lifecycle/crawl/failures/whois/compare）；原 tld-rules/tld-failures/whois-servers 改重定向壳
- [ ] **T6 crawl tab 轮询**: 页面每 15s 轮询 tld-crawl-progress，展示后台脚本进度横幅（与 BatchPanel 区分）
- [ ] **T7 后台首页收敛**: admin/index.tsx 入口收敛为「域名与 TLD」与「访问与密钥」两个入口，统计卡片更新
- [ ] **T8 验证回归**: tsc 干净 + 冒烟（脚本进度落库、旧路由重定向、各 tab 可用）

## 备注

- 拆分采用「新中枢页 + 子组件文件化 + 旧页面重定向壳」，逐步迁移降低回归风险
- `tld_crawl_progress` 单行 upsert（run_key='iana'），重复运行幂等
