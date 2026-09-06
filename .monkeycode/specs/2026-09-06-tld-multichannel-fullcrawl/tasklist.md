# Tasklist — TLD 生命周期多渠道全量抓取

Feature Name: tld-multichannel-fullcrawl
Created: 2026-09-06

## 实施任务

- [x] **T1 数据库迁移**: `tld_rules` 增加 `channels JSONB` 列（已执行 ALTER TABLE）
- [x] **T2 渠道路由核心**: `collectChannels(tld, ianaUrl)` 实现注册局官网（既有发现链）+ 注册商模板（Namecheap/GoDaddy/Cloudflare/Ionos）+ ICANN Agreement（gTLD 标准条款常量注入）+ Wikipedia 四主渠道并发采集
- [x] **T3 回退链**: 主渠道全空时触发 Bing 搜索补 URL → Wayback 快照回退
- [x] **T4 AI 综合裁决**: `extractWithAI` 升级为多渠道原文汇总 + 权威加权 + 字段级 `fields_source` 输出
- [x] **T5 解析与约束**: `parseAiJson` 支持 `fields_source` 透传、时区白名单、drop 三件套越界置 null、pre_expiry clamp
- [x] **T6 落库**: `saveToDb` 写 `channels JSONB`、confidence 分级（多源一致=high）、fetch_strategy 渠道路由说明
- [x] **T7 全量调度**: main() 支持 IANA 根区全量清单、断点续传、SIGTERM/SIGINT 优雅结束（沿用既有）
- [x] **T8 单元测试**: `lifecycle-parse.mjs` 抽取纯函数 + `multichannel-parse.test.ts`（217 例全绿）
- [x] **T9 冒烟验证**: `--tld de`(registry+wiki high) / `--tld com`(registry+icann+wiki) / `--tld tf`(registry+wiki high) 均多渠道落库成功
- [ ] **T10 提交推送**: 代码、specs、tasklist 提交并推送

## 待办（全量跑）

- [ ] **T11 全量后台跑**: `node scripts/batch-scrape.mjs --type iana`（先 seed 缺口，再分渠道抓取，监控占比）