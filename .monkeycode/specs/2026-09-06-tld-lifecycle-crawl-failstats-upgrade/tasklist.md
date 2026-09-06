# Task List — TLD 生命周期 AI 抓取与查询失败统计升级

Feature Name: tld-lifecycle-crawl-failstats-upgrade
Created: 2026-09-06
Status: In Progress

## 批次 1 — 失败统计后端（修复周对比 + 双事实源基础）

- [ ] 1.1 建表 `tld_failure_events` + `ai_call_log`（db.ts 迁移数组追加，含索引）
- [ ] 1.2 新建 `classifyFailure` 归因模块（12+ 类扩展枚举 + 规则映射）
- [ ] 1.3 新建 `recordFailureEvent`（写事件表，fire-and-forget，不阻塞查询）
- [ ] 1.4 改造 `recordTldLookupFailure`：写事件表，不再累加 `tld_fallback_stats`（R5）；lookup 调用点补充 context
- [ ] 1.5 改造 `GET /api/admin/tld-failures`：window 参数 + metrics（query_logs 成功率健康度）+ 修复期望对比（修复 B1）

## 批次 2 — 失败统计仪表盘

- [ ] 2.1 GET 扩展 `reason_dist` / `trend` / `top_failed`
- [ ] 2.2 `tld-failures.tsx` 改造：窗口仪表盘（卡片/原因分布/Top 列表/成功率列，纯 DOM 图）
- [ ] 2.3 历史 `tld_fallback_stats.fail_count` 一次性清零迁移

## 批次 3 — B 组统一抓取服务层

- [ ] 3.1 新建 `scrapeTld` 统一服务：合并 cron/POST 保存、失败落库 failed、needs_admin_review 一致（R6）
- [ ] 3.2 `fetchPageText` 返回 `fetchStrategy`；`findRegistryLifecyclePage` 并发 3 + Jina 短路（R12）
- [ ] 3.3 时区/掉落字段严格校验：白名单 + drop 三件套整体性 + 范围 clamp（R8）
- [ ] 3.4 IANA 根区总数动态化（R9）
- [ ] 3.5 cron 队列 stale 优先级 + PATCH 批量重抓 + 页面批量刷新按钮（R13）

## 批次 4 — B 组 AI 增强

- [ ] 4.1 AI 字段来源标记 prompt + `parseAiJson` 双格式兼容 + confidence + warn_defaults 新判定（R7）
- [ ] 4.2 Provider 熔断降权（进程内滑窗 + 半开放行）（R10）
- [ ] 4.3 `ai_call_log` 写入 + `/api/admin/ai-stats` + 用量区块（R11）

## 批次 5 — 回归与部署

- [ ] 5.1 `npx tsc --noEmit` + `vitest run` + 本地 build + dev 冒烟
- [ ] 5.2 部署验证（poll READY → 线上 --resolve curl + 接口冒烟）