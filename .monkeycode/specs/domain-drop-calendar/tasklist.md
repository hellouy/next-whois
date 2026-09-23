# 需求实施计划

- [x] 1. 扩展数据模型与共享类型
  - [x] 1.1 扩展 `expired_domain_leads` 表结构
    - 在 `src/lib/db.ts` 迁移中新增 `drop_date`、`expiry_date`、`stage`、`date_type`、`value_score`、`value_tier`、`value_reasons` 列（对应 R2.1、R2.2、R4.1）
    - 新增 `idx_edl_drop_date`、`idx_edl_stage`、`idx_edl_value` 索引（对应 design Data Models）

  - [x] 1.2 新建 `drop_source_status` 表
    - 记录 `source`、`enabled`、`last_success_at`、`last_error`、`last_error_at`、`items_last_run`（对应 R1.5、R9.4）

  - [x] 1.3 定义共享类型与枚举
    - 定义 `DropStage`（`pending_delete` / `expiring` / `deleted`）、`DateType`（`source` / `derived`）、`DropLeadView`（对应 R1.2、R5.5）

  - [x]* 1.4 为迁移与类型编写单元测试
    - 校验列存在、索引创建幂等、枚举取值合法

- [x] 2. 实现日期解析与阶段归类
  - [x] 2.1 实现 `parseDropDate` 多格式解析
    - 支持 `YYYY-MM-DD`、`DD-MMM-YYYY`、`YYYY`，解析失败返回 null（对应 R2.1）

  - [x] 2.2 实现 `classifyStage` 阶段归类
    - 按源与状态归类 `pending_delete` / `expiring` / `deleted`，保证阶段互斥（对应 R1.2、R1.3）

  - [x] 2.3 实现源日期与推算日期优先级
    - 同域名两者并存时以源提供日期为准并记录偏差（对应 R2.2、R2.4）

  - [x]* 2.4 编写日期解析与归类单元测试
    - 覆盖各日期格式、非法输入、阶段互斥（design 正确性属性 2、5）

- [x] 3. 实现多维价值评分扩展
  - [x] 3.1 内置英文词表数据文件
    - 在 `src/data/wordlist.ts` 导出常用英文词 `Set<string>`（对应 R4.2）

  - [x] 3.2 内置拼音音节与常用词数据文件
    - 在 `src/data/pinyin.ts` 导出有效音节 `Set<string>` 与常用拼音词 `Set<string>`（对应 R4.2）

  - [x] 3.3 实现 `isDictionaryWord` 单词判定
    - 精确匹配词表，按词长分级给分（3-4 字母满分）（对应 R4.2）

  - [x] 3.4 实现 `splitPinyin` 双拼判定
    - 动态规划将纯字母 SLD 切分为 2-4 个有效音节且无剩余，命中常用词额外加分（对应 R4.2）

  - [x] 3.5 实现 `scoreDomainExtended` 七维评分
    - 长度 0-25、后缀 0-15、词性 0-20、热门前缀 0-15、模式 0-15、市场 0-10，返回 breakdown 与 reasons（对应 R4.1、R4.2、R4.3）

  - [x] 3.6 接入热门前缀动态权重
    - 预加载 `hot_prefixes`（`enabled=true`）并复用 `HOT_PREFIX_CACHE_KEY` 缓存，SLD 命中取最高权重归一化（对应 R4.2）

  - [x] 3.7 实现市场数据归一化
    - BL 与 DP 对数归一化到 0-10（对应 R4.2）

  - [x] 3.8 实现价值等级与告警阈值
    - 依据价值分划分等级并复用 `shouldAlertAdmin` 语义（对应 R4.5、R4.6）

  - [x]* 3.9 编写评分维度单元测试
    - 覆盖单字符、双字符、含连字符、纯数字、单词、双拼、热门前缀、市场数据边界（对应 R4.3、R4.4）

  - [x]* 3.10 编写评分属性测试
    - 同输入同输出（design 正确性属性 3）、各维度不越界且总分不超过 100（design 正确性属性 8）

- [x] 4. 检查点 - 确保所有测试通过
  - 确保所有测试通过,如有疑问请询问用户

- [x] 5. 实现采集器层
  - [x] 5.1 定义采集适配器接口与调度器
    - 在 `src/lib/drop-sources/` 定义 `DropSourceAdapter`、`RawDropRow` 与 `registry.ts` 调度（对应 R1.1、R1.7）

  - [x] 5.2 实现 expireddomains 待删除视图采集器
    - 复用现有登录流程与表格解析，新增待删除视图抓取（对应 R1.1）

  - [x] 5.3 实现 whoisds 每日列表采集器
    - 下载每日文本列表并解析，按文件类型归类阶段（对应 R1.1）

  - [x] 5.4 实现单源失败隔离与错误计数
    - 单源失败不影响其他源，解析失败行计数跳过（对应 R1.5、R1.6）

  - [x]* 5.5 编写采集器解析集成测试
    - 以 HTML/文本 fixture 校验解析结果与错误计数

- [x] 6. 实现生命周期推算集成
  - [x] 6.1 对即将过期行推算掉落日与时刻
    - 调用 `computeLifecycle` 计算 `dropDate`，组装 `dropTime`（对应 R3.1、R3.2）

  - [x] 6.2 实现 EPP 剔除与置信度标注
    - 剔除 hold/prohibited/disputed/suspicious，标注推算置信度（对应 R3.3、R3.4）

  - [x] 6.3 实现偏差记录
    - 推算与源日期偏差超阈值时记录供核对（对应 R3.5）

  - [x]* 6.4 编写推算单元测试
    - 覆盖无 TLD 规则回退、EPP 剔除（design 正确性属性 7）、偏差记录

- [x] 7. 实现采集入库管线
  - [x] 7.1 实现幂等 upsert 与评分落库
    - 按 `domain` 唯一约束 upsert，写入价值分与理由（对应 R1.4、R4.1）

  - [x] 7.2 实现数据源状态写入
    - 运行结果写入 `drop_source_status`，失败时保留上次数据（对应 R1.5、R9.4）

  - [x] 7.3 实现采集后缓存失效
    - 失效掉落查询缓存（对应 design 数据流）

  - [x]* 7.4 编写幂等性与状态写入测试
    - 重复采集不产生重复行（design 正确性属性 1）

- [x] 8. 检查点 - 确保所有测试通过
  - 确保所有测试通过,如有疑问请询问用户

- [x] 9. 实现定时采集端点
  - [x] 9.1 实现 `/api/cron/drop-sources`
    - 复用 `CRON_SECRET` Bearer 认证，串联采集到入库全流程（对应 design 定时采集）

- [x] 10. 改造掉落查询接口
  - [x] 10.1 实现窗口与筛选参数
    - 支持 `days`、`sort`、`tld`、`minLen`、`maxLen`、`minScore`、`source`、`dateType`（对应 R5.1、R5.4）

  - [x] 10.2 实现按日期分组与统计聚合
    - 返回每日总数、最高等级、后缀分布与 Top 价值（对应 R5.3、R11.1 至 R11.4）

  - [x] 10.3 实现窗口边界与条数上限
    - 仅返回 `today <= drop_date <= today + days`，超出按价值分截断（对应 R5.2、R5.7）

  - [x] 10.4 实现缓存头与登录隔离
    - 匿名响应可缓存，含 `user_drops` 响应 `private, no-store`（对应 R5.6）

  - [x] 10.5 保留并适配用户订阅部分
    - 保留现有 `reminders` 精确掉落逻辑（对应 R5.5）

  - [x]* 10.6 编写 API 集成测试
    - 窗口边界（design 正确性属性 4）、缓存隔离（design 正确性属性 6）、筛选参数

- [x] 11. 改造掉落日历视图
  - [x] 11.1 实现月历网格组件
    - 日期格显示数量与最高价值等级，支持月份切换与今日高亮（对应 R6.1、R6.3、R6.4）

  - [x] 11.2 实现当日列表展开与线索行
    - 展示域名、掉落日/时刻、来源与日期类型、价值分与理由（对应 R6.2、R9.3）

  - [x] 11.3 实现筛选与排序栏
    - 五类筛选器与三种排序，变更保留窗口（对应 R7.1、R7.2、R7.3）

  - [x] 11.4 实现价值构成展示
    - 展示价值分维度构成供用户理解排序（对应 R7.4）

  - [x] 11.5 实现统计概览与数据源新鲜度
    - 窗口总数、今日掉落、后缀分布、Top 价值、各源更新时间与过期提示（对应 R11、R9.1、R9.2）

  - [x] 11.6 实现空状态与移动端布局
    - 空结果显示提示与最近更新时间，移动端可用（对应 R6.5、R6.6、R7.5）

- [x] 12. 实现订阅与抢注衔接
  - [x] 12.1 实现监控提醒操作
    - 复用 `/api/remind/submit`，已订阅显示标记，未登录引导登录（对应 R8.1、R8.2、R8.4、R8.5）

  - [x] 12.2 实现管理员加入抢注目标入口
    - 复用现有抢注目标接口（对应 R8.3）

- [x] 13. 实现访问控制与国际化
  - [x] 13.1 实现公开日历锁定逻辑
    - 依据 `drop_calendar_public` 返回锁定状态与登录引导（对应 R10.1 至 R10.3）

  - [x] 13.2 同步新增文案到全部 locale 文件
    - 运行 `node scripts/check-locale-keys.mjs` 校验 8 个语言文件键一致（对应 design Test Strategy）

- [x] 14. 检查点 - 最终验证
  - 运行 `npx tsc --noEmit`、`npx vitest run`、`node scripts/check-locale-keys.mjs` 全部通过
  - 确保所有测试通过,如有疑问请询问用户

- [x] 15. 增量需求 - 受限注册状态卡片区分
  - [x] 15.1 打通注册状态数据通路
    - `RegStatus` 类型（available/reserved/prohibited）；`RawDropRow`/`EnrichedDropRow`/`UpsertLeadInput` 透传；管线 upsert 写入 `status` 列；`/api/drops` 仅在非 available 时返回 `regStatus`
  - [x] 15.2 实现受限卡片独立样式
    - 保留域名（琥珀）/禁止注册（玫红）使用独立左边条、底色、状态徽章与说明文案；受限域名隐藏监控入口，抢注入口仅管理员可见
  - [x] 15.3 补充状态文案与测试
    - 4 个 `drops.reg_*` key × 8 语言；lifecycle/pipeline/API 透传测试
  - [x] 15.4 管理端手动标记入口
    - 新增 `POST /api/admin/drop-lead-status`（requireAdmin，校验 domain/status，写 `expired_domain_leads.status` 并失效缓存）；`drops.tsx` 管理员操作区加入状态下拉（available/reserved/prohibited），含 4 个 `drops.reg_*` key × 8 语言与端点单测（6 例）

