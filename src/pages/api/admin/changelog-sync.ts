import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "crypto";
import { requireAdmin } from "@/lib/admin";
import { many, run, isDbReady } from "@/lib/db-query";

type SeedEntry = {
  entry_date: string;
  type: "new" | "feature" | "improve" | "fix";
  zh: string;
  version: string;
};

const SEED: SeedEntry[] = [
  // v3.35
  { entry_date: "2026-04-02", type: "improve", version: "3.35", zh: "流式 WHOIS 查询提速：RDAP 结果提前推送，WHOIS 补全后静默更新，首屏加载体感大幅缩短" },
  { entry_date: "2026-04-02", type: "improve", version: "3.35", zh: "查询超时优化：WHOIS_TIMEOUT 从 7s 降至 5s，RDAP 容忍窗口从 800ms 降至 400ms" },
  { entry_date: "2026-04-02", type: "new",     version: "3.35", zh: "用户中心余额明细展开：点击余额行查看最近 30 条充值/消费记录，支持金额正负色区分" },
  // v3.34
  { entry_date: "2026-04-02", type: "new",     version: "3.34", zh: "支持接入 Google Analytics 4 / Umami 统计：后台填入 ID 即时生效，无需改代码" },
  { entry_date: "2026-04-02", type: "fix",     version: "3.34", zh: "修复 OG 站点名称被硬编码覆盖的问题，og:site_name 现由后台设置动态控制" },
  { entry_date: "2026-04-02", type: "improve", version: "3.34", zh: "管理后台批量邮件和重置密码操作改为两步确认，避免误触" },
  // v3.33
  { entry_date: "2026-04-01", type: "new",     version: "3.33", zh: "首页公告横幅：支持 info / warning / success / notice 类型，可配置跳转 URL，关闭后不再弹出" },
  { entry_date: "2026-04-01", type: "new",     version: "3.33", zh: "结果页文字广告位：可配置广告内容、外链、标签文字，使用 rel=sponsored 标记" },
  { entry_date: "2026-04-01", type: "fix",     version: "3.33", zh: "修复首页冷启动慢（5-9s）导致 iOS Safari 弹出下载框的问题：改用 ISR 静态生成" },
  // v3.32
  { entry_date: "2026-04-01", type: "improve", version: "3.32", zh: "Redis 客户端升级为 Upstash HTTP 模式，无持久 TCP 连接，完全兼容 Vercel Serverless" },
  { entry_date: "2026-04-01", type: "improve", version: "3.32", zh: "站点设置新增 Redis L2 缓存（60s），冷启动时跳过 DB 查询，首屏响应更快" },
  { entry_date: "2026-04-01", type: "improve", version: "3.32", zh: "DB 连接池在 Vercel 环境自动降低 max 至 2，避免 Supabase 连接数超限" },
  // v3.31
  { entry_date: "2026-04-01", type: "improve", version: "3.31", zh: "HTTP 检测工具全面升级：安全评分环形图、7 项安全响应头检测、HSTS 徽标、详细响应信息" },
  { entry_date: "2026-04-01", type: "improve", version: "3.31", zh: "DNS 工具新增 SPF / DMARC 深度解析：机制列表、all 指令色码、策略对齐、报告地址" },
  { entry_date: "2026-04-01", type: "improve", version: "3.31", zh: "IP/ASN 页面新增外部查询链接：BGP.he.net、ARIN RDAP、Shodan、VirusTotal、IPinfo" },
  // v3.30
  { entry_date: "2026-04-01", type: "improve", version: "3.30", zh: "WHOIS 查询架构重构：whoiser 作为主查询源，自动处理 TLD 发现与转介链，移除静态 whois-servers.json 依赖" },
  { entry_date: "2026-04-01", type: "fix",     version: "3.30", zh: "修复切换查询时结果页跳动问题：骨架屏淡出 + 内容淡入动画，消除布局突变" },
  // v3.29
  { entry_date: "2026-04-01", type: "fix",     version: "3.29", zh: "修复 Vercel 环境无法查询部分 TLD（如 .me）的问题：改用 whoiser 作为主通道" },
  { entry_date: "2026-04-01", type: "improve", version: "3.29", zh: "服务器列表文件合并为两个：rdap_gtld_bootstrap.ts（1223 条）+ whois-servers.json（192 条），结构更清晰" },
  // v3.28
  { entry_date: "2026-03-29", type: "fix",     version: "3.28", zh: "仪表盘日期格式跟随用户语言显示，不再强制使用中文格式" },
  { entry_date: "2026-03-29", type: "improve", version: "3.28", zh: "WHOIS 结果页 meta 标签完整国际化：标题、描述、关键词、og:locale、JSON-LD 全部随语言切换" },
  // v3.27
  { entry_date: "2026-03-29", type: "fix",     version: "3.27", zh: "WHOIS 错误模式识别精化：速率限制不再触发付费 API 兜底，保护用量配额" },
  { entry_date: "2026-03-29", type: "improve", version: "3.27", zh: "管理后台全面性能优化：并行 DB 查询、DNS 缓存头、兜底表服务端搜索、实时内存门更新" },
  { entry_date: "2026-03-29", type: "improve", version: "3.27", zh: "管理后台 9 个旧页面整合为 2 个统一标签页（access-control / domains），旧 URL 自动 301 跳转" },
  // v3.26
  { entry_date: "2026-03-29", type: "improve", version: "3.26", zh: "首页预加载查询页编译，首次搜索等待时间从 12s 降至约 100ms" },
  { entry_date: "2026-03-29", type: "improve", version: "3.26", zh: "页面进度条：路由切换即时出现进度动画，消除「页面冻结」体感" },
  // v3.25
  { entry_date: "2026-03-29", type: "improve", version: "3.25", zh: "页面切换退出动画从 100ms 缩短至 50ms，路由跳转更流畅" },
  // v3.24
  { entry_date: "2026-03-29", type: "improve", version: "3.24", zh: "语言切换在首次绘制前同步，消除非中文用户的语言闪烁问题" },
  // v3.23
  { entry_date: "2026-03-29", type: "fix",     version: "3.23", zh: "修复查询失败错误提示误导性文字，更新为明确的 WHOIS/RDAP 查询失败说明" },
  { entry_date: "2026-03-29", type: "fix",     version: "3.23", zh: "无效 TLD 查询首次阻断：输入非法 TLD 会提示警告，二次确认才放行查询" },
  { entry_date: "2026-03-29", type: "improve", version: "3.23", zh: "同源请求绕过速率限制，管理后台及内部批量操作不受 40次/分钟约束" },
  // v3.22
  { entry_date: "2026-03-24", type: "fix",     version: "3.22", zh: "订阅权限跨设备/跨会话失效修复：后台从数据库实时读取权限，JWT 过期时自动修复，无需重新登录" },
  // v3.21
  { entry_date: "2026-03-24", type: "improve", version: "3.21", zh: "用户中心合并为单一 API 端点：订阅列表、品牌认领、TLD 配置四个数据库查询完全并行，首屏数据大幅加速" },
  { entry_date: "2026-03-24", type: "improve", version: "3.21", zh: "用户中心 60 秒客户端缓存：页面内导航切换立即显示缓存数据，后台静默刷新，彻底消除重复加载转圈" },
  // v3.20
  { entry_date: "2026-03-24", type: "improve", version: "3.20", zh: "致谢页各项目展示真实 favicon（Google Favicon 服务），无法加载时自动回退默认图标" },
  { entry_date: "2026-03-24", type: "improve", version: "3.20", zh: "更新记录页全面重设计：竖向时间线布局、超大版本号、彩色 NEW / IMPROVE / FIX 标签" },
  // v3.19
  { entry_date: "2026-03-24", type: "improve", version: "3.19", zh: "域名查询缓存分级精细化：到期 > 180 天 → 12 小时；> 60 天 → 6 小时；≤ 7 天 → 30 分钟，减少稳定域名重复查询" },
  // v3.18
  { entry_date: "2026-03-24", type: "improve", version: "3.18", zh: "OG 图片响应加入 Cache-Control 头（s-maxage=3600），相同 URL 首次生成后由 CDN 直接命中，无需再走 Edge Function" },
  // v3.17
  { entry_date: "2026-03-24", type: "improve", version: "3.17", zh: "匿名查询记录上限取消：原 50 条硬上限移除，所有匿名查询永久保存，同 IP 同查询自动去重" },
  { entry_date: "2026-03-24", type: "new",     version: "3.17", zh: "管理后台查询记录新增「已登录用户」筛选标签，与「全部」/「匿名查询」并列，数量角标实时准确" },
  // v3.16
  { entry_date: "2026-03-24", type: "improve", version: "3.16", zh: "订阅卡片全面升级：生命周期进度条 + 阶段提示文字 + 下次提醒日期 + 可调节提醒间隔（7/14/30/60/90 天，即点即存）" },
  { entry_date: "2026-03-24", type: "improve", version: "3.16", zh: "订阅标签页新增统计概览芯片（有效/即将到期/紧急/已过期）及高亮提醒横幅，列出受影响域名" },
  // v3.15
  { entry_date: "2026-03-24", type: "improve", version: "3.15", zh: "API lookup 精准识别域名/IPv4/IPv6/ASN/CIDR 查询类型，全用户高价值域名检测与告警" },
  // v3.14
  { entry_date: "2026-03-24", type: "new",     version: "3.14", zh: "TLD 生命周期管理页新增主流 TLD 内置参考数据表，一键对照修改覆盖规则" },
  // v3.13
  { entry_date: "2026-03-24", type: "fix",     version: "3.13", zh: "修复公告横幅与导航栏重叠遮挡问题" },
  { entry_date: "2026-03-24", type: "new",     version: "3.13", zh: "管理后台提醒支持内联编辑到期日 + 直接触发测试邮件发送" },
  // v3.12
  { entry_date: "2026-03-24", type: "fix",     version: "3.12", zh: "修复已登录用户查询历史未正确记录的问题（lookup API 鉴权判断错位）" },
  // v3.11
  { entry_date: "2026-03-24", type: "improve", version: "3.11", zh: "WHOIS 解析新增多语言域名状态字符串支持（保留/禁用/暂停等多语言变体）" },
  // v3.10
  { entry_date: "2026-03-24", type: "new",     version: "3.10", zh: "OG 图片文字可编辑：品牌名称、标语在后台实时修改，即时生效" },
  { entry_date: "2026-03-24", type: "improve", version: "3.10", zh: "OG 图片所有 8 种样式的品牌名 / 标语统一读取配置，不再硬编码" },
  { entry_date: "2026-03-24", type: "new",     version: "3.10", zh: "更新记录后台新增「同步版本历史」按钮，自动导入缺失条目" },
  { entry_date: "2026-03-24", type: "improve", version: "3.10", zh: "用户搜索历史隐藏高价值 / 有价值域名标签（数据仍后台记录）" },
  // v3.9
  { entry_date: "2026-03-24", type: "new",     version: "3.9", zh: "API Key 管理系统：支持生成、吊销、范围管理（api / subscription / all）" },
  { entry_date: "2026-03-24", type: "new",     version: "3.9", zh: "管理后台新增「密钥」页面，提供 Key 生成 / 启停 / 删除 / 使用统计" },
  { entry_date: "2026-03-24", type: "feature", version: "3.9", zh: "所有公开 API（WHOIS / DNS / SSL / IP）支持 X-API-Key 鉴权，全局可开关" },
  { entry_date: "2026-03-24", type: "improve", version: "3.9", zh: "文档页新增「API Key 鉴权」章节，说明传参方式、权限范围及错误码" },
  // v3.8
  { entry_date: "2026-03-23", type: "fix",     version: "3.8", zh: "修复页面切换动画失效问题（animationKey 逻辑错误）" },
  { entry_date: "2026-03-23", type: "fix",     version: "3.8", zh: "修复 DNS / SSL / IP 工具页 URL 参数在首次渲染时被忽略的问题" },
  { entry_date: "2026-03-23", type: "new",     version: "3.8", zh: "DNS / IP / SSL API 新增限流保护（60 / 30 / 20 次/分钟）" },
  { entry_date: "2026-03-23", type: "fix",     version: "3.8", zh: "修复站点名称水合不一致导致首屏闪烁的问题" },
  // v3.7
  { entry_date: "2026-03-23", type: "improve", version: "3.7", zh: "Redis 缓存升级为智能 TTL 策略：按域名类型自适应缓存时长" },
  { entry_date: "2026-03-23", type: "improve", version: "3.7", zh: "新增 L1（内存 30s）+ L2（Redis 自适应）双层缓存架构" },
  // v3.6
  { entry_date: "2026-03-22", type: "new",     version: "3.6", zh: "新增 WHOIS 限流（60 次/分钟）并引入 429 响应" },
  { entry_date: "2026-03-22", type: "improve", version: "3.6", zh: "文档页「限流规则」表格更新为实际阈值" },
  // v3.5
  { entry_date: "2026-03-22", type: "new",     version: "3.5", zh: "提醒管理后台：批量操作、状态筛选、到期日范围查询" },
  { entry_date: "2026-03-22", type: "improve", version: "3.5", zh: "提醒列表新增「上次发送时间」列，支持重新触发测试邮件" },
  // v3.4
  { entry_date: "2026-03-22", type: "new",     version: "3.4", zh: "用户管理后台：用户列表、禁用/解禁、权限查看与分配" },
  { entry_date: "2026-03-22", type: "new",     version: "3.4", zh: "品牌认领管理后台：审核、强制验证、批量清除失效认领" },
  // v3.3
  { entry_date: "2026-03-22", type: "new",     version: "3.3", zh: "用户反馈系统：前台在线提交反馈，管理后台按类别分类处理与状态流转" },
  { entry_date: "2026-03-22", type: "new",     version: "3.3", zh: "TLD 兜底 WHOIS 服务器：管理后台可自定义任意 TLD 的解析入口，解决小众 TLD 查询失败" },
  // v3.2
  { entry_date: "2026-03-21", type: "new",     version: "3.2", zh: "系统状态监控页：数据库 / 邮件 / Redis 连通性实时检查，管理员一览全局健康" },
  { entry_date: "2026-03-21", type: "new",     version: "3.2", zh: "站点公告功能：管理后台发布通知，用户首页顶部横幅实时展示" },
  // v3.1
  { entry_date: "2026-03-21", type: "new",     version: "3.1", zh: "Vercel 平台集成：域名 DNS 配置一键检测，自动比对 Vercel 所需记录与当前解析" },
  { entry_date: "2026-03-21", type: "improve", version: "3.1", zh: "Vercel 域名绑定助手：检测缺失记录并提供精确补全指引" },
  // v3.0
  { entry_date: "2026-03-21", type: "new",     version: "3.0", zh: "价格页面：多套餐定价方案对比，区分月付/年付与功能权限" },
  { entry_date: "2026-03-21", type: "new",     version: "3.0", zh: "赞助商展示系统：首页赞助商位，管理后台增删改查、排序、显示控制" },
  // v2.4
  { entry_date: "2026-03-20", type: "new",     version: "2.4", zh: "天虎平台集成：域名评估报告接入，查询结果页展示估值与市场参考" },
  { entry_date: "2026-03-20", type: "improve", version: "2.4", zh: "查询结果页新增「域名估值」模块，联动天虎 API 实时拉取数据" },
  // v2.3
  { entry_date: "2026-03-20", type: "new",     version: "2.3", zh: "查询历史系统：已登录用户自动记录每次查询，管理后台可查看所有用户历史" },
  { entry_date: "2026-03-20", type: "new",     version: "2.3", zh: "管理后台「查询记录」页面：全量历史、域名/用户筛选、匿名标注" },
];

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).end();
  }

  const admin = await requireAdmin(req, res);
  if (!admin) return;
  if (!(await isDbReady())) return res.status(503).json({ error: "数据库暂不可用" });

  try {
    const existing = await many<{ version: string; zh: string }>(
      `SELECT version, zh FROM changelog_entries WHERE version IS NOT NULL`,
    );
    const existingSet = new Set(existing.map(e => `${e.version}::${e.zh.slice(0, 40)}`));

    let inserted = 0;
    for (const e of SEED) {
      const key = `${e.version}::${e.zh.slice(0, 40)}`;
      if (existingSet.has(key)) continue;
      const id = randomBytes(8).toString("hex");
      await run(
        `INSERT INTO changelog_entries (id, entry_date, type, zh, en, version) VALUES ($1, $2, $3, $4, '', $5)`,
        [id, e.entry_date, e.type, e.zh, e.version],
      );
      inserted++;
    }

    return res.json({ ok: true, inserted, skipped: SEED.length - inserted });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
}
