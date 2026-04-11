<div align="center">

<img src="/public/icons/icon-512x512.png" alt="Next Whois" width="64" height="64">

# Next Whois (hellouy fork)

**高性能 WHOIS/RDAP 域名查询工具** — 基于 [zmh-program/next-whois-ui](https://github.com/zmh-program/next-whois-ui) 深度二次开发，在原版基础上新增完整的后台管理系统、多级缓存优化、第三方 WHOIS API 兜底、流式输出、批量查询等企业级特性。

[English](#features) · [部署说明](#deploy) · [环境变量](#environment-variables) · [API 文档](#api)

[![Based on](https://img.shields.io/badge/based%20on-zmh--program%2Fnext--whois--ui-blue)](https://github.com/zmh-program/next-whois-ui)
[![Next.js](https://img.shields.io/badge/Next.js-14-black)](https://nextjs.org)
[![Version](https://img.shields.io/badge/version-3.35.0-green)](https://github.com/hellouy/next-whois)

</div>

---

## 相比原版的核心增强

| 模块 | 原版 | 本版 |
|------|------|------|
| 缓存层 | 单层 Redis | L1 内存 + L2 Redis（Upstash/ioredis）+ L3 Supabase DB 三级缓存 |
| WHOIS 来源 | whoiser 库 | whoiser + 第三方 API 兜底（西数、WhoisFreaks 等，按 TLD 路由）|
| 查询模式 | 同步返回 | 流式输出（SSE）+ 批量查询 `/api/lookup-batch` |
| 解析器 | 单文件 | 拆分为独立模块：日期、状态注入、预处理器、工具函数 |
| RDAP 解析 | 基础 | 完整 EPP 状态码库（800+ 条目）+ RDAP gTLD bootstrap |
| 后台管理 | 无 | 完整 Admin 面板（用户/API Key/TLD 规则/系统监控/GitHub 同步）|
| 数据持久化 | 无 | Supabase PostgreSQL（查询记录、用户系统、订阅、提醒等）|
| 认证 | 无 | NextAuth.js（邮箱注册/登录/找回密码/邮件验证）|
| 通知 | 无 | 域名到期提醒、邮件队列、Webhook 通知 |
| 爬虫/数据 | 无 | TLD 注册表爬取、批量扫描、失败率监控 |

---

## Features

- **WHOIS & RDAP** — 域名、IPv4、IPv6、ASN、CIDR 查询，RDAP 优先 + WHOIS 兜底
- **第三方 API 兜底** — 当直连 WHOIS 服务器失败时，自动切换至第三方 API（按 TLD 配置）
- **流式输出（SSE）** — `/api/lookup-stream` 实时推送解析进度，零感知等待
- **批量查询** — `/api/lookup-batch` 支持多域名并行查询
- **三级缓存** — 进程内 LRU（60s）→ Redis → Supabase DB，雪崩保护 + SWR 后台刷新
- **EPP 状态码** — 完整 ICANN EPP 状态码解释库，含人类可读描述
- **Admin 后台** — 用户管理、API Key、TLD 规则、系统状态、GitHub 一键同步
- **用户系统** — 注册/登录/订阅/额度/查询历史/域名到期提醒
- **Dynamic OG Images** — Satori 生成 Open Graph 图片
- **响应式 UI** — Shadcn UI + Tailwind CSS，支持 PWA、深色/浅色主题
- **i18n** — 中文（简/繁）、英文、俄文、日文、德文、法文、韩文
- **内置 API 文档** — `/docs` 页面，含交互式示例

---

## Deploy

### Vercel（推荐）

```bash
# 1. Fork 本仓库
# 2. 在 Vercel 导入项目
# 3. 配置以下环境变量
# 4. 部署
```

### Source Code

```bash
git clone https://github.com/hellouy/next-whois
cd next-whois
pnpm install
pnpm dev
```

---

## Environment Variables

### 基础配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `NEXT_PUBLIC_SITE_TITLE` | 站点标题 | Next Whois |
| `NEXT_PUBLIC_SITE_DESCRIPTION` | 站点描述 | — |
| `NEXT_PUBLIC_SITE_URL` | 站点 URL（OG 图片等） | — |
| `NEXT_PUBLIC_HISTORY_LIMIT` | 本地历史记录上限（-1 不限） | -1 |
| `NEXT_PUBLIC_MAX_WHOIS_FOLLOW` | WHOIS 跳转跟随深度 | 0 |

### 数据库（必须）

| 变量 | 说明 |
|------|------|
| `SUPABASE_DATABASE_URL` | Supabase 连接字符串（Transaction Pooler，端口 6543）|
| `DIRECT_URL` | Supabase 直连 URL（端口 5432，用于 migrate）|

### Redis 缓存（可选，支持多种客户端）

| 变量 | 说明 |
|------|------|
| `KV_REST_API_URL` | Upstash Redis REST URL |
| `KV_REST_API_TOKEN` | Upstash Redis REST Token |
| `REDIS_URL` | ioredis 连接 URL（`rediss://` 支持 TLS）|
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD` | ioredis 分离配置 |
| `REDIS_CACHE_TTL` | 缓存 TTL（秒） | 3600 |

### 认证

| 变量 | 说明 |
|------|------|
| `NEXTAUTH_SECRET` | NextAuth 签名密钥（必须）|
| `NEXTAUTH_URL` | 应用 URL（生产环境必须）|
| `ADMIN_EMAIL` | 管理员邮箱（后台访问权限）|

### 邮件

| 变量 | 说明 |
|------|------|
| `SMTP_HOST` | SMTP 服务器地址 |
| `SMTP_PORT` | SMTP 端口 |
| `SMTP_USER` | SMTP 用户名 |
| `SMTP_PASS` | SMTP 密码 |
| `SMTP_FROM` | 发件人地址 |

### 第三方 WHOIS API（可选）

| 变量 | 说明 |
|------|------|
| `XISHU_API_KEY` | 西数 WHOIS API Key |
| `WHOISFREAKS_API_KEY` | WhoisFreaks API Key |

### 其他集成

| 变量 | 说明 |
|------|------|
| `GITHUB_TOKEN` | GitHub PAT（Admin 后台一键同步功能）|
| `VERCEL_TOKEN` | Vercel API Token（部署触发）|
| `MOZ_ACCESS_ID` / `MOZ_SECRET_KEY` | Moz DA/PA 评分（可选）|

---

## API

### 主要接口

```
GET  /api/lookup?query=google.com          # 标准 WHOIS/RDAP 查询
GET  /api/lookup-stream?query=google.com   # 流式输出（SSE）
POST /api/lookup-batch                     # 批量查询（JSON body: { queries: [...] }）
GET  /api/og-image?query=google.com        # OG 图片生成
GET  /api/dns/records?domain=google.com    # DNS 记录查询
GET  /api/ssl/cert?domain=google.com       # SSL 证书查询
GET  /api/ip/lookup?ip=1.1.1.1            # IP 归属查询
```

### 管理接口（需 Admin 认证）

```
GET  /api/admin/stats          # 系统统计
GET  /api/admin/tld-rules      # TLD 规则配置
GET  /api/admin/users          # 用户管理
POST /api/admin/git-force-push # 一键同步到 GitHub
```

---

## Tech Stack

- **Framework** — Next.js 14（Pages Router）
- **Database** — Supabase PostgreSQL（via `pg` + `drizzle-orm`）
- **Cache** — Upstash Redis（HTTP）+ ioredis（TCP）+ DB cache
- **Auth** — NextAuth.js
- **WHOIS** — [whoiser](https://www.npmjs.com/package/whoiser) + 自建 RDAP 客户端 + 第三方 API
- **UI** — Shadcn UI + Tailwind CSS + Framer Motion
- **OG Image** — Satori（via `next/og`）
- **Email** — Nodemailer

---

## 致谢

本项目基于 [zmh-program/next-whois-ui](https://github.com/zmh-program/next-whois-ui) 开发，感谢原作者的开源贡献。

---

<div align="center">

MIT License · [hellouy/next-whois](https://github.com/hellouy/next-whois)

</div>
