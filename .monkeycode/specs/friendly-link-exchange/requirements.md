# Requirements Document

## Introduction

为 `/links` 友情链接页面新增"友链申请与自动审核"能力：访客可在线提交友链申请，
系统自动抓取对方网站并检测是否已放置本站链接（反链），已放置则自动通过并上链，
未检出则进入人工审核队列；同时为通过审核的站点提供可一键复制的文字徽章与图标徽章
HTML 片段，方便双方页面对接。

## Glossary

- **申请（Application）**：访客通过友链表单提交的一次友链请求记录
- **反链检测（Backlink Check）**：抓取申请站点页面，查找指向本站 URL/域名的链接
- **徽章（Badge）**：供对方嵌入其页面的、指向本站的一段 HTML 片段（文字版与图标版）
- **本站标识（Site Identity）**：由 `og_url`/站点域名/站点名组成的匹配目标集合

## Requirements

### Requirement 1 — 友链申请表单

**User Story:** AS 站长/访客，I want 在线填写友链信息，so that 我能便捷地申请友链。

#### Acceptance Criteria

1. GIVEN 访客访问 `/links` 页面，WHEN 访客点击"申请友链"，THE 系统 SHALL 展示友链申请表单。
2. WHEN 访客提交站点名称、网站 URL、简介、联系邮箱、建议分类，THE 系统 SHALL 将申请写入待审队列。
3. WHEN 提交的 URL 非 `http/https` 或格式非法，THE 系统 SHALL 拒绝该申请并提示错误。
4. IF 提交信息命中反滥用规则（频控超限、蜜罐字段非空、提交耗时过短），THE 系统 SHALL 拒收或静默丢弃该请求。
5. GIVEN 同一 URL 已存在已通过申请或已上链，WHEN 再次提交，THE 系统 SHALL 拒绝并提示重复。

### Requirement 2 — 自动反链检测审核

**User Story:** AS 站长，I want 对方已挂我站链接时自动放行，so that 双边友链能快速生效。

#### Acceptance Criteria

1. WHEN 申请通过基础校验，THE 系统 SHALL 抓取申请站点页面并检索本站标识。
2. IF 任一被抓取页面包含本站标识，THE 系统 SHALL 将申请标记为"自动通过"，将其计入 `friendly_links` 并启用显示。
3. IF 全部被抓取页面均不包含本站标识，THE 系统 SHALL 将申请标记为"待人工审核"。
4. IF 页面抓取失败（超时/不可达/无有效内容），THE 系统 SHALL 保守判定为"待人工审核"。
5. WHEN 判定完成，THE 系统 SHALL 持久化检测结果、抓取摘要与判定时间。

### Requirement 3 — 人工审核队列

**User Story:** AS 管理员，I want 集中处理待审与驳回的申请，so that 保底兜住自动检测的漏网。

#### Acceptance Criteria

1. WHILE 存在待人工审核的申请，管理员在后台"友链申请"页 SHALL 查看其站点、申请人联系方式、反链检测结果与摘要。
2. WHEN 管理员执行"通过"，THE 系统 SHALL 将申请计入 `friendly_links` 并保留检测快照。
3. WHEN 管理员执行"拒绝"或"删除"，THE 系统 SHALL 卸载申请并记录原因。

### Requirement 4 — 徽章生成与一键复制

**User Story:** AS 申请人，I want 拿到一段可粘贴的徽章代码，so that 我能把本站徽章放到自己页面完成兑换。

#### Acceptance Criteria

1. WHEN 申请提交成功，THE 系统 SHALL 为用户展示文字徽章与图标徽章两种 HTML 片段。
2. EACH 徽章片段 SHALL 包含指向本站的 `href` 链接与本站名称/标识，可安全嵌入第三方页面。
3. WHEN 用户点击"复制"，THE 系统 SHALL 将对应 HTML 片段复制到剪贴板并反馈复制状态。
4. IF 页面展示的徽章被用户嵌入其站点，被本站自动反链检测识别为站点标识，THEN 该站后续申请可自动通过。

### Requirement 5 — 审核结果通知

**User Story:** AS 申请人，I want 收到审核结果邮件，so that 我能及时知道通过与否及原因的起点。

#### Acceptance Criteria

1. WHEN 申请审核产生结果（自动通过/人工通过/拒绝），THE 系统 SHALL 向申请人邮箱发送结果邮件。
2. IF 申请人邮箱无效或邮件发送失败，THE 系统 SHALL 记录发送失败且不影响审核结果。

### Requirement 6 — 管理员通知

**User Story:** AS 管理员，I want 有新申请时收到提醒，so that 能及时处理人工审核队列。

#### Acceptance Criteria

1. WHEN 一条申请进入"待人工审核"，THE 系统 SHALL 向管理员发送通知（邮件）或后台提醒。

## 已确认决策

- 反链检测抓取范围：首页 + 常见友链页（`/links`、`/friends`、`/friend`、`/link` 等同域候选路径）
- 徽章 HTML 展示时机：提交成功即展示（含待审核标注），便于对方尽快挂链命中自动审核
- 申请入口形式：独立 `/links/apply` 页面