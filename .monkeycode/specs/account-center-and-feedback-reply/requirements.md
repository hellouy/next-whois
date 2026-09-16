# Requirements Document

Feature Name: account-center-and-feedback-reply
Updated: 2026-09-16

## Introduction

优化网站的用户反馈处理与用户中心体验，包含四个子需求：
1. 后台反馈处理改为站内直接回复（替代当前跳转邮件客户端的 mailto 方式）
2. 创建账户时用户名改为必填
3. 个人中心显示用户名
4. 将账户余额与购买记录从"跳转会员页"改为独立的充值页与购买记录页

## Glossary

- **反馈（Feedback）**：用户通过前台反馈表单提交的问题记录，存储于 `feedback` 表。
- **站内回复（Inline Reply）**：后台管理员填写回复内容，存储后通过站内通知推送给提交反馈的用户。
- **站内通知（Notification）**：复用现有 `notifications` 表与用户通知中心。
- **购买记录（Order）**：用户支付的订单，数据来自 `payment_orders` 表，现有 API `/api/user/orders`。
- **余额（Balance）**：账户充值余额，现有 API `/api/user/balance-transactions`。
- **充值（Recharge）**：用户为账户余额充值的行为，现有充值入口为 `/payment/checkout`。

---

## Requirements

### Requirement 1: 反馈站内回复

**User Story:** AS 后台管理员, I want 在反馈处理页面直接填写回复并提交, so that 用户无需依赖邮件客户端即可收到处理结果.

#### Acceptance Criteria

1. WHEN 后台管理员在反馈处理页面点击"回复"，系统 SHALL 展开回复表单（文本域与提交按钮）而不跳转邮件客户端。
2. WHEN 后台管理员填写回复内容并提交，系统 SHALL 校验内容非空并将回复持久化存储。
3. WHEN 回复存储成功，系统 SHALL 向提交该反馈的用户发送一条站内通知，内容包含回复正文与关联的反馈内容。
4. WHEN 回复成功提交，系统 SHALL 将反馈标记为已处理（handled=true, handled_at 记录时间）。
5. IF 回复内容为空，系统 SHALL 拒绝提交并提示管理员。

#### 设计要点
- `feedback` 表新增 `reply` 与 `replied_at` 字段（或新建回复关联表，实现时评估）。
- 通知复用现有 `notifications` 表插入逻辑与通知中心渲染。
- 前台反馈页新增"我的反馈"历史区，展示该用户提交的反馈与后台回复往来记录。
- 保留 `mailto` 作为辅助操作，但站内回复成为主操作。

### Requirement 2: 注册用户名必填

**User Story:** AS 新用户, I want 注册时填写用户名, so that 我的个人中心能展示专属名称.

#### Acceptance Criteria

1. WHEN 新用户在注册页填写注册信息，系统 SHALL 要求用户名非空。
2. WHEN 用户名输入为空，系统 SHALL 阻止注册提交并提示"用户名不能为空"。
3. WHEN 用户名长度超过 50 字符，系统 SHALL 阻止提交并提示长度超限。
4. WHEN 注册成功，系统 SHALL 将用户名写入 `users.name` 字段。
5. WHEN 用户已注册登录，系统 SHALL 在个人中心展示该用户名。

#### 设计要点
- 后端 `/api/user/register` 已支持 `name` 字段，补充必填校验。
- 前端 `register.tsx` 将用户名从可选改为必填，去掉"可选"标注并增加必填校验与占位提示。
- 多语言文案需要为必填错误补充翻译键。

### Requirement 3: 个人中心显示用户名

**User Story:** AS 登录用户, I want 在个人中心看到自己的用户名, so that 我能确认账户显示名.

#### Acceptance Criteria

1. WHILE 用户登录并在个人中心（AccountTab），系统 SHALL 展示用户名。
2. WHEN 用户已设置用户名，系统 SHALL 显示该用户名。
3. WHEN 用户未设置用户名（历史账户），系统 SHALL 显示邮箱前缀作为默认显示名，并提供设置入口。

#### 设计要点
- `AccountTab.tsx` 已展示 `user.name`（未设置显示"未设置"），补充邮箱前缀默认值与设置引导。
- 邮箱前缀默认名仅用于展示，不写入数据库，避免破坏可编辑姓名逻辑。

### Requirement 4: 独立购买记录页与充值页

**User Story:** AS 登录用户, I want 独立的购买记录页与充值页, so that 我不再需要跳转到会员页才能查看余额与订单.

#### Acceptance Criteria

1. WHEN 用户访问 `/account/orders`，系统 SHALL 展示该用户的全部购买记录（订单列表）。
2. WHEN 用户访问 `/account/recharge`，系统 SHALL 提供余额充值入口（复用现有支付能力）。
3. WHEN 用户在个人中心点击"账户余额"入口，系统 SHALL 跳转到充值页 `/account/recharge`。
4. WHEN 用户在个人中心点击"购买记录"入口，系统 SHALL 跳转到购买记录页 `/account/orders`。
5. WHILE 用户未登录，系统 SHALL 将 `/account/orders` 与 `/account/recharge` 重定向到登录页。

#### 设计要点
- 新建 `/account/orders` 与 `/account/recharge` 两个独立页面，需登录访问。
- 复用现有 `/api/user/orders` 与 `/api/user/balance-transactions` API。
- 充值页复用 `/payment/checkout` 的充值表单与支付流程。
- dashboard 中"余额""购买记录"入口改为跳转独立页。
