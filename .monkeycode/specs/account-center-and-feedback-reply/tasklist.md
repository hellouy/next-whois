# 需求实施计划 — account-center-and-feedback-reply

## 阶段一：反馈站内回复（R1）

- [x] 1. 数据迁移 — `feedback` 表新增 `reply TEXT` 与 `replied_at TIMESTAMPTZ`（db.ts 自动迁移 + 复用既有 handled/handled_at）
- [x] 2. 后台回复 API — `POST /api/admin/feedback?id=` 校验非空(≤2000)，`UPDATE feedback SET reply/replied_at/handled=true/handled_at`，按 email 匹配 users 命中则 `recordNotification(type:'feedback_reply')`
- [x] 3. 站内通知类型 — `NotificationType` 新增 `feedback_reply`；navbar 铃铛图标 `RiMailCheckLine`
- [x] 4. 前台反馈历史 API — 新增 `GET /api/feedback/mine`（登录用户返回带回复的自身反馈列表，未登录返回空）
- [x] 5. 后台反馈页内联回复 — `admin/feedback.tsx` 展开区显示历史回复 + 「站内回复」内联表单（TextArea/提交/取消），mailto 降为辅助操作
- [x] 6. 前台「我的反馈」 — `feedback.tsx` 新增可折叠历史区，登录后拉取并展示反馈与回复（无回复显示「暂无回复」）
- [x] 7. 单元测试 — `feedback.test.ts` 覆盖空回复/超长/404/正常+通知/无账号跳过/无邮箱跳过

## 阶段二：注册用户名必填（R2）

- [x] 8. 后端校验 — `register.ts` 校验 `name` 非空(≤50)，移除可选分支，始终写入 `users.name`
- [x] 9. 前端校验 — `register.tsx` 提交前非空+长度校验，label 改必填星标，去掉「可选」
- [x] 10. 多语言文案 — 新增 `register_err_name_required` / `register_err_name_too_long`（8 语言），移除 `register_name_optional`

## 阶段三：个人中心用户名展示（R3）

- [x] 11. 邮箱前缀回退 — `AccountTab.tsx` 头部展示名回退为邮箱前缀（仅展示不落库），未设置时提供「设置用户名」入口
- [x] 12. 多语言文案 — 新增 `dashboard.set_nickname`（8 语言）

## 阶段四：独立购买记录页与充值页（R4）

- [x] 13. `/account/orders` 独立购买记录页 — 登录态展示购买记录（`/api/user/orders`）+ 余额摘要 + 余额变动明细（`/api/user/balance-transactions`）；未登录重定向登录页
- [x] 14. `/account/recharge` 独立充值页 — 复用 `/payment/recharge` 页面组件（默认导出直接复用），支付流程/登录守卫保持一致
- [x] 15. dashboard 入口改跳独立页 — `onGoRecharge → /account/recharge`、`onGoOrders → /account/orders`（AccountTab 按钮语义不变）
- [x] 16. 未登录守卫 — 两独立页均按既有 `/payment/recharge` 模式在客户端重定向 `/login?callbackUrl=...`

## 验证

- [x] 17. `tsc --noEmit` 0 错误；`check-locale-keys` 8 语言同步（复用既有键，无新增）；vitest 全量通过（含 feedback.test 6 例）
