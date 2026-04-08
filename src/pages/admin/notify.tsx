import React from "react";
import { GetServerSideProps } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { TextArea as Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import {
  RiMailSendLine,
  RiGroupLine,
  RiVipCrownLine,
  RiUserLine,
  RiLoader4Line,
  RiInformationLine,
} from "@remixicon/react";
import { cn } from "@/lib/utils";

type RecipientMode = "all" | "subscribed" | "custom";

export default function AdminNotifyPage() {
  const [mode, setMode] = React.useState<RecipientMode>("subscribed");
  const [customEmails, setCustomEmails] = React.useState("");
  const [subject, setSubject] = React.useState("");
  const [body, setBody] = React.useState("");
  const [count, setCount] = React.useState<number | null>(null);
  const [sending, setSending] = React.useState(false);
  const [pendingSend, setPendingSend] = React.useState(false);
  const [result, setResult] = React.useState<{ sent: number; failed: number; total: number } | null>(null);
  const [previewing, setPreviewing] = React.useState(false);

  React.useEffect(() => {
    setCount(null);
    setResult(null);
    if (mode === "all" || mode === "subscribed") {
      fetch(`/api/admin/notify?recipients=${mode}`)
        .then(r => r.json())
        .then(d => setCount(d.count ?? null))
        .catch(() => {});
    }
  }, [mode]);

  const customEmailList = React.useMemo(() => {
    return customEmails.split(/[\n,;]+/).map(e => e.trim()).filter(e => e.includes("@"));
  }, [customEmails]);

  async function handleSend() {
    if (!subject.trim()) { toast.error("请填写邮件主题"); return; }
    if (!body.trim()) { toast.error("请填写邮件正文"); return; }
    if (mode === "custom" && customEmailList.length === 0) {
      toast.error("请输入至少一个有效邮箱地址");
      return;
    }

    const recipients = mode === "custom" ? customEmailList : mode;
    const totalHint = mode === "custom"
      ? customEmailList.length
      : (count ?? "?");

    if (!pendingSend) { setPendingSend(true); return; }
    setPendingSend(false);
    setSending(true);
    setResult(null);

    try {
      const resp = await fetch("/api/admin/notify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ subject, bodyHtml: body.replace(/\n/g, "<br/>"), recipients }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        toast.error(data.error || "发送失败");
      } else {
        setResult(data);
        toast.success(`发送完成：成功 ${data.sent}，失败 ${data.failed}`);
      }
    } catch {
      toast.error("网络请求失败");
    } finally {
      setSending(false);
    }
  }

  const MODES: { key: RecipientMode; label: string; desc: string; icon: React.ElementType; color: string }[] = [
    { key: "subscribed", label: "订阅会员", desc: "仅发送给已开通会员订阅的用户", icon: RiVipCrownLine, color: "text-violet-500" },
    { key: "all", label: "全部用户", desc: "发送给所有未停用的注册用户", icon: RiGroupLine, color: "text-blue-500" },
    { key: "custom", label: "指定邮箱", desc: "手动输入收件人邮箱，逗号或换行分隔", icon: RiUserLine, color: "text-emerald-500" },
  ];

  return (
    <AdminLayout title="邮件通知">
      <div className="max-w-3xl mx-auto space-y-6 pb-16">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">邮件群发</h1>
          <p className="text-sm text-muted-foreground mt-1">向用户发送站点通知、公告或运营邮件</p>
        </div>

        <div className="rounded-xl border border-border bg-card p-5 space-y-4">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">收件人范围</p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {MODES.map(m => {
              const Icon = m.icon;
              const active = mode === m.key;
              return (
                <button
                  key={m.key}
                  onClick={() => setMode(m.key)}
                  className={cn(
                    "flex flex-col gap-1.5 p-4 rounded-xl border text-left transition-all",
                    active
                      ? "border-primary bg-primary/5 ring-1 ring-primary/30"
                      : "border-border bg-background hover:border-primary/40"
                  )}
                >
                  <div className="flex items-center gap-2">
                    <Icon className={cn("w-4 h-4", active ? "text-primary" : m.color)} />
                    <span className={cn("text-sm font-semibold", active ? "text-primary" : "text-foreground")}>{m.label}</span>
                    {(m.key === "all" || m.key === "subscribed") && mode === m.key && count !== null && (
                      <Badge variant="secondary" className="ml-auto text-[10px]">{count} 人</Badge>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">{m.desc}</p>
                </button>
              );
            })}
          </div>

          {mode === "custom" && (
            <div>
              <label className="text-xs font-medium text-muted-foreground block mb-1.5">收件人邮箱列表</label>
              <Textarea
                placeholder={"user1@example.com\nuser2@example.com, user3@example.com"}
                value={customEmails}
                onChange={e => setCustomEmails(e.target.value)}
                rows={4}
                className="font-mono text-sm resize-none"
              />
              {customEmailList.length > 0 && (
                <p className="text-xs text-muted-foreground mt-1.5">
                  已识别 <strong className="text-foreground">{customEmailList.length}</strong> 个有效邮箱
                </p>
              )}
            </div>
          )}
        </div>

        <div className="rounded-xl border border-border bg-card p-5 space-y-4">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">邮件内容</p>

          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1.5">邮件主题</label>
            <Input
              placeholder="例：系统维护通知 / 新功能上线公告"
              value={subject}
              onChange={e => setSubject(e.target.value)}
            />
            <p className="text-xs text-muted-foreground mt-1">
              实际主题为：{subject ? `"${subject} | 站点名称"` : <span className="italic">（未填写）</span>}
            </p>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-medium text-muted-foreground">正文内容</label>
              <button
                onClick={() => setPreviewing(p => !p)}
                className="text-xs text-primary underline underline-offset-2"
              >
                {previewing ? "编辑" : "预览 HTML"}
              </button>
            </div>
            {previewing ? (
              <div
                className="min-h-[160px] rounded-lg border border-border bg-muted/30 p-4 text-sm text-foreground leading-relaxed"
                dangerouslySetInnerHTML={{ __html: body.replace(/\n/g, "<br/>") }}
              />
            ) : (
              <Textarea
                placeholder={"支持换行，发送后将自动转换为 HTML。\n\n例：\n亲爱的用户，我们将于 2026-04-01 进行系统维护……"}
                value={body}
                onChange={e => setBody(e.target.value)}
                rows={8}
                className="resize-none text-sm"
              />
            )}
            <p className="text-xs text-muted-foreground mt-1 flex items-start gap-1">
              <RiInformationLine className="w-3 h-3 mt-0.5 shrink-0" />
              换行将自动转为 &lt;br/&gt;，支持手动输入 HTML 标签（加粗、链接等）
            </p>
          </div>
        </div>

        {result && (
          <div className={cn(
            "rounded-xl border p-4 flex items-start gap-3",
            result.failed === 0
              ? "border-emerald-200 bg-emerald-50 dark:bg-emerald-900/20 dark:border-emerald-800"
              : "border-amber-200 bg-amber-50 dark:bg-amber-900/20 dark:border-amber-800"
          )}>
            <RiMailSendLine className={cn("w-5 h-5 mt-0.5 shrink-0", result.failed === 0 ? "text-emerald-600" : "text-amber-600")} />
            <div>
              <p className="text-sm font-semibold text-foreground">发送完成</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                共 {result.total} 封 · 成功 <strong className="text-emerald-600">{result.sent}</strong>
                {result.failed > 0 && <> · 失败 <strong className="text-red-500">{result.failed}</strong></>}
              </p>
            </div>
          </div>
        )}

        <div className="flex items-center justify-end gap-3 flex-wrap">
          {pendingSend && (
            <span className="text-sm text-amber-600 dark:text-amber-400 font-medium">
              确认发送给 {mode === "custom" ? customEmailList.length : (count ?? "?")} 位收件人？
            </span>
          )}
          {pendingSend ? (
            <Button
              variant="outline"
              onClick={() => setPendingSend(false)}
              disabled={sending}
            >
              取消
            </Button>
          ) : (
            <Button
              variant="outline"
              onClick={() => { setSubject(""); setBody(""); setResult(null); }}
              disabled={sending}
            >
              清空
            </Button>
          )}
          <Button onClick={handleSend} disabled={sending} className={`gap-2 min-w-[120px] ${pendingSend ? "bg-amber-600 hover:bg-amber-700" : ""}`}>
            {sending
              ? <><RiLoader4Line className="w-4 h-4 animate-spin" /> 发送中…</>
              : pendingSend
                ? <><RiMailSendLine className="w-4 h-4" /> 确认发送</>
                : <><RiMailSendLine className="w-4 h-4" /> 发送邮件</>
            }
          </Button>
        </div>
      </div>
    </AdminLayout>
  );
}

export const getServerSideProps: GetServerSideProps = async (ctx) => {
  const session = await getServerSession(ctx.req, ctx.res, authOptions);
  if (!(session?.user as any)?.isAdmin) {
    return { redirect: { destination: "/login", permanent: false } };
  }
  return { props: {} };
};
