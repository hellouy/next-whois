import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { PageTabs } from "@/components/page-tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiRefreshLine, RiDeleteBinLine,
  RiCheckLine, RiCloseLine, RiWrenchLine, RiServerLine,
  RiAlertLine, RiInformationLine, RiTimeLine,
} from "@remixicon/react";

const TLD_TABS = [
  { href: "/admin/tld-lifecycle",          label: "生命周期" },
  { href: "/admin/tld-rules",              label: "TLD 规则" },
  { href: "/admin/tld-fallback",           label: "查询兜底" },
  { href: "/admin/tld-lifecycle-feedback", label: "纠错反馈" },
  { href: "/admin/repair-queue",           label: "服务器修复" },
  { href: "/admin/custom-servers",         label: "自定义服务器" },
  { href: "/admin/tld-probe",              label: "TLD 探测" },
  { href: "/admin/tld-registry",           label: "注册局信息" },
];

type RepairRow = {
  tld: string;
  fail_count: number;
  error_type: string;
  last_failed_at: string | null;
  repair_status: string;
  found_server: string | null;
  ai_notes: string | null;
  repaired_at: string | null;
};

type Summary = { repair_status: string; count: number };

function fmt(d: string | null) {
  if (!d) return "—";
  const date = new Date(d);
  const diff = Date.now() - date.getTime();
  const mins = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);
  if (mins < 1) return "刚刚";
  if (mins < 60) return `${mins}分钟前`;
  if (hours < 24) return `${hours}小时前`;
  if (days < 7) return `${days}天前`;
  return date.toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" });
}

const STATUS_STYLES: Record<string, string> = {
  pending:   "bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-400 border-amber-300/50",
  found:     "bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400 border-emerald-300/50",
  not_found: "bg-rose-50 dark:bg-rose-950/30 text-rose-700 dark:text-rose-400 border-rose-300/50",
  ignored:   "bg-muted/50 text-muted-foreground border-border/50",
};

const STATUS_LABELS: Record<string, string> = {
  pending:   "待修复",
  found:     "已修复",
  not_found: "未找到",
  ignored:   "已忽略",
};

export default function AdminRepairQueuePage() {
  const [rows, setRows] = React.useState<RepairRow[]>([]);
  const [summary, setSummary] = React.useState<Summary[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [repairing, setRepairing] = React.useState(false);
  const [actionId, setActionId] = React.useState<string | null>(null);

  function load() {
    setLoading(true);
    fetch("/api/admin/repair-servers")
      .then(r => r.json())
      .then(d => { setRows(d.rows ?? []); setSummary(d.summary ?? []); })
      .catch(e => toast.error(e.message))
      .finally(() => setLoading(false));
  }

  React.useEffect(() => { load(); }, []);

  async function runRepair() {
    setRepairing(true);
    try {
      const r = await fetch("/api/admin/repair-servers?limit=20", { method: "POST" });
      const d = await r.json();
      const ok  = (d.results ?? []).filter((x: any) => x.ok).length;
      const bad = (d.results ?? []).filter((x: any) => !x.ok).length;
      toast.success(`修复完成：${ok} 成功，${bad} 未找到`);
      load();
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setRepairing(false);
    }
  }

  async function resetNotFound() {
    try {
      await fetch("/api/admin/repair-servers?reset=1", { method: "POST" });
      toast.success("已将 not_found 重置为 pending");
      load();
    } catch (e: any) {
      toast.error(e.message);
    }
  }

  async function ignoreTld(tld: string) {
    setActionId(tld);
    try {
      await fetch(`/api/admin/repair-servers?tld=${encodeURIComponent(tld)}`, { method: "DELETE" });
      toast.success(`.${tld} 已标记为忽略`);
      load();
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setActionId(null);
    }
  }

  const pending   = rows.filter(r => r.repair_status === "pending");
  const repaired  = rows.filter(r => r.repair_status === "found");
  const notFound  = rows.filter(r => r.repair_status === "not_found");
  const ignored   = rows.filter(r => r.repair_status === "ignored");

  return (
    <AdminLayout title="TLD 管理">
      <div className="space-y-5">
        <PageTabs tabs={TLD_TABS} />

        {/* Header */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h2 className="text-lg font-bold">WHOIS/RDAP 服务器修复队列</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              记录每次返回「IANA 兜底页」的 TLD，通过 RDAP bootstrap → IANA TCP → AI 三级策略自动发现正确服务器
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Button variant="outline" size="sm" onClick={load} disabled={loading}>
              <RiRefreshLine className={cn("w-4 h-4 mr-1.5", loading && "animate-spin")} />
              刷新
            </Button>
            <Button variant="outline" size="sm" onClick={resetNotFound}>
              <RiCloseLine className="w-4 h-4 mr-1.5" />
              重置 not_found
            </Button>
            <Button size="sm" onClick={runRepair} disabled={repairing || pending.length === 0}
              className="gap-1.5">
              {repairing ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiWrenchLine className="w-4 h-4" />}
              运行修复 ({pending.length})
            </Button>
          </div>
        </div>

        {/* Summary */}
        <div className="flex gap-3 flex-wrap">
          {[
            { key: "pending",   label: "待修复", icon: RiAlertLine,      color: "text-amber-500" },
            { key: "found",     label: "已修复", icon: RiCheckLine,      color: "text-emerald-500" },
            { key: "not_found", label: "未找到", icon: RiCloseLine,      color: "text-rose-500" },
            { key: "ignored",   label: "已忽略", icon: RiInformationLine, color: "text-muted-foreground" },
          ].map(({ key, label, icon: Icon, color }) => {
            const count = summary.find(s => s.repair_status === key)?.count ?? 0;
            return (
              <div key={key} className="flex items-center gap-2 px-3 py-1.5 rounded-lg border bg-card text-sm">
                <Icon className={cn("w-4 h-4", color)} />
                <span className="text-muted-foreground">{label}</span>
                <span className="font-bold tabular-nums">{count}</span>
              </div>
            );
          })}
        </div>

        {/* Script hint */}
        <div className="flex items-start gap-2 rounded-xl border border-blue-200/50 bg-blue-50/30 dark:bg-blue-950/20 px-4 py-3">
          <RiInformationLine className="w-4 h-4 text-blue-500 shrink-0 mt-0.5" />
          <p className="text-xs text-muted-foreground leading-relaxed">
            也可在后台脚本中运行批量修复：
            <code className="mx-1 font-mono text-foreground">node scripts/repair-servers.mjs --min-failures 2 --limit 50</code>
            支持 <code className="font-mono">--dry-run</code>、<code className="font-mono">--tld xx</code>、<code className="font-mono">--reset-not-found</code> 等参数。
          </p>
        </div>

        {/* Pending table */}
        {pending.length > 0 && (
          <Section title="待修复" count={pending.length} color="text-amber-500">
            <RepairTable rows={pending} onIgnore={ignoreTld} actionId={actionId} />
          </Section>
        )}

        {/* Not found */}
        {notFound.length > 0 && (
          <Section title="未找到" count={notFound.length} color="text-rose-500">
            <RepairTable rows={notFound} onIgnore={ignoreTld} actionId={actionId} />
          </Section>
        )}

        {/* Repaired */}
        {repaired.length > 0 && (
          <Section title="已修复" count={repaired.length} color="text-emerald-500">
            <RepairTable rows={repaired} onIgnore={ignoreTld} actionId={actionId} />
          </Section>
        )}

        {/* Ignored */}
        {ignored.length > 0 && (
          <Section title="已忽略" count={ignored.length} color="text-muted-foreground">
            <RepairTable rows={ignored} onIgnore={ignoreTld} actionId={actionId} />
          </Section>
        )}

        {rows.length === 0 && !loading && (
          <div className="text-center py-16 text-muted-foreground text-sm">
            <RiServerLine className="w-10 h-10 mx-auto mb-3 opacity-25" />
            <p>暂无记录。当查询某 TLD 时收到 IANA 兜底页，系统会自动将其加入队列。</p>
          </div>
        )}
      </div>
    </AdminLayout>
  );
}

function Section({ title, count, color, children }: {
  title: string; count: number; color: string; children: React.ReactNode;
}) {
  const [open, setOpen] = React.useState(true);
  return (
    <div className="glass-panel border border-border rounded-2xl overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-muted/30 transition-colors"
      >
        <span className="font-semibold text-sm flex items-center gap-2">
          <span className={color}>{title}</span>
          <Badge variant="outline" className="text-[10px] font-mono">{count}</Badge>
        </span>
        <span className="text-muted-foreground text-xs">{open ? "▲" : "▼"}</span>
      </button>
      {open && children}
    </div>
  );
}

function RepairTable({ rows, onIgnore, actionId }: {
  rows: RepairRow[];
  onIgnore: (tld: string) => void;
  actionId: string | null;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-t border-border/60 bg-muted/20">
            {["TLD", "失败次数", "错误类型", "最后失败", "状态", "发现服务器", "AI 备注", "修复时间", "操作"].map(h => (
              <th key={h} className="text-left text-[11px] font-semibold text-muted-foreground px-4 py-2.5 whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={row.tld}
              className={cn("border-t border-border/40 hover:bg-muted/15 transition-colors", i % 2 === 0 ? "" : "bg-muted/5")}
            >
              <td className="px-4 py-2.5 font-mono font-semibold text-foreground">.{row.tld}</td>
              <td className="px-4 py-2.5 tabular-nums text-center">{row.fail_count}</td>
              <td className="px-4 py-2.5 text-muted-foreground font-mono text-[11px]">{row.error_type}</td>
              <td className="px-4 py-2.5 text-muted-foreground whitespace-nowrap">
                <span className="flex items-center gap-1">
                  <RiTimeLine className="w-3 h-3 shrink-0" />
                  {fmt(row.last_failed_at)}
                </span>
              </td>
              <td className="px-4 py-2.5">
                <Badge variant="outline" className={cn("text-[10px] font-semibold", STATUS_STYLES[row.repair_status] ?? "")}>
                  {STATUS_LABELS[row.repair_status] ?? row.repair_status}
                </Badge>
              </td>
              <td className="px-4 py-2.5 font-mono text-[11px] text-foreground max-w-[220px] truncate">
                {row.found_server ?? <span className="text-muted-foreground/50">—</span>}
              </td>
              <td className="px-4 py-2.5 text-[11px] text-muted-foreground max-w-[200px] truncate" title={row.ai_notes ?? ""}>
                {row.ai_notes ?? "—"}
              </td>
              <td className="px-4 py-2.5 text-muted-foreground whitespace-nowrap text-[11px]">
                {row.repaired_at ? fmt(row.repaired_at) : "—"}
              </td>
              <td className="px-4 py-2.5">
                {row.repair_status !== "ignored" && (
                  <button
                    onClick={() => onIgnore(row.tld)}
                    disabled={actionId === row.tld}
                    title="忽略此 TLD"
                    className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-destructive transition-colors"
                  >
                    {actionId === row.tld
                      ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                      : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
