import React from "react";
import Head from "next/head";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiDownloadLine, RiLoader4Line, RiDatabase2Line,
  RiCheckLine, RiErrorWarningLine, RiInformationLine,
  RiRefreshLine, RiFileTextLine,
} from "@remixicon/react";

type TableStat = {
  name: string;
  label: string;
  count: number;
  ephemeral?: boolean;
};

export default function DbExportPage() {
  const [stats, setStats] = React.useState<TableStat[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [downloading, setDownloading] = React.useState(false);
  const [skipEphemeral, setSkipEphemeral] = React.useState(true);

  async function loadStats() {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/db-export");
      const d = await r.json();
      setStats(d.tables ?? []);
    } catch {
      toast.error("加载统计失败");
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => { loadStats(); }, []);

  async function handleExport() {
    setDownloading(true);
    try {
      const params = skipEphemeral ? "" : "&skip_ephemeral=0";
      const r = await fetch(`/api/admin/db-export?download=1${params}`);
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        toast.error(d.error || "导出失败");
        return;
      }
      const blob = await r.blob();
      const disposition = r.headers.get("content-disposition") ?? "";
      const filenameMatch = disposition.match(/filename="([^"]+)"/);
      const filename = filenameMatch?.[1] ?? `db-export-${new Date().toISOString().slice(0, 10)}.json`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.success("数据库导出完成");
    } catch {
      toast.error("导出时发生网络错误");
    } finally {
      setDownloading(false);
    }
  }

  const includedTables = stats.filter(t => !t.ephemeral || !skipEphemeral);
  const skippedTables  = stats.filter(t => t.ephemeral && skipEphemeral);
  const totalRows      = includedTables.reduce((sum, t) => sum + Math.max(0, t.count), 0);
  const errorTables    = includedTables.filter(t => t.count < 0);

  return (
    <AdminLayout title="数据库导出">
      <Head><title>数据库导出 · Admin</title></Head>
      <div className="space-y-4">

        {/* Header */}
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div>
            <h2 className="text-lg font-bold">数据库导出</h2>
            <p className="text-xs text-muted-foreground mt-0.5">将全量数据导出为 JSON 文件，用于备份或迁移</p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              onClick={loadStats}
              disabled={loading}
              className="h-9 rounded-xl gap-2 text-sm"
            >
              {loading
                ? <RiLoader4Line className="w-4 h-4 animate-spin" />
                : <RiRefreshLine className="w-4 h-4" />}
              刷新统计
            </Button>
            <Button
              onClick={handleExport}
              disabled={downloading || loading}
              className="h-9 rounded-xl gap-2 font-semibold"
            >
              {downloading
                ? <><RiLoader4Line className="w-4 h-4 animate-spin" />导出中…</>
                : <><RiDownloadLine className="w-4 h-4" />导出 JSON</>}
            </Button>
          </div>
        </div>

        {/* Notice */}
        <div className="flex items-start gap-2.5 p-3.5 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800/40">
          <RiInformationLine className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
          <div className="text-xs text-amber-700 dark:text-amber-400 leading-relaxed">
            导出文件包含敏感信息（用户数据、密码哈希、支付记录等），请妥善保管，切勿泄露。
            导出为 JSON 格式，可用于数据迁移或备份恢复。
          </div>
        </div>

        {/* Options */}
        <div className="glass-panel border border-border rounded-2xl overflow-hidden">
          <div className="px-5 py-3 border-b border-border bg-muted/30 flex items-center gap-2">
            <RiFileTextLine className="w-4 h-4 text-muted-foreground" />
            <h3 className="text-sm font-bold">导出选项</h3>
          </div>
          <div className="p-5 space-y-3">
            <label className="flex items-start gap-3 cursor-pointer group">
              <div className="relative mt-0.5">
                <input
                  type="checkbox"
                  checked={skipEphemeral}
                  onChange={e => setSkipEphemeral(e.target.checked)}
                  className="peer sr-only"
                />
                <div className={cn(
                  "w-4 h-4 rounded border-2 flex items-center justify-center transition-colors",
                  skipEphemeral ? "bg-primary border-primary" : "border-border bg-background group-hover:border-primary/50"
                )}>
                  {skipEphemeral && <RiCheckLine className="w-3 h-3 text-primary-foreground" />}
                </div>
              </div>
              <div>
                <p className="text-sm font-medium">跳过临时数据表</p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  不导出密码重置令牌、频率限制记录等临时/过期数据，建议保持开启
                </p>
              </div>
            </label>
          </div>
        </div>

        {/* Stats */}
        <div className="glass-panel border border-border rounded-2xl overflow-hidden">
          <div className="px-5 py-3 border-b border-border bg-muted/30 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <RiDatabase2Line className="w-4 h-4 text-muted-foreground" />
              <h3 className="text-sm font-bold">数据表统计</h3>
            </div>
            {!loading && (
              <span className="text-xs text-muted-foreground">
                {includedTables.length} 张表 · 共 {totalRows.toLocaleString()} 行
              </span>
            )}
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-12 gap-2 text-muted-foreground">
              <RiLoader4Line className="w-5 h-5 animate-spin" />
              <span className="text-sm">加载中…</span>
            </div>
          ) : (
            <div className="divide-y divide-border">
              {includedTables.map(t => (
                <div key={t.name} className="flex items-center gap-3 px-5 py-2.5">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{t.label}</span>
                      <span className="text-[10px] font-mono text-muted-foreground/60">{t.name}</span>
                    </div>
                  </div>
                  {t.count < 0 ? (
                    <div className="flex items-center gap-1 text-red-500 text-xs">
                      <RiErrorWarningLine className="w-3.5 h-3.5" />
                      表不存在
                    </div>
                  ) : (
                    <span className={cn(
                      "text-sm font-mono tabular-nums font-semibold",
                      t.count === 0 ? "text-muted-foreground/40" : "text-foreground"
                    )}>
                      {t.count.toLocaleString()}
                    </span>
                  )}
                </div>
              ))}

              {skippedTables.length > 0 && (
                <div className="px-5 py-2.5 bg-muted/20">
                  <p className="text-xs text-muted-foreground">
                    已跳过临时表：{skippedTables.map(t => t.name).join("、")}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Error summary */}
        {errorTables.length > 0 && (
          <div className="flex items-start gap-2.5 p-3.5 rounded-xl bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-800/40">
            <RiErrorWarningLine className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
            <div className="text-xs text-red-700 dark:text-red-400">
              以下表格无法查询，可能尚未创建（首次 API 请求后会自动建表）：
              <span className="font-mono ml-1">{errorTables.map(t => t.name).join("、")}</span>
            </div>
          </div>
        )}

        {/* Format note */}
        <div className="p-4 rounded-xl bg-muted/40 border border-border/60">
          <p className="text-xs font-medium mb-1.5">导出格式说明</p>
          <p className="text-[11px] text-muted-foreground leading-relaxed">
            导出文件为标准 JSON，结构为 <code className="font-mono bg-muted px-1 rounded">{"{ exported_at, schema_version, meta, tables: { 表名: [行数据...] } }"}</code>。
            可通过脚本将 JSON 数据导入新数据库。每张表的行数据与数据库列完全对应，无需额外转换。
          </p>
        </div>

      </div>
    </AdminLayout>
  );
}
