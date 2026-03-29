import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { PageTabs } from "@/components/page-tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiDeleteBinLine, RiRefreshLine,
  RiToggleLine, RiAlertLine, RiCheckLine, RiServerLine,
  RiAddLine, RiPencilLine, RiCloseLine, RiSaveLine,
  RiSettings3Line, RiGlobalLine, RiWifiLine,
  RiFlaskLine, RiCheckboxCircleLine, RiCloseCircleLine, RiTimeLine,
  RiDatabase2Line, RiArrowDownSLine, RiArrowUpSLine,
} from "@remixicon/react";
import type { CustomServerEntry, TcpServerEntry, HttpServerEntry } from "@/lib/whois/custom-servers";

type BuiltinRdapEntry = { url: string; source: "cctld-override" | "gtld-bootstrap" };
type BuiltinServers = {
  rdap: Record<string, BuiltinRdapEntry>;
  whois: Record<string, string | null>;
  rdapTotal: number;
  whoisTotal: number;
};

const TLD_TABS = [
  { href: "/admin/domains",      label: "TLD 管理" },
  { href: "/admin/tld-rules",   label: "TLD 规则" },
  { href: "/admin/tld-fallback", label: "查询兜底" },
];

type FallbackRow = {
  tld: string;
  fail_count: number;
  use_fallback: boolean;
  last_fail_at: string | null;
};

type ServerWithSource = {
  entry: CustomServerEntry;
  source: "manual" | "iana" | "repair" | "registry";
};

type ServerType = "whois-tcp" | "rdap-http" | "http-whois";

function fmt(d: string | null) {
  if (!d) return "—";
  const date = new Date(d);
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  const mins = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);
  if (mins < 1) return "刚刚";
  if (mins < 60) return `${mins}分钟前`;
  if (hours < 24) return `${hours}小时前`;
  if (days < 7) return `${days}天前`;
  return date.toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" });
}

function entryLabel(entry: CustomServerEntry): string {
  if (typeof entry === "string") return entry;
  if (entry.type === "tcp") return `TCP: ${entry.host}${entry.port ? `:${entry.port}` : ""}`;
  if (entry.type === "http") return `HTTP: ${entry.url}`;
  if (entry.type === "scraper") return `Scraper: ${entry.name}`;
  return JSON.stringify(entry);
}

function entryType(entry: CustomServerEntry): string {
  if (typeof entry === "string") return "WHOIS";
  if (entry.type === "tcp") return "WHOIS";
  if (entry.type === "http") {
    const url = (entry as HttpServerEntry).url;
    if (url.includes("/domain/") || url.includes("rdap")) return "RDAP";
    return "HTTP";
  }
  if (entry.type === "scraper") return "Scraper";
  return "?";
}

function sourceColor(source: string) {
  if (source === "manual")   return "bg-violet-100 dark:bg-violet-950/40 text-violet-700 dark:text-violet-400";
  if (source === "repair")   return "bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-400";
  if (source === "iana")     return "bg-sky-100 dark:bg-sky-950/40 text-sky-700 dark:text-sky-400";
  if (source === "registry") return "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400";
  return "bg-muted text-muted-foreground";
}

function sourceLabel(source: string) {
  if (source === "manual")   return "手动";
  if (source === "repair")   return "自动修复";
  if (source === "iana")     return "IANA自动";
  if (source === "registry") return "注册局";
  return source;
}

function parseEntryForEdit(entry: CustomServerEntry): {
  serverType: ServerType;
  whoisHost: string;
  whoisPort: string;
  rdapUrl: string;
  httpUrl: string;
  httpMethod: string;
} {
  if (typeof entry === "string") {
    return { serverType: "whois-tcp", whoisHost: entry, whoisPort: "", rdapUrl: "", httpUrl: "", httpMethod: "GET" };
  }
  if (entry.type === "tcp") {
    return { serverType: "whois-tcp", whoisHost: (entry as TcpServerEntry).host, whoisPort: String((entry as TcpServerEntry).port ?? ""), rdapUrl: "", httpUrl: "", httpMethod: "GET" };
  }
  if (entry.type === "http") {
    const h = entry as HttpServerEntry;
    const isRdap = h.url.includes("/domain/") || h.url.toLowerCase().includes("rdap");
    if (isRdap) {
      const base = h.url.replace(/\/domain\/?$/, "").replace(/\/$/, "");
      return { serverType: "rdap-http", whoisHost: "", whoisPort: "", rdapUrl: base, httpUrl: "", httpMethod: "GET" };
    }
    return { serverType: "http-whois", whoisHost: "", whoisPort: "", rdapUrl: "", httpUrl: h.url, httpMethod: h.method ?? "GET" };
  }
  return { serverType: "whois-tcp", whoisHost: "", whoisPort: "", rdapUrl: "", httpUrl: "", httpMethod: "GET" };
}

function buildEntry(
  serverType: ServerType,
  whoisHost: string,
  whoisPort: string,
  rdapUrl: string,
  httpUrl: string,
  httpMethod: string,
): CustomServerEntry | null {
  if (serverType === "whois-tcp") {
    const h = whoisHost.trim();
    if (!h) return null;
    const p = parseInt(whoisPort.trim(), 10);
    if (whoisPort.trim() && !isNaN(p) && p > 0) {
      return { type: "tcp", host: h, port: p };
    }
    return h;
  }
  if (serverType === "rdap-http") {
    const base = rdapUrl.trim().replace(/\/$/, "");
    if (!base) return null;
    return { type: "http", url: `${base}/domain/`, method: "GET" };
  }
  if (serverType === "http-whois") {
    const u = httpUrl.trim();
    if (!u) return null;
    return { type: "http", url: u, method: (httpMethod as "GET" | "POST") || "GET" };
  }
  return null;
}

export default function AdminTldFallbackPage() {
  const [rows, setRows] = React.useState<FallbackRow[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [actionId, setActionId] = React.useState<string | null>(null);

  // ── DB servers state ──────────────────────────────────────────────────────
  const [dbServers, setDbServers] = React.useState<Record<string, ServerWithSource>>({});
  const [serversLoading, setServersLoading] = React.useState(false);

  // ── Add-TLD form state ────────────────────────────────────────────────────
  const [showAddForm, setShowAddForm] = React.useState(false);
  const [addTldInput, setAddTldInput] = React.useState("");
  const [addFailCount, setAddFailCount] = React.useState("0");
  const [addUseFallback, setAddUseFallback] = React.useState(false);
  const [adding, setAdding] = React.useState(false);

  // ── Inline fail_count edit state ─────────────────────────────────────────
  const [editingTld, setEditingTld] = React.useState<string | null>(null);
  const [editFailCount, setEditFailCount] = React.useState("");

  // ── Server edit dialog state ──────────────────────────────────────────────
  const [serverDialogTld, setServerDialogTld] = React.useState<string | null>(null);
  const [serverDialogIsNew, setServerDialogIsNew] = React.useState(false);
  const [serverType, setServerType] = React.useState<ServerType>("whois-tcp");
  const [whoisHost, setWhoisHost] = React.useState("");
  const [whoisPort, setWhoisPort] = React.useState("");
  const [rdapUrl, setRdapUrl] = React.useState("");
  const [httpUrl, setHttpUrl] = React.useState("");
  const [httpMethod, setHttpMethod] = React.useState("GET");
  const [serverSaving, setServerSaving] = React.useState(false);
  // For the standalone "新增服务器" dialog (not linked to a fallback row)
  const [serverDialogNewTld, setServerDialogNewTld] = React.useState("");
  // ── Server test state ─────────────────────────────────────────────────────
  const [testing, setTesting] = React.useState(false);
  type TestResult = { ok: boolean; method: string; output?: string; statusCode?: number; error?: string; elapsedMs: number };
  const [testResult, setTestResult] = React.useState<TestResult | null>(null);

  // ── Built-in server state ──────────────────────────────────────────────────
  const [builtinData, setBuiltinData] = React.useState<BuiltinServers | null>(null);
  const [builtinLoading, setBuiltinLoading] = React.useState(false);
  const [builtinOpen, setBuiltinOpen] = React.useState<"rdap" | "whois" | null>(null);
  const [rdapSearch, setRdapSearch] = React.useState("");
  const [whoisSearch, setWhoisSearch] = React.useState("");

  function loadBuiltin() {
    setBuiltinLoading(true);
    fetch("/api/admin/builtin-servers")
      .then(r => r.json())
      .then(data => setBuiltinData(data))
      .catch(() => toast.error("加载内置服务器列表失败"))
      .finally(() => setBuiltinLoading(false));
  }

  function load() {
    setLoading(true);
    fetch("/api/admin/tld-fallback")
      .then(r => r.json())
      .then(data => {
        if (data.error) toast.error(data.error);
        else setRows(data.rows || []);
      })
      .catch(() => toast.error("加载失败"))
      .finally(() => setLoading(false));
  }

  function loadServers() {
    setServersLoading(true);
    fetch("/api/admin/tld-servers")
      .then(r => r.json())
      .then(data => {
        if (!data.success) toast.error(data.message || "加载服务器失败");
        else setDbServers(data.dbServers || {});
      })
      .catch(() => toast.error("加载服务器列表失败"))
      .finally(() => setServersLoading(false));
  }

  React.useEffect(() => { load(); loadServers(); }, []);

  function openServerDialog(tld: string, existing?: ServerWithSource) {
    setTestResult(null);
    setServerDialogTld(tld);
    setServerDialogIsNew(!existing);
    setServerDialogNewTld(tld);
    if (existing) {
      const parsed = parseEntryForEdit(existing.entry);
      setServerType(parsed.serverType);
      setWhoisHost(parsed.whoisHost);
      setWhoisPort(parsed.whoisPort);
      setRdapUrl(parsed.rdapUrl);
      setHttpUrl(parsed.httpUrl);
      setHttpMethod(parsed.httpMethod);
    } else {
      setServerType("whois-tcp");
      setWhoisHost("");
      setWhoisPort("");
      setRdapUrl("");
      setHttpUrl("");
      setHttpMethod("GET");
    }
  }

  function openNewServerDialog() {
    setTestResult(null);
    setServerDialogTld("__new__");
    setServerDialogIsNew(true);
    setServerDialogNewTld("");
    setServerType("whois-tcp");
    setWhoisHost("");
    setWhoisPort("");
    setRdapUrl("");
    setHttpUrl("");
    setHttpMethod("GET");
  }

  async function testServer() {
    const rawTld = serverDialogTld === "__new__" ? serverDialogNewTld : serverDialogTld;
    const tld = (rawTld ?? "").trim().toLowerCase().replace(/^\./, "");
    if (!tld) { toast.error("请先输入 TLD"); return; }
    const entry = buildEntry(serverType, whoisHost, whoisPort, rdapUrl, httpUrl, httpMethod);
    if (!entry) { toast.error("请填写完整的服务器信息"); return; }

    setTesting(true);
    setTestResult(null);
    try {
      const res = await fetch("/api/admin/test-server", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, entry }),
      });
      const data = await res.json();
      setTestResult(data);
    } catch (e: any) {
      setTestResult({ ok: false, method: "?", error: e?.message || "请求失败", elapsedMs: 0 });
    } finally {
      setTesting(false);
    }
  }

  async function saveServer() {
    const rawTld = serverDialogTld === "__new__" ? serverDialogNewTld : serverDialogTld;
    const tld = (rawTld ?? "").trim().toLowerCase().replace(/^\./, "");
    if (!tld) { toast.error("请输入 TLD"); return; }

    const entry = buildEntry(serverType, whoisHost, whoisPort, rdapUrl, httpUrl, httpMethod);
    if (!entry) { toast.error("请填写完整的服务器信息"); return; }

    setServerSaving(true);
    try {
      const res = await fetch("/api/admin/tld-servers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, entry }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.message || "保存失败");
      toast.success(`已保存 .${tld} 服务器配置`);
      setDbServers(prev => ({ ...prev, [tld]: { entry, source: "manual" } }));
      setServerDialogTld(null);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setServerSaving(false);
    }
  }

  async function deleteServer(tld: string) {
    if (!confirm(`确认删除 .${tld} 的服务器配置？`)) return;
    setActionId("srv-del-" + tld);
    try {
      const res = await fetch("/api/admin/tld-servers", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.message || "删除失败");
      toast.success(`已删除 .${tld} 服务器配置`);
      setDbServers(prev => {
        const n = { ...prev };
        delete n[tld];
        return n;
      });
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setActionId(null);
    }
  }

  async function addTld() {
    const tld = addTldInput.trim().toLowerCase().replace(/^\./, "");
    if (!tld) { toast.error("请输入 TLD"); return; }
    setAdding(true);
    try {
      const res = await fetch("/api/admin/tld-fallback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, fail_count: Number(addFailCount) || 0, use_fallback: addUseFallback }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "添加失败");
      toast.success(`已添加 .${tld}`);
      if (data.row) {
        setRows(prev => {
          const exists = prev.find(r => r.tld === tld);
          return exists
            ? prev.map(r => r.tld === tld ? data.row : r)
            : [data.row, ...prev];
        });
      }
      setAddTldInput("");
      setAddFailCount("0");
      setAddUseFallback(false);
      setShowAddForm(false);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setAdding(false);
    }
  }

  async function saveFailCount(tld: string) {
    const fc = parseInt(editFailCount, 10);
    if (isNaN(fc) || fc < 0) { toast.error("失败次数必须为非负整数"); return; }
    setActionId(tld + "-fc");
    try {
      const res = await fetch("/api/admin/tld-fallback", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, fail_count: fc }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "保存失败");
      const uf = fc >= 3;
      setRows(prev => prev.map(r => r.tld === tld ? { ...r, fail_count: fc, use_fallback: uf } : r));
      toast.success(`已更新 .${tld} 失败次数为 ${fc}`);
      setEditingTld(null);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setActionId(null);
    }
  }

  async function toggleFallback(tld: string, current: boolean) {
    setActionId(tld + "-toggle");
    try {
      const res = await fetch("/api/admin/tld-fallback", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, use_fallback: !current }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "操作失败");
      toast.success(`已${!current ? "启用" : "关闭"} .${tld} 兜底`);
      setRows(prev => prev.map(r => r.tld === tld ? { ...r, use_fallback: !current } : r));
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setActionId(null);
    }
  }

  async function deleteTld(tld: string) {
    if (!confirm(`确认清除 .${tld} 的兜底记录？`)) return;
    setActionId(tld + "-del");
    try {
      const res = await fetch("/api/admin/tld-fallback", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "删除失败");
      toast.success(`已清除 .${tld}`);
      setRows(prev => prev.filter(r => r.tld !== tld));
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setActionId(null);
    }
  }

  async function clearAll() {
    if (!confirm("确认清空全部 TLD 兜底记录？")) return;
    setActionId("clear-all");
    try {
      const res = await fetch("/api/admin/tld-fallback", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "清空失败");
      toast.success("已清空全部记录");
      setRows([]);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setActionId(null);
    }
  }

  const enabledCount = rows.filter(r => r.use_fallback).length;
  const dbServerEntries = Object.entries(dbServers).sort(([a], [b]) => a.localeCompare(b));
  const manualCount = dbServerEntries.filter(([, v]) => v.source === "manual").length;

  return (
    <AdminLayout title="TLD 管理">
      <div className="space-y-5">
        <PageTabs tabs={TLD_TABS} />

        {/* ── Header ── */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h2 className="text-lg font-bold">TLD 兜底查询统计</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              追踪各 TLD 原生 WHOIS/RDAP 失败次数，失败 ≥3 次自动启用第三方备用查询
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm"
              onClick={() => setShowAddForm(v => !v)}
              className="gap-1.5">
              <RiAddLine className="w-4 h-4" />手动添加
            </Button>
            <Button variant="outline" size="sm" onClick={() => { load(); loadServers(); }} disabled={loading}>
              <RiRefreshLine className={cn("w-4 h-4 mr-1.5", loading && "animate-spin")} />
              刷新
            </Button>
            {rows.length > 0 && (
              <Button variant="outline" size="sm" onClick={clearAll}
                disabled={actionId === "clear-all"}
                className="text-destructive border-destructive/30 hover:bg-destructive/10">
                {actionId === "clear-all"
                  ? <RiLoader4Line className="w-4 h-4 mr-1.5 animate-spin" />
                  : <RiDeleteBinLine className="w-4 h-4 mr-1.5" />}
                清空全部
              </Button>
            )}
          </div>
        </div>

        {/* ── Add TLD form ── */}
        {showAddForm && (
          <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <RiAddLine className="w-4 h-4 text-violet-500" />
              手动添加 / 覆盖 TLD 兜底记录
            </h3>
            <div className="flex flex-wrap gap-3 items-end">
              <div className="flex-1 min-w-[120px]">
                <label className="text-xs text-muted-foreground mb-1 block">TLD（不含点）</label>
                <Input
                  value={addTldInput}
                  onChange={e => setAddTldInput(e.target.value)}
                  placeholder="例如 bf 或 bn"
                  className="h-8 text-sm font-mono"
                  onKeyDown={e => e.key === "Enter" && addTld()}
                />
              </div>
              <div className="w-28">
                <label className="text-xs text-muted-foreground mb-1 block">失败次数</label>
                <Input
                  type="number" min="0"
                  value={addFailCount}
                  onChange={e => setAddFailCount(e.target.value)}
                  className="h-8 text-sm"
                />
              </div>
              <div className="flex items-center gap-2 pb-1">
                <input
                  type="checkbox"
                  id="add-use-fallback"
                  checked={addUseFallback}
                  onChange={e => setAddUseFallback(e.target.checked)}
                  className="w-4 h-4"
                />
                <label htmlFor="add-use-fallback" className="text-sm cursor-pointer">立即启用兜底</label>
              </div>
              <Button size="sm" onClick={addTld} disabled={adding} className="gap-1.5">
                {adding ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiSaveLine className="w-4 h-4" />}
                提交
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setShowAddForm(false)}>
                <RiCloseLine className="w-4 h-4" />
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              若该 TLD 已有记录则覆盖更新。失败次数 ≥3 时会自动勾选启用兜底。
            </p>
          </div>
        )}

        {/* ── Stats cards ── */}
        <div className="grid grid-cols-3 gap-3">
          <div className="glass-panel border border-border rounded-2xl p-4 text-center">
            <p className="text-2xl font-bold">{rows.length}</p>
            <p className="text-xs text-muted-foreground mt-1">已追踪 TLD</p>
          </div>
          <div className="glass-panel border border-border rounded-2xl p-4 text-center">
            <p className="text-2xl font-bold text-amber-500">{enabledCount}</p>
            <p className="text-xs text-muted-foreground mt-1">已启用兜底</p>
          </div>
          <div className="glass-panel border border-border rounded-2xl p-4 text-center">
            <p className="text-2xl font-bold text-muted-foreground">{rows.length - enabledCount}</p>
            <p className="text-xs text-muted-foreground mt-1">观察中</p>
          </div>
        </div>

        {/* ── Fallback Table ── */}
        {loading && rows.length === 0 ? (
          <div className="flex items-center justify-center py-16">
            <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : rows.length === 0 ? (
          <div className="glass-panel border border-border rounded-2xl p-10 text-center">
            <RiServerLine className="w-8 h-8 text-muted-foreground/40 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">暂无记录，查询失败时自动生成统计，或点击"手动添加"</p>
          </div>
        ) : (
          <div className="glass-panel border border-border rounded-2xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  <th className="text-left px-4 py-3 font-medium text-muted-foreground text-xs">TLD</th>
                  <th className="text-center px-3 py-3 font-medium text-muted-foreground text-xs">失败次数</th>
                  <th className="text-center px-3 py-3 font-medium text-muted-foreground text-xs">状态</th>
                  <th className="text-left px-3 py-3 font-medium text-muted-foreground text-xs hidden sm:table-cell">服务器</th>
                  <th className="text-left px-3 py-3 font-medium text-muted-foreground text-xs">最后失败</th>
                  <th className="text-right px-4 py-3 font-medium text-muted-foreground text-xs">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map(row => {
                  const isEditingThis = editingTld === row.tld;
                  const srvEntry = dbServers[row.tld];
                  return (
                    <tr key={row.tld} className="hover:bg-muted/20 transition-colors">
                      <td className="px-4 py-3 font-mono font-semibold">.{row.tld}</td>

                      {/* ── Fail count cell ── */}
                      <td className="px-3 py-3 text-center">
                        {isEditingThis ? (
                          <div className="flex items-center justify-center gap-1">
                            <Input
                              type="number" min="0"
                              value={editFailCount}
                              onChange={e => setEditFailCount(e.target.value)}
                              className="h-6 w-16 text-xs text-center px-1"
                              onKeyDown={e => {
                                if (e.key === "Enter") saveFailCount(row.tld);
                                if (e.key === "Escape") setEditingTld(null);
                              }}
                              autoFocus
                            />
                            <Button variant="ghost" size="icon" className="h-6 w-6"
                              title="保存"
                              disabled={actionId === row.tld + "-fc"}
                              onClick={() => saveFailCount(row.tld)}>
                              {actionId === row.tld + "-fc"
                                ? <RiLoader4Line className="w-3 h-3 animate-spin" />
                                : <RiSaveLine className="w-3 h-3 text-green-600" />}
                            </Button>
                            <Button variant="ghost" size="icon" className="h-6 w-6"
                              title="取消" onClick={() => setEditingTld(null)}>
                              <RiCloseLine className="w-3 h-3" />
                            </Button>
                          </div>
                        ) : (
                          <div className="flex items-center justify-center gap-1 group">
                            <span className={cn(
                              "inline-flex items-center justify-center w-7 h-7 rounded-full text-xs font-bold",
                              row.fail_count >= 3
                                ? "bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400"
                                : row.fail_count >= 1
                                ? "bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400"
                                : "bg-muted text-muted-foreground",
                            )}>
                              {row.fail_count}
                            </span>
                            <Button variant="ghost" size="icon"
                              className="h-5 w-5 opacity-0 group-hover:opacity-100 transition-opacity"
                              title="编辑失败次数"
                              onClick={() => { setEditingTld(row.tld); setEditFailCount(String(row.fail_count)); }}>
                              <RiPencilLine className="w-3 h-3" />
                            </Button>
                          </div>
                        )}
                      </td>

                      <td className="px-3 py-3 text-center">
                        {row.use_fallback ? (
                          <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 font-semibold">
                            <RiAlertLine className="w-3 h-3" />兜底中
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 font-semibold">
                            <RiCheckLine className="w-3 h-3" />正常
                          </span>
                        )}
                      </td>

                      {/* ── Server column ── */}
                      <td className="px-3 py-3 hidden sm:table-cell">
                        {srvEntry ? (
                          <button
                            className="flex items-center gap-1.5 group text-left"
                            onClick={() => openServerDialog(row.tld, srvEntry)}
                            title="点击编辑服务器"
                          >
                            <span className={cn(
                              "text-[10px] px-1.5 py-0.5 rounded font-semibold shrink-0",
                              entryType(srvEntry.entry) === "RDAP"
                                ? "bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-400"
                                : "bg-green-100 dark:bg-green-950/40 text-green-700 dark:text-green-400",
                            )}>
                              {entryType(srvEntry.entry)}
                            </span>
                            <span className="text-xs text-muted-foreground font-mono truncate max-w-[140px] group-hover:text-foreground transition-colors">
                              {entryLabel(srvEntry.entry)}
                            </span>
                          </button>
                        ) : (
                          <button
                            className="text-[11px] text-muted-foreground/60 hover:text-violet-500 flex items-center gap-1 transition-colors"
                            onClick={() => openServerDialog(row.tld)}
                          >
                            <RiAddLine className="w-3 h-3" />配置服务器
                          </button>
                        )}
                      </td>

                      <td className="px-3 py-3 text-xs text-muted-foreground">{fmt(row.last_fail_at)}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-1.5">
                          <Button
                            variant="ghost" size="icon"
                            className="w-7 h-7 sm:hidden"
                            title="配置服务器"
                            onClick={() => openServerDialog(row.tld, srvEntry)}
                          >
                            <RiSettings3Line className="w-3.5 h-3.5 text-muted-foreground" />
                          </Button>
                          <Button
                            variant="ghost" size="icon"
                            className="w-7 h-7"
                            title={row.use_fallback ? "关闭兜底" : "启用兜底"}
                            disabled={actionId === row.tld + "-toggle"}
                            onClick={() => toggleFallback(row.tld, row.use_fallback)}
                          >
                            {actionId === row.tld + "-toggle"
                              ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                              : <RiToggleLine className="w-3.5 h-3.5" />}
                          </Button>
                          <Button
                            variant="ghost" size="icon"
                            className="w-7 h-7 text-destructive hover:text-destructive"
                            title="清除记录"
                            disabled={actionId === row.tld + "-del"}
                            onClick={() => deleteTld(row.tld)}
                          >
                            {actionId === row.tld + "-del"
                              ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                              : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            WHOIS / RDAP Server Management Section
        ══════════════════════════════════════════════════════════════════════ */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold flex items-center gap-2">
                <RiServerLine className="w-5 h-5 text-violet-500" />
                自定义服务器配置
              </h2>
              <p className="text-xs text-muted-foreground mt-0.5">
                手动配置各 TLD 的 WHOIS / RDAP 服务器地址，优先级高于内置配置
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={loadServers} disabled={serversLoading}>
                <RiRefreshLine className={cn("w-4 h-4 mr-1.5", serversLoading && "animate-spin")} />
                刷新
              </Button>
              <Button size="sm" onClick={openNewServerDialog} className="gap-1.5">
                <RiAddLine className="w-4 h-4" />新增服务器
              </Button>
            </div>
          </div>

          {/* Stats */}
          <div className="flex items-center gap-4 px-1">
            <span className="text-xs text-muted-foreground">
              共 <span className="font-semibold text-foreground">{dbServerEntries.length}</span> 条配置
              · 手动 <span className="font-semibold text-violet-600">{manualCount}</span>
              · 自动发现 <span className="font-semibold text-blue-600">{dbServerEntries.length - manualCount}</span>
            </span>
          </div>

          {serversLoading && dbServerEntries.length === 0 ? (
            <div className="flex items-center justify-center py-10">
              <RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" />
            </div>
          ) : dbServerEntries.length === 0 ? (
            <div className="glass-panel border border-border rounded-2xl p-10 text-center">
              <RiWifiLine className="w-8 h-8 text-muted-foreground/40 mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">暂无自定义服务器，点击"新增服务器"添加</p>
            </div>
          ) : (
            <div className="glass-panel border border-border rounded-2xl overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/30">
                    <th className="text-left px-4 py-3 font-medium text-muted-foreground text-xs">TLD</th>
                    <th className="text-left px-3 py-3 font-medium text-muted-foreground text-xs">类型</th>
                    <th className="text-left px-3 py-3 font-medium text-muted-foreground text-xs">服务器 / URL</th>
                    <th className="text-center px-3 py-3 font-medium text-muted-foreground text-xs">来源</th>
                    <th className="text-right px-4 py-3 font-medium text-muted-foreground text-xs">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {dbServerEntries.map(([tld, srv]) => (
                    <tr key={tld} className="hover:bg-muted/20 transition-colors">
                      <td className="px-4 py-3 font-mono font-semibold">.{tld}</td>
                      <td className="px-3 py-3">
                        <span className={cn(
                          "text-[10px] px-1.5 py-0.5 rounded font-semibold",
                          entryType(srv.entry) === "RDAP"
                            ? "bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-400"
                            : entryType(srv.entry) === "WHOIS"
                            ? "bg-green-100 dark:bg-green-950/40 text-green-700 dark:text-green-400"
                            : "bg-muted text-muted-foreground",
                        )}>
                          {entryType(srv.entry)}
                        </span>
                      </td>
                      <td className="px-3 py-3 font-mono text-xs text-muted-foreground max-w-[240px] truncate">
                        {entryLabel(srv.entry)}
                      </td>
                      <td className="px-3 py-3 text-center">
                        <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-semibold", sourceColor(srv.source))}>
                          {sourceLabel(srv.source)}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-1.5">
                          <Button
                            variant="ghost" size="icon" className="w-7 h-7"
                            title="编辑"
                            onClick={() => openServerDialog(tld, srv)}
                          >
                            <RiPencilLine className="w-3.5 h-3.5" />
                          </Button>
                          <Button
                            variant="ghost" size="icon" className="w-7 h-7 text-destructive hover:text-destructive"
                            title="删除"
                            disabled={actionId === "srv-del-" + tld}
                            onClick={() => deleteServer(tld)}
                          >
                            {actionId === "srv-del-" + tld
                              ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                              : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* ══════════════════════════════════════════════════════════════════
            Built-in Server Lists (RDAP + WHOIS)
        ══════════════════════════════════════════════════════════════════ */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold flex items-center gap-2">
                <RiDatabase2Line className="w-5 h-5 text-sky-500" />
                内置服务器列表
              </h2>
              <p className="text-xs text-muted-foreground mt-0.5">
                程序内置的 RDAP / WHOIS 服务器表（只读参考，自定义配置优先级更高）
              </p>
            </div>
            <Button
              variant="outline" size="sm"
              onClick={() => { if (!builtinData) loadBuiltin(); setBuiltinOpen(builtinOpen ? null : "rdap"); }}
              disabled={builtinLoading}
              className="gap-1.5"
            >
              {builtinLoading
                ? <RiLoader4Line className="w-4 h-4 animate-spin" />
                : builtinOpen
                  ? <RiArrowUpSLine className="w-4 h-4" />
                  : <RiArrowDownSLine className="w-4 h-4" />}
              {builtinOpen ? "收起" : "展开查看"}
            </Button>
          </div>

          {builtinOpen && builtinData && (
            <div className="space-y-4">
              {/* Sub-tabs */}
              <div className="flex gap-2">
                <button
                  onClick={() => setBuiltinOpen("rdap")}
                  className={cn(
                    "px-3 py-1.5 text-sm rounded-lg font-medium transition-colors",
                    builtinOpen === "rdap"
                      ? "bg-sky-100 dark:bg-sky-950/50 text-sky-700 dark:text-sky-400"
                      : "text-muted-foreground hover:text-foreground hover:bg-muted/50",
                  )}
                >
                  RDAP 服务器
                  <span className="ml-1.5 text-xs font-normal opacity-70">({builtinData.rdapTotal})</span>
                </button>
                <button
                  onClick={() => setBuiltinOpen("whois")}
                  className={cn(
                    "px-3 py-1.5 text-sm rounded-lg font-medium transition-colors",
                    builtinOpen === "whois"
                      ? "bg-emerald-100 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-400"
                      : "text-muted-foreground hover:text-foreground hover:bg-muted/50",
                  )}
                >
                  WHOIS 服务器
                  <span className="ml-1.5 text-xs font-normal opacity-70">({builtinData.whoisTotal})</span>
                </button>
              </div>

              {/* ── RDAP tab ── */}
              {builtinOpen === "rdap" && (() => {
                const entries = Object.entries(builtinData.rdap)
                  .filter(([tld, e]) =>
                    !rdapSearch ||
                    tld.includes(rdapSearch.toLowerCase().replace(/^\./, "")) ||
                    e.url.toLowerCase().includes(rdapSearch.toLowerCase()),
                  )
                  .sort(([a], [b]) => a.localeCompare(b));
                return (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Input
                        value={rdapSearch}
                        onChange={e => setRdapSearch(e.target.value)}
                        placeholder="搜索 TLD 或 URL…"
                        className="h-8 text-sm max-w-xs"
                      />
                      <span className="text-xs text-muted-foreground">
                        共 {entries.length} 条
                      </span>
                    </div>
                    <div className="glass-panel border border-border rounded-2xl overflow-hidden max-h-[480px] overflow-y-auto">
                      <table className="w-full text-sm">
                        <thead className="sticky top-0 z-10 bg-background border-b border-border">
                          <tr className="bg-muted/30">
                            <th className="text-left px-4 py-2.5 font-medium text-muted-foreground text-xs">TLD</th>
                            <th className="text-left px-3 py-2.5 font-medium text-muted-foreground text-xs">来源</th>
                            <th className="text-left px-3 py-2.5 font-medium text-muted-foreground text-xs">RDAP 服务器</th>
                            <th className="text-right px-4 py-2.5 font-medium text-muted-foreground text-xs">覆盖</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {entries.map(([tld, e]) => (
                            <tr key={tld} className="hover:bg-muted/20 transition-colors">
                              <td className="px-4 py-2 font-mono font-semibold text-sm">.{tld}</td>
                              <td className="px-3 py-2">
                                <span className={cn(
                                  "text-[10px] px-1.5 py-0.5 rounded font-semibold",
                                  e.source === "cctld-override"
                                    ? "bg-violet-100 dark:bg-violet-950/40 text-violet-700 dark:text-violet-400"
                                    : "bg-sky-100 dark:bg-sky-950/40 text-sky-700 dark:text-sky-400",
                                )}>
                                  {e.source === "cctld-override" ? "ccTLD手工" : "IANA自动"}
                                </span>
                              </td>
                              <td className="px-3 py-2 font-mono text-xs text-muted-foreground max-w-[300px] truncate">
                                {e.url}
                              </td>
                              <td className="px-4 py-2 text-right">
                                {dbServers[tld] ? (
                                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 font-semibold">
                                    已覆盖
                                  </span>
                                ) : null}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                );
              })()}

              {/* ── WHOIS tab ── */}
              {builtinOpen === "whois" && (() => {
                const entries = Object.entries(builtinData.whois)
                  .filter(([tld, srv]) =>
                    !whoisSearch ||
                    tld.includes(whoisSearch.toLowerCase().replace(/^\./, "")) ||
                    (srv && srv.toLowerCase().includes(whoisSearch.toLowerCase())),
                  )
                  .sort(([a], [b]) => a.localeCompare(b));
                return (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Input
                        value={whoisSearch}
                        onChange={e => setWhoisSearch(e.target.value)}
                        placeholder="搜索 TLD 或服务器…"
                        className="h-8 text-sm max-w-xs"
                      />
                      <span className="text-xs text-muted-foreground">
                        共 {entries.length} 条
                        · 无服务器 <span className="text-amber-500">{entries.filter(([, v]) => !v).length}</span>
                      </span>
                    </div>
                    <div className="glass-panel border border-border rounded-2xl overflow-hidden max-h-[480px] overflow-y-auto">
                      <table className="w-full text-sm">
                        <thead className="sticky top-0 z-10 bg-background border-b border-border">
                          <tr className="bg-muted/30">
                            <th className="text-left px-4 py-2.5 font-medium text-muted-foreground text-xs">TLD</th>
                            <th className="text-left px-3 py-2.5 font-medium text-muted-foreground text-xs">WHOIS 服务器</th>
                            <th className="text-right px-4 py-2.5 font-medium text-muted-foreground text-xs">覆盖</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {entries.map(([tld, srv]) => (
                            <tr key={tld} className={cn("hover:bg-muted/20 transition-colors", !srv && "opacity-60")}>
                              <td className="px-4 py-2 font-mono font-semibold text-sm">.{tld}</td>
                              <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                                {srv ?? (
                                  <span className="text-amber-500/80 text-[11px]">— 无服务器</span>
                                )}
                              </td>
                              <td className="px-4 py-2 text-right">
                                {dbServers[tld] ? (
                                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 font-semibold">
                                    已覆盖
                                  </span>
                                ) : null}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                );
              })()}
            </div>
          )}
        </div>
      </div>

      {/* ══════════════════════════════════════════════════════════════════════
          Server Edit / Add Dialog
      ══════════════════════════════════════════════════════════════════════ */}
      <Dialog open={serverDialogTld !== null} onOpenChange={open => { if (!open) setServerDialogTld(null); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <RiServerLine className="w-4 h-4 text-violet-500" />
              {serverDialogTld === "__new__" ? "新增服务器配置" : `编辑 .${serverDialogTld} 服务器`}
            </DialogTitle>
            <DialogDescription>
              配置该 TLD 的 WHOIS 或 RDAP 服务器，保存后立即生效
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            {/* TLD input for new entries */}
            {serverDialogTld === "__new__" && (
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground">TLD（不含点）</label>
                <Input
                  value={serverDialogNewTld}
                  onChange={e => setServerDialogNewTld(e.target.value.toLowerCase().replace(/^\./, ""))}
                  placeholder="例如 cc 或 com.au"
                  className="font-mono"
                />
              </div>
            )}

            {/* Server type */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">服务器类型</label>
              <Select value={serverType} onValueChange={v => setServerType(v as ServerType)}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="whois-tcp">
                    <span className="flex items-center gap-2">
                      <RiGlobalLine className="w-3.5 h-3.5 text-green-600" />
                      WHOIS TCP 服务器
                    </span>
                  </SelectItem>
                  <SelectItem value="rdap-http">
                    <span className="flex items-center gap-2">
                      <RiWifiLine className="w-3.5 h-3.5 text-blue-600" />
                      RDAP HTTP 接口
                    </span>
                  </SelectItem>
                  <SelectItem value="http-whois">
                    <span className="flex items-center gap-2">
                      <RiGlobalLine className="w-3.5 h-3.5 text-amber-600" />
                      自定义 HTTP WHOIS
                    </span>
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* WHOIS TCP fields */}
            {serverType === "whois-tcp" && (
              <div className="space-y-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground">WHOIS 主机名</label>
                  <Input
                    value={whoisHost}
                    onChange={e => setWhoisHost(e.target.value)}
                    placeholder="whois.example.tld"
                    className="font-mono"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground">端口（可选，默认 43）</label>
                  <Input
                    type="number" min="1" max="65535"
                    value={whoisPort}
                    onChange={e => setWhoisPort(e.target.value)}
                    placeholder="43"
                    className="font-mono w-28"
                  />
                </div>
              </div>
            )}

            {/* RDAP HTTP fields */}
            {serverType === "rdap-http" && (
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground">RDAP 基础 URL</label>
                <Input
                  value={rdapUrl}
                  onChange={e => setRdapUrl(e.target.value)}
                  placeholder="https://rdap.example.tld"
                  className="font-mono"
                />
                <p className="text-[11px] text-muted-foreground">
                  自动补全为 <code className="bg-muted px-1 rounded">{rdapUrl.trim().replace(/\/$/, "") || "https://rdap.example.tld"}/domain/</code>
                </p>
              </div>
            )}

            {/* Custom HTTP WHOIS fields */}
            {serverType === "http-whois" && (
              <div className="space-y-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground">请求 URL</label>
                  <Input
                    value={httpUrl}
                    onChange={e => setHttpUrl(e.target.value)}
                    placeholder="https://api.example.tld/whois"
                    className="font-mono"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground">HTTP 方法</label>
                  <Select value={httpMethod} onValueChange={setHttpMethod}>
                    <SelectTrigger className="w-28">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="GET">GET</SelectItem>
                      <SelectItem value="POST">POST</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            )}
          </div>

          {/* ── Test result panel ──────────────────────────────────────────── */}
          {testResult && (
            <div className={cn(
              "rounded-lg border text-[12px] overflow-hidden",
              testResult.ok ? "border-green-200 bg-green-50 dark:border-green-900 dark:bg-green-950/30" : "border-red-200 bg-red-50 dark:border-red-900 dark:bg-red-950/30",
            )}>
              {/* header */}
              <div className={cn(
                "flex items-center gap-2 px-3 py-2 border-b font-medium",
                testResult.ok ? "border-green-200 text-green-800 dark:border-green-900 dark:text-green-300" : "border-red-200 text-red-800 dark:border-red-900 dark:text-red-300",
              )}>
                {testResult.ok
                  ? <RiCheckboxCircleLine className="w-4 h-4 flex-shrink-0" />
                  : <RiCloseCircleLine className="w-4 h-4 flex-shrink-0" />}
                <span>{testResult.ok ? "连接成功" : "连接失败"}</span>
                <span className="text-muted-foreground font-normal ml-auto flex items-center gap-1">
                  <RiTimeLine className="w-3 h-3" />{testResult.elapsedMs}ms
                </span>
                {testResult.statusCode && (
                  <span className={cn("font-mono px-1.5 py-0.5 rounded text-[11px]",
                    testResult.ok ? "bg-green-200/60 dark:bg-green-900/40" : "bg-red-200/60 dark:bg-red-900/40",
                  )}>HTTP {testResult.statusCode}</span>
                )}
              </div>
              {/* body */}
              <div className="px-3 py-2">
                {testResult.error && !testResult.ok && (
                  <p className="text-red-700 dark:text-red-400 mb-1">{testResult.error}</p>
                )}
                {testResult.output && (
                  <pre className="font-mono text-[11px] whitespace-pre-wrap break-all text-foreground/80 max-h-40 overflow-y-auto leading-relaxed">{testResult.output}</pre>
                )}
              </div>
            </div>
          )}

          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setServerDialogTld(null)}>取消</Button>
            <Button
              variant="outline"
              onClick={testServer}
              disabled={testing || serverSaving}
              className={cn("gap-1.5", testResult?.ok && "border-green-500 text-green-700 dark:text-green-400")}
            >
              {testing
                ? <RiLoader4Line className="w-4 h-4 animate-spin" />
                : testResult?.ok
                  ? <RiCheckboxCircleLine className="w-4 h-4" />
                  : <RiFlaskLine className="w-4 h-4" />}
              {testing ? "测试中…" : testResult?.ok ? "测试通过" : "测试连接"}
            </Button>
            <Button onClick={saveServer} disabled={serverSaving || testing} className="gap-1.5">
              {serverSaving
                ? <RiLoader4Line className="w-4 h-4 animate-spin" />
                : <RiSaveLine className="w-4 h-4" />}
              确认保存
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </AdminLayout>
  );
}
