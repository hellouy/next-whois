import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import {
  RiAddLine,
  RiCloseLine,
  RiCheckLine,
  RiDeleteBinLine,
  RiEditLine,
  RiGlobalLine,
  RiLoader4Line,
  RiRefreshLine,
  RiSearchLine,
  RiServerLine,
} from "@remixicon/react";
import type { CustomServerEntry } from "@/lib/whois/custom-servers";

type Protocol = "tcp" | "http";

interface ServerRow {
  tld: string;
  entry: CustomServerEntry;
  source: "user" | "builtin" | "registry";
}

function getProtocol(entry: CustomServerEntry): Protocol {
  if (typeof entry === "object" && (entry.type === "http" || entry.type === "scraper")) return "http";
  return "tcp";
}

function getDisplayHost(entry: CustomServerEntry): string {
  if (typeof entry === "string") return entry;
  if (entry.type === "tcp") return entry.host + (entry.port && entry.port !== 43 ? `:${entry.port}` : "");
  if (entry.type === "scraper") return entry.registryUrl;
  return entry.url;
}

function ProtocolBadge({ protocol }: { protocol: Protocol }) {
  if (protocol === "http") {
    return (
      <Badge className="text-[9px] bg-blue-500/10 text-blue-500 dark:text-blue-400 hover:bg-blue-500/20 border-0 shrink-0">HTTP</Badge>
    );
  }
  return (
    <Badge className="text-[9px] bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/20 border-0 shrink-0">TCP 43</Badge>
  );
}

function SourceBadge({ source }: { source: ServerRow["source"] }) {
  if (source === "user") return <Badge variant="outline" className="text-[9px] shrink-0">自定义</Badge>;
  if (source === "builtin") return <Badge variant="outline" className="text-[9px] text-muted-foreground shrink-0">内置</Badge>;
  return <Badge variant="outline" className="text-[9px] text-muted-foreground shrink-0">注册局</Badge>;
}

function AddEditForm({
  initial,
  onSave,
  onCancel,
}: {
  initial?: { tld: string; entry: CustomServerEntry };
  onSave: (tld: string, entry: CustomServerEntry) => Promise<void>;
  onCancel: () => void;
}) {
  const [tld, setTld] = React.useState(initial?.tld ?? "");
  const [protocol, setProtocol] = React.useState<Protocol>(() =>
    initial ? getProtocol(initial.entry) : "tcp",
  );
  const [host, setHost] = React.useState(() => {
    if (!initial) return "";
    const e = initial.entry;
    if (typeof e === "string") return e;
    if (e.type === "tcp") return e.host;
    return "";
  });
  const [port, setPort] = React.useState(() => {
    if (!initial) return "";
    const e = initial.entry;
    if (typeof e === "object" && e.type === "tcp" && e.port) return String(e.port);
    return "";
  });
  const [url, setUrl] = React.useState(() => {
    if (!initial) return "";
    const e = initial.entry;
    if (typeof e === "object" && e.type === "http") return e.url;
    return "";
  });
  const [httpMethod, setHttpMethod] = React.useState<"GET" | "POST">(() => {
    if (!initial) return "GET";
    const e = initial.entry;
    if (typeof e === "object" && e.type === "http") return e.method ?? "GET";
    return "GET";
  });
  const [saving, setSaving] = React.useState(false);

  const buildEntry = (): CustomServerEntry | null => {
    if (protocol === "tcp") {
      if (!host.trim()) return null;
      const p = parseInt(port);
      if (port && (isNaN(p) || p < 1 || p > 65535)) return null;
      if (!port || p === 43) return host.trim();
      return { type: "tcp", host: host.trim(), port: p };
    }
    if (!url.trim()) return null;
    return { type: "http", url: url.trim(), method: httpMethod };
  };

  const isValid = (() => {
    const normalizedTldCheck = tld.trim().toLowerCase().replace(/^\./, "");
    if (!normalizedTldCheck) return false;
    if (protocol === "tcp") return !!host.trim();
    return !!url.trim();
  })();

  const handleSave = async () => {
    const normalizedTld = tld.trim().toLowerCase().replace(/^\./, "");
    if (!normalizedTld) return;
    const entry = buildEntry();
    if (!entry) return;
    setSaving(true);
    try {
      await onSave(normalizedTld, entry);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4 p-4 rounded-xl border border-border/60 bg-muted/20">
      <div className="space-y-1.5">
        <label className="text-xs font-medium text-muted-foreground">TLD / 域名后缀</label>
        <div className="flex items-center gap-1.5">
          <span className="text-sm text-muted-foreground">.</span>
          <Input placeholder="com, com.br, co.uk ..." value={tld} onChange={(e) => setTld(e.target.value)}
            disabled={!!initial} className="h-8 text-sm font-mono" />
        </div>
      </div>
      <div className="space-y-1.5">
        <label className="text-xs font-medium text-muted-foreground">协议类型</label>
        <div className="flex gap-2">
          {(["tcp", "http"] as Protocol[]).map((p) => (
            <button key={p} onClick={() => setProtocol(p)}
              className={[
                "flex items-center gap-1.5 px-3 py-1.5 rounded-md border text-xs font-medium transition-colors",
                protocol === p
                  ? p === "tcp"
                    ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                    : "border-blue-500/50 bg-blue-500/10 text-blue-500 dark:text-blue-400"
                  : "border-border text-muted-foreground hover:text-foreground",
              ].join(" ")}
            >
              {p === "tcp" ? <RiServerLine className="w-3.5 h-3.5" /> : <RiGlobalLine className="w-3.5 h-3.5" />}
              {p === "tcp" ? "TCP 43" : "HTTP"}
            </button>
          ))}
        </div>
      </div>
      {protocol === "tcp" && (
        <div className="grid grid-cols-3 gap-2">
          <div className="col-span-2 space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">WHOIS 服务器主机</label>
            <Input placeholder="whois.example.com" value={host} onChange={(e) => setHost(e.target.value)}
              className="h-8 text-sm font-mono" />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">端口 (默认 43)</label>
            <Input placeholder="43" value={port} onChange={(e) => setPort(e.target.value)}
              className="h-8 text-sm font-mono" type="number" min={1} max={65535} />
          </div>
        </div>
      )}
      {protocol === "http" && (
        <div className="space-y-3">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">
              请求地址模板，用 <code className="bg-muted px-1 py-0.5 rounded text-[10px]">{"{{domain}}"}</code> 表示域名
            </label>
            <Input placeholder="https://whois.example.com/query?domain={{domain}}" value={url}
              onChange={(e) => setUrl(e.target.value)} className="h-8 text-sm font-mono" />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">HTTP 方法</label>
            <div className="flex gap-2">
              {(["GET", "POST"] as const).map((m) => (
                <button key={m} onClick={() => setHttpMethod(m)}
                  className={[
                    "px-3 py-1 rounded-md border text-xs font-mono transition-colors",
                    httpMethod === m
                      ? "border-primary/50 bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:text-foreground",
                  ].join(" ")}
                >
                  {m}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
      <div className="flex gap-2 pt-1">
        <Button size="sm" onClick={handleSave} disabled={!isValid || saving} className="h-7 text-xs">
          <RiCheckLine className="w-3.5 h-3.5 mr-1" />
          {saving ? "保存中..." : "保存"}
        </Button>
        <Button size="sm" variant="ghost" onClick={onCancel} className="h-7 text-xs">
          <RiCloseLine className="w-3.5 h-3.5 mr-1" />取消
        </Button>
      </div>
    </div>
  );
}

export default function AdminWhoisServersPage() {
  const [rows, setRows] = React.useState<ServerRow[]>([]);
  const [userTlds, setUserTlds] = React.useState<Set<string>>(new Set());
  const [loading, setLoading] = React.useState(false);
  const [search, setSearch] = React.useState("");
  const [showAdd, setShowAdd] = React.useState(false);
  const [editingTld, setEditingTld] = React.useState<string | null>(null);
  const [deleting, setDeleting] = React.useState<string | null>(null);
  const BUILTIN_TLDS = new Set(["bn", "gw"]);

  const fetchServers = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/whois-servers");
      const d = await res.json();
      if (!d.success) return;
      const userKeys = new Set<string>(Object.keys(d.userServers ?? {}));
      setUserTlds(userKeys);
      const list: ServerRow[] = Object.entries(
        d.servers as Record<string, CustomServerEntry>,
      ).map(([tld, entry]) => ({
        tld,
        entry,
        source: userKeys.has(tld) ? "user" : BUILTIN_TLDS.has(tld) ? "builtin" : "registry",
      }));
      list.sort((a, b) => {
        const order = { user: 0, builtin: 1, registry: 2 };
        if (order[a.source] !== order[b.source]) return order[a.source] - order[b.source];
        return a.tld.localeCompare(b.tld);
      });
      setRows(list);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    fetchServers();
  }, [fetchServers]);

  const filtered = rows.filter(
    (r) => r.tld.includes(search.toLowerCase()) || getDisplayHost(r.entry).toLowerCase().includes(search.toLowerCase()),
  );

  const handleSave = async (tld: string, entry: CustomServerEntry) => {
    const res = await fetch("/api/whois-servers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tld, entry }),
    });
    const d = await res.json();
    if (d.success) {
      toast.success(d.message || `已保存 .${tld}`);
      setShowAdd(false);
      setEditingTld(null);
      await fetchServers();
    } else {
      toast.error(d.message || "保存失败");
    }
  };

  const handleDelete = async (tld: string) => {
    setDeleting(tld);
    try {
      const res = await fetch(`/api/whois-servers?tld=${encodeURIComponent(tld)}`, { method: "DELETE" });
      const d = await res.json();
      if (d.success) { toast.success(d.message || `已删除 .${tld}`); await fetchServers(); }
      else toast.error(d.message || "删除失败");
    } finally {
      setDeleting(null);
    }
  };

  const userCount = userTlds.size;
  const builtinCount = rows.filter((r) => r.source === "builtin").length;
  const registryCount = rows.filter((r) => r.source === "registry").length;

  return (
    <AdminLayout title="WHOIS 服务器管理">
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm text-muted-foreground">
            每个 TLD 的自定义 WHOIS 服务器覆盖。自定义条目优先级最高，会覆盖注册局/内置来源。
          </p>
        </div>

        <div className="grid grid-cols-3 gap-2">
          <div className="glass-panel border border-border rounded-xl p-3 text-center">
            <p className="text-lg font-bold tabular-nums">{userCount}</p>
            <p className="text-[10px] text-muted-foreground">自定义（用户维护）</p>
          </div>
          <div className="glass-panel border border-border rounded-xl p-3 text-center">
            <p className="text-lg font-bold tabular-nums">{builtinCount}</p>
            <p className="text-[10px] text-muted-foreground">内置（只读）</p>
          </div>
          <div className="glass-panel border border-border rounded-xl p-3 text-center">
            <p className="text-lg font-bold tabular-nums">{registryCount}</p>
            <p className="text-[10px] text-muted-foreground">注册局信息（只读）</p>
          </div>
        </div>

        <div className="flex gap-2">
          <div className="relative flex-1">
            <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
            <Input
              placeholder="搜索 TLD 或服务器地址..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 h-9 text-sm"
            />
          </div>
          <Button size="sm" className="h-9 shrink-0" onClick={() => { setShowAdd(true); setEditingTld(null); }}>
            <RiAddLine className="w-3.5 h-3.5 mr-1" />添加
          </Button>
          <Button size="sm" variant="outline" className="h-9 w-9 p-0 shrink-0" onClick={fetchServers} title="刷新">
            <RiRefreshLine className={["w-3.5 h-3.5", loading && "animate-spin"].filter(Boolean).join(" ")} />
          </Button>
        </div>

        {showAdd && (
          <AddEditForm
            onSave={handleSave}
            onCancel={() => setShowAdd(false)}
          />
        )}

        <div className="glass-panel border border-border rounded-2xl overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border/60 bg-muted/20">
            <p className="text-xs font-medium text-muted-foreground">服务器列表</p>
            <p className="text-xs font-mono text-muted-foreground">
              {loading ? "加载中..." : `${filtered.length}`}
            </p>
          </div>

          {loading && rows.length === 0 ? (
            <div className="flex items-center justify-center py-16 text-muted-foreground text-sm gap-2">
              <RiLoader4Line className="w-4 h-4 animate-spin" />加载中...
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex items-center justify-center py-16 text-muted-foreground text-sm">
              未找到服务器
            </div>
          ) : (
            <div className="divide-y divide-border/50 max-h-[70vh] overflow-y-auto overscroll-contain">
              {filtered.map((row) => (
                <div key={row.tld}>
                  {editingTld === row.tld && row.source === "user" ? (
                    <div className="px-4 py-3">
                      <AddEditForm
                        initial={{ tld: row.tld, entry: row.entry }}
                        onSave={handleSave}
                        onCancel={() => setEditingTld(null)}
                      />
                    </div>
                  ) : (
                    <div className="flex items-center gap-3 px-4 py-2.5 hover:bg-muted/30 transition-colors group">
                      <code className="text-xs font-mono text-foreground w-20 shrink-0">.{row.tld}</code>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <ProtocolBadge protocol={getProtocol(row.entry)} />
                        <SourceBadge source={row.source} />
                      </div>
                      <span className="text-xs text-muted-foreground font-mono truncate flex-1 min-w-0">
                        {getDisplayHost(row.entry)}
                      </span>
                      {row.source === "user" && (
                        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                          <Button size="icon-sm" variant="ghost" className="h-6 w-6 touch-manipulation"
                            onClick={() => setEditingTld(row.tld)} title="编辑">
                            <RiEditLine className="w-3 h-3" />
                          </Button>
                          <Button size="icon-sm" variant="ghost"
                            className="h-6 w-6 text-destructive hover:text-destructive touch-manipulation"
                            onClick={() => handleDelete(row.tld)}
                            disabled={deleting === row.tld} title="删除">
                            <RiDeleteBinLine className="w-3 h-3" />
                          </Button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="rounded-xl border border-border/60 bg-muted/20 p-4 space-y-2">
          <p className="text-xs font-medium">使用说明</p>
          <ul className="text-xs text-muted-foreground space-y-1 list-disc list-inside">
            <li><strong>TCP 43</strong>：连接到指定主机的标准 WHOIS 端口</li>
            <li>
              <strong>HTTP GET/POST</strong>：通过 HTTP 查询，URL 中用{" "}
              <code className="bg-muted px-1 rounded text-[10px]">{"{{domain}}"}</code>{" "}
              代替域名
            </li>
            <li>自定义服务器优先级高于内置列表与注册局信息</li>
            <li>注册局与内置条目只读；可为同一 TLD 添加自定义覆盖</li>
          </ul>
        </div>
      </div>
    </AdminLayout>
  );
}
