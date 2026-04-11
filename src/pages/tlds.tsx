import React from "react";
import Head from "next/head";
import Link from "next/link";
import { getCached, setCached } from "@/lib/client-cache";
import { motion, AnimatePresence } from "framer-motion";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";
import {
  RiArrowLeftSLine,
  RiGlobalLine,
  RiSearchLine,
  RiLoader4Line,
  RiFlagLine,
  RiStarLine,
  RiServerLine,
  RiAddLine,
  RiDeleteBinLine,
  RiEditLine,
  RiCheckLine,
  RiCloseLine,
  RiRefreshLine,
} from "@remixicon/react";
import type { TldInfo, IanaTldsResponse } from "./api/iana-tlds";
import { CustomServerEntry } from "@/lib/whois/custom-servers";
import { toast } from "sonner";

type FilterType = "all" | "cctld" | "gtld";
type TabType = "tlds" | "servers";
type Protocol = "tcp" | "http";

interface ServerRow {
  tld: string;
  entry: CustomServerEntry;
  source: "builtin" | "cctld" | "user";
}

function getProtocol(entry: CustomServerEntry): Protocol {
  if (typeof entry === "object" && entry.type === "http") return "http";
  if (typeof entry === "object" && entry.type === "scraper") return "http";
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
  if (source === "user") return <Badge variant="outline" className="text-[9px] shrink-0">Custom</Badge>;
  if (source === "cctld") return <Badge variant="outline" className="text-[9px] text-muted-foreground shrink-0">ccTLD</Badge>;
  return <Badge variant="outline" className="text-[9px] text-muted-foreground shrink-0">Built-in</Badge>;
}

interface AddEditFormProps {
  initial?: { tld: string; entry: CustomServerEntry };
  onSave: (tld: string, entry: CustomServerEntry) => Promise<void>;
  onCancel: () => void;
}

function AddEditForm({ initial, onSave, onCancel }: AddEditFormProps) {
  const { t } = useTranslation();
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
    } else {
      if (!url.trim()) return null;
      return { type: "http", url: url.trim(), method: httpMethod };
    }
  };

  const handleSave = async () => {
    const normalizedTld = tld.trim().toLowerCase().replace(/^\./, "");
    if (!normalizedTld) return;
    const entry = buildEntry();
    if (!entry) return;
    setSaving(true);
    try { await onSave(normalizedTld, entry); }
    finally { setSaving(false); }
  };

  const isValid = (() => {
    const normalizedTldCheck = tld.trim().toLowerCase().replace(/^\./, "");
    if (!normalizedTldCheck) return false;
    if (protocol === "tcp") return !!host.trim();
    return !!url.trim();
  })();

  return (
    <div className="space-y-4 p-4 rounded-xl border border-border/60 bg-muted/20">
      <div className="space-y-1.5">
        <label className="text-xs font-medium text-muted-foreground">{t("tlds.form_tld_label")}</label>
        <div className="flex items-center gap-1.5">
          <span className="text-sm text-muted-foreground">.</span>
          <Input placeholder="com, com.br, co.uk ..." value={tld} onChange={(e) => setTld(e.target.value)}
            disabled={!!initial} className="h-8 text-sm font-mono" />
        </div>
      </div>
      <div className="space-y-1.5">
        <label className="text-xs font-medium text-muted-foreground">{t("tlds.form_protocol_label")}</label>
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
            <label className="text-xs font-medium text-muted-foreground">{t("tlds.form_host_label")}</label>
            <Input placeholder="whois.example.com" value={host} onChange={(e) => setHost(e.target.value)}
              className="h-8 text-sm font-mono" />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">{t("tlds.form_port_label")}</label>
            <Input placeholder="43" value={port} onChange={(e) => setPort(e.target.value)}
              className="h-8 text-sm font-mono" type="number" min={1} max={65535} />
          </div>
        </div>
      )}
      {protocol === "http" && (
        <div className="space-y-3">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">
              {t("tlds.form_url_label").split("{{domain}}")[0]}<code className="bg-muted px-1 py-0.5 rounded text-[10px]">{"{{domain}}"}</code>{t("tlds.form_url_label").split("{{domain}}")[1]}
            </label>
            <Input placeholder="https://whois.example.com/query?domain={{domain}}" value={url}
              onChange={(e) => setUrl(e.target.value)} className="h-8 text-sm font-mono" />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">{t("tlds.form_method_label")}</label>
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
          {saving ? t("tlds.form_saving") : t("tlds.form_save")}
        </Button>
        <Button size="sm" variant="ghost" onClick={onCancel} className="h-7 text-xs">
          <RiCloseLine className="w-3.5 h-3.5 mr-1" />{t("tlds.form_cancel")}
        </Button>
      </div>
    </div>
  );
}

const TldCard = React.memo(function TldCard({ entry, isChinese }: { entry: TldInfo; isChinese: boolean }) {
  const { t } = useTranslation();
  const isCc = entry.type === "cctld";
  const countryLabel = isChinese ? entry.country : entry.countryEn;
  return (
    <div className="glass-panel border border-border rounded-xl p-3 flex flex-col gap-1.5">
      <div className="flex items-center justify-between gap-1">
        <span className="font-mono text-sm font-bold truncate">.{entry.tld}</span>
        {isCc && countryLabel ? (
          <span className="text-[9px] px-1.5 py-0 h-4 leading-4 rounded-sm bg-blue-500/12 text-blue-600 dark:text-blue-400 border border-blue-400/30 truncate max-w-[80px] inline-block">
            {countryLabel}
          </span>
        ) : (
          <span className="text-[9px] px-1.5 py-0 h-4 leading-4 rounded-sm bg-violet-500/12 text-violet-600 dark:text-violet-400 border border-violet-400/30 inline-block">
            gTLD
          </span>
        )}
      </div>
      <div className="flex items-center gap-1 min-h-[14px]">
        {entry.hasWhois && (
          <span className="text-[9px] px-1.5 py-0 h-4 leading-4 rounded-sm bg-emerald-500/12 text-emerald-600 dark:text-emerald-400 border border-emerald-400/30 inline-flex items-center">
            WHOIS
          </span>
        )}
        {entry.hasRdap && (
          <span className="text-[9px] px-1.5 py-0 h-4 leading-4 rounded-sm bg-sky-500/12 text-sky-600 dark:text-sky-400 border border-sky-400/30 inline-flex items-center">
            RDAP
          </span>
        )}
        {!entry.hasWhois && !entry.hasRdap && (
          <span className="text-[9px] px-1.5 py-0 h-4 leading-4 rounded-sm bg-red-500/8 text-red-400/70 dark:text-red-500/60 border border-red-400/20 inline-flex items-center">
            {isChinese ? "不支持" : "No support"}
          </span>
        )}
      </div>
    </div>
  );
});

export default function TldsPage() {
  const { locale, t } = useTranslation();
  const settings = useSiteSettings();
  const isChinese = locale === "zh" || locale === "zh-tw";
  const siteName = settings.site_logo_text || "WHOIS";

  const [tab, setTab] = React.useState<TabType>("tlds");

  const [search, setSearch] = React.useState("");
  const [typeFilter, setTypeFilter] = React.useState<FilterType>("all");
  const IANA_CACHE_TTL = 5 * 60_000;
  const [data, setData] = React.useState<IanaTldsResponse | null>(
    () => getCached<IanaTldsResponse>("iana_tlds", IANA_CACHE_TTL)
  );
  const [loading, setLoading] = React.useState(
    () => !getCached<IanaTldsResponse>("iana_tlds", IANA_CACHE_TTL)
  );

  const [allServers, setAllServers] = React.useState<ServerRow[]>([]);
  const [userTlds, setUserTlds] = React.useState<Set<string>>(new Set());
  const [srvLoading, setSrvLoading] = React.useState(false);
  const [srvSearch, setSrvSearch] = React.useState("");
  const [showAdd, setShowAdd] = React.useState(false);
  const [editingTld, setEditingTld] = React.useState<string | null>(null);
  const [deleting, setDeleting] = React.useState<string | null>(null);
  const BUILTIN_TLDS = new Set(["bn"]);

  React.useEffect(() => {
    if (getCached("iana_tlds", IANA_CACHE_TTL)) return;
    fetch("/api/iana-tlds")
      .then((r) => r.json())
      .then((d: IanaTldsResponse) => { setCached("iana_tlds", d); setData(d); })
      .catch(() => {})
      .finally(() => setLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fetchServers = React.useCallback(async () => {
    setSrvLoading(true);
    try {
      const res = await fetch("/api/whois-servers");
      const d = await res.json();
      if (!d.success) return;
      const userKeys = new Set<string>(Object.keys(d.userServers ?? {}));
      setUserTlds(userKeys);
      const rows: ServerRow[] = Object.entries(
        d.servers as Record<string, CustomServerEntry>,
      ).map(([tld, entry]) => ({
        tld,
        entry,
        source: userKeys.has(tld) ? "user" : BUILTIN_TLDS.has(tld) ? "builtin" : "cctld",
      }));
      rows.sort((a, b) => {
        const order = { user: 0, builtin: 1, cctld: 2 };
        if (order[a.source] !== order[b.source]) return order[a.source] - order[b.source];
        return a.tld.localeCompare(b.tld);
      });
      setAllServers(rows);
    } finally {
      setSrvLoading(false);
    }
  }, []);

  React.useEffect(() => {
    if (tab === "servers" && allServers.length === 0) fetchServers();
  }, [tab, fetchServers, allServers.length]);

  const handleSave = async (tld: string, entry: CustomServerEntry) => {
    const res = await fetch("/api/whois-servers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tld, entry }),
    });
    const d = await res.json();
    if (d.success) {
      toast.success(d.message || t("tlds.toast_saved"));
      setShowAdd(false);
      setEditingTld(null);
      await fetchServers();
    } else {
      toast.error(d.message || t("tlds.toast_save_failed"));
    }
  };

  const handleDelete = async (tld: string) => {
    setDeleting(tld);
    try {
      const res = await fetch(`/api/whois-servers?tld=${encodeURIComponent(tld)}`, { method: "DELETE" });
      const d = await res.json();
      if (d.success) { toast.success(d.message || t("tlds.toast_deleted")); await fetchServers(); }
      else toast.error(d.message || t("tlds.toast_delete_failed"));
    } finally {
      setDeleting(null);
    }
  };

  const filtered = React.useMemo(() => {
    if (!data) return [];
    const q = search.trim().toLowerCase().replace(/^\./, "");
    let list = data.tlds;
    if (typeFilter !== "all") list = list.filter((t) => t.type === typeFilter);
    if (!q) return list;
    return list.filter(
      (t) => t.tld.includes(q) || (t.country && t.country.includes(q)) || (t.countryEn && t.countryEn.toLowerCase().includes(q)),
    );
  }, [data, search, typeFilter]);

  const filteredServers = allServers.filter(
    (r) => r.tld.includes(srvSearch.toLowerCase()) || getDisplayHost(r.entry).toLowerCase().includes(srvSearch.toLowerCase()),
  );

  const handleFilterClick = (f: FilterType) => setTypeFilter((prev) => (prev === f ? "all" : f));

  const TAB_LABELS = {
    tlds:    isChinese ? "TLD 列表" : "TLD List",
    servers: isChinese ? "WHOIS 服务器" : "WHOIS Servers",
  };

  return (
    <>
      <Head>
        <title key="title">{`${tab === "servers" ? (isChinese ? "WHOIS 服务器" : "WHOIS Servers") : (isChinese ? "支持后缀" : "Supported TLDs")} — ${siteName}`}</title>
      </Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-3xl mx-auto px-4 sm:px-6 py-6 pb-16 overflow-x-hidden">

          <div className="flex items-center gap-3 mb-5">
            <Link
              href="/about"
              className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground shrink-0"
            >
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-2 flex-1 min-w-0">
              <div className="p-1.5 rounded-lg bg-blue-500/10 text-blue-500 shrink-0">
                {tab === "servers" ? <RiServerLine className="w-5 h-5" /> : <RiGlobalLine className="w-5 h-5" />}
              </div>
              <div className="min-w-0">
                <h1 className="text-lg font-bold leading-none">
                  {tab === "servers"
                    ? (isChinese ? "WHOIS 服务器" : "WHOIS Servers")
                    : (isChinese ? "支持后缀" : "Supported TLDs")}
                </h1>
                <p className="text-[11px] text-muted-foreground mt-0.5 break-words">
                  {tab === "servers"
                    ? (isChinese ? "查看与管理各 TLD 的 WHOIS 查询服务器配置" : "View and manage custom WHOIS server overrides per TLD")
                    : (isChinese ? "IANA 全量后缀列表，标注 WHOIS/RDAP 查询支持情况" : "Full IANA TLD list with WHOIS/RDAP support status")}
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-1 mb-5 p-1 glass-panel border border-border rounded-xl">
            {(["tlds", "servers"] as TabType[]).map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={[
                  "flex-1 flex items-center justify-center gap-1.5 px-2 sm:px-4 py-2 rounded-lg text-sm font-medium transition-all min-w-0 overflow-hidden touch-manipulation select-none active:scale-[0.97]",
                  tab === t
                    ? "bg-primary text-primary-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted/60",
                ].join(" ")}
              >
                {t === "tlds"
                  ? <RiGlobalLine className="w-4 h-4 shrink-0" />
                  : <RiServerLine className="w-4 h-4 shrink-0" />}
                <span className="truncate">{TAB_LABELS[t]}</span>
              </button>
            ))}
          </div>

          <AnimatePresence mode="wait" initial={false}>
          {tab === "tlds" ? (
            <motion.div
              key="tab-tlds"
              initial={{ opacity: 0, x: -12 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 12 }}
              transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
            >
              {!loading && data && (
                <motion.div
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.22 }}
                  className="grid grid-cols-2 gap-2.5 mb-5"
                >
                  <button
                    onClick={() => handleFilterClick("cctld")}
                    className={[
                      "glass-panel border rounded-xl p-3 text-center transition-all cursor-pointer",
                      typeFilter === "cctld"
                        ? "border-blue-500/60 bg-blue-500/8 ring-1 ring-blue-500/30"
                        : "border-border hover:border-blue-400/40 hover:bg-blue-500/5",
                    ].join(" ")}
                  >
                    <RiFlagLine className={["w-4 h-4 mx-auto mb-1 transition-colors", typeFilter === "cctld" ? "text-blue-500" : "text-blue-400/70"].join(" ")} />
                    <p className="text-lg font-bold tabular-nums">{data.ccTldCount}</p>
                    <p className="text-[10px] text-muted-foreground">{isChinese ? "国别域名 (ccTLD)" : "Country Code (ccTLD)"}</p>
                  </button>
                  <button
                    onClick={() => handleFilterClick("gtld")}
                    className={[
                      "glass-panel border rounded-xl p-3 text-center transition-all cursor-pointer",
                      typeFilter === "gtld"
                        ? "border-violet-500/60 bg-violet-500/8 ring-1 ring-violet-500/30"
                        : "border-border hover:border-violet-400/40 hover:bg-violet-500/5",
                    ].join(" ")}
                  >
                    <RiStarLine className={["w-4 h-4 mx-auto mb-1 transition-colors", typeFilter === "gtld" ? "text-violet-500" : "text-violet-400/70"].join(" ")} />
                    <p className="text-lg font-bold tabular-nums">{data.gTldCount}</p>
                    <p className="text-[10px] text-muted-foreground">{isChinese ? "通用顶级 (gTLD)" : "Generic (gTLD)"}</p>
                  </button>
                </motion.div>
              )}

              <div className="mb-5">
                <div className="relative">
                  <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                  <Input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder={isChinese ? "搜索后缀、国家名称，如 com / 中国 / china ..." : "Search TLD or country, e.g. com / china ..."}
                    className="pl-9 h-9 text-sm"
                  />
                </div>
              </div>

              {loading ? (
                <div className="flex flex-col items-center justify-center py-20 gap-3">
                  <RiLoader4Line className="w-6 h-6 text-muted-foreground animate-spin" />
                  <p className="text-sm text-muted-foreground">{isChinese ? "正在加载 IANA 后缀列表..." : "Loading IANA TLD list..."}</p>
                </div>
              ) : filtered.length === 0 ? (
                <div className="text-center py-16">
                  <RiGlobalLine className="w-8 h-8 mx-auto text-muted-foreground/40 mb-3" />
                  <p className="text-sm text-muted-foreground">{isChinese ? "未找到匹配的后缀" : "No matching TLDs found"}</p>
                </div>
              ) : (
                <>
                  <p className="text-[11px] text-muted-foreground mb-3">
                    {isChinese
                      ? `显示 ${filtered.length} 个后缀（共 ${data?.total ?? 0} 个）`
                      : `Showing ${filtered.length} of ${data?.total ?? 0} TLDs`}
                  </p>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {filtered.map((entry) => (
                      <TldCard key={entry.tld} entry={entry} isChinese={isChinese} />
                    ))}
                  </div>
                </>
              )}

              <div className="mt-10 pt-6 border-t border-border/40 text-center">
                <p className="text-[11px] text-muted-foreground/50">
                  {isChinese ? "点击统计卡片可按类型筛选 · 数据来源 IANA" : "Click the cards above to filter by type · Data source: IANA"}
                </p>
              </div>
            </motion.div>
          ) : (
            <motion.div
              key="tab-servers"
              initial={{ opacity: 0, x: 12 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -12 }}
              transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
            >
            <div className="space-y-4">
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                  <Input
                    placeholder={isChinese ? "搜索 TLD 或服务器地址..." : "Search TLD or server..."}
                    value={srvSearch}
                    onChange={(e) => setSrvSearch(e.target.value)}
                    className="pl-9 h-9 text-sm"
                  />
                </div>
                <Button size="sm" className="h-9 shrink-0" onClick={() => { setShowAdd(true); setEditingTld(null); }}>
                  <RiAddLine className="w-3.5 h-3.5 mr-1" />
                  {isChinese ? "添加" : "Add"}
                </Button>
                <Button size="sm" variant="outline" className="h-9 w-9 p-0 shrink-0" onClick={fetchServers} title={isChinese ? "刷新" : "Refresh"}>
                  <RiRefreshLine className={["w-3.5 h-3.5", srvLoading && "animate-spin"].filter(Boolean).join(" ")} />
                </Button>
              </div>

              <AnimatePresence initial={false}>
                {showAdd && (
                  <motion.div
                    key="add-form"
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
                    style={{ overflow: "hidden" }}
                  >
                    <AddEditForm onSave={handleSave} onCancel={() => setShowAdd(false)} />
                  </motion.div>
                )}
              </AnimatePresence>

              <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                <div className="flex items-center justify-between px-4 py-3 border-b border-border/60 bg-muted/20">
                  <p className="text-xs font-medium text-muted-foreground">{isChinese ? "服务器列表" : "Server List"}</p>
                  <p className="text-xs font-mono text-muted-foreground">
                    {srvLoading ? (isChinese ? "加载中..." : "Loading...") : `${filteredServers.length}`}
                  </p>
                </div>

                {srvLoading && allServers.length === 0 ? (
                  <div className="flex items-center justify-center py-16 text-muted-foreground text-sm gap-2">
                    <RiLoader4Line className="w-4 h-4 animate-spin" />
                    {isChinese ? "加载中..." : "Loading..."}
                  </div>
                ) : filteredServers.length === 0 ? (
                  <div className="flex items-center justify-center py-16 text-muted-foreground text-sm">
                    {isChinese ? "未找到服务器" : "No servers found"}
                  </div>
                ) : (
                  <div className="divide-y divide-border/50 max-h-[60vh] overflow-y-auto overscroll-contain">
                    {filteredServers.map((row) => (
                      <div key={row.tld}>
                        <AnimatePresence initial={false} mode="wait">
                          {editingTld === row.tld && row.source === "user" ? (
                            <motion.div
                              key="form"
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: "auto" }}
                              exit={{ opacity: 0, height: 0 }}
                              transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
                              style={{ overflow: "hidden" }}
                            >
                              <div className="px-4 py-3">
                                <AddEditForm
                                  initial={{ tld: row.tld, entry: row.entry }}
                                  onSave={handleSave}
                                  onCancel={() => setEditingTld(null)}
                                />
                              </div>
                            </motion.div>
                          ) : (
                            <motion.div
                              key="row"
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              exit={{ opacity: 0 }}
                              transition={{ duration: 0.12 }}
                              className="flex items-center gap-3 px-4 py-2.5 hover:bg-muted/30 transition-colors group"
                            >
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
                                    onClick={() => setEditingTld(row.tld)} title={isChinese ? "编辑" : "Edit"}>
                                    <RiEditLine className="w-3 h-3" />
                                  </Button>
                                  <Button size="icon-sm" variant="ghost"
                                    className="h-6 w-6 text-destructive hover:text-destructive touch-manipulation"
                                    onClick={() => handleDelete(row.tld)}
                                    disabled={deleting === row.tld} title={isChinese ? "删除" : "Delete"}>
                                    <RiDeleteBinLine className="w-3 h-3" />
                                  </Button>
                                </div>
                              )}
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="rounded-xl border border-border/60 bg-muted/20 p-4 space-y-2">
                <p className="text-xs font-medium">{isChinese ? "使用说明" : "Usage"}</p>
                <ul className="text-xs text-muted-foreground space-y-1 list-disc list-inside">
                  <li><strong>TCP 43</strong>：{isChinese ? "连接到指定主机的标准 WHOIS 端口" : "Connect to host via standard WHOIS port"}</li>
                  <li>
                    <strong>HTTP GET/POST</strong>：{isChinese ? "通过 HTTP 查询，URL 中用" : "HTTP query; use"}{" "}
                    <code className="bg-muted px-1 rounded text-[10px]">{"{{domain}}"}</code>{" "}
                    {isChinese ? "替代域名" : "as domain placeholder"}
                  </li>
                  <li>{isChinese ? "自定义服务器优先级高于内置列表" : "Custom servers override built-in entries"}</li>
                  <li>{isChinese ? "ccTLD 和内置服务器只读；可为同一 TLD 添加自定义覆盖" : "ccTLD/built-in entries are read-only; add a custom entry to override"}</li>
                </ul>
              </div>
            </div>
            </motion.div>
          )}
          </AnimatePresence>
        </main>
      </ScrollArea>
    </>
  );
}
