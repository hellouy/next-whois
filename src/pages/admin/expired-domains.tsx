/**
 * /admin/expired-domains
 * Crawl expireddomains.net for short/high-value expired domain leads.
 * Supports length-based and prefix-based crawl modes, with rich filtering.
 */
import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { getPageCache, setPageCache } from "@/lib/page-cache";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiRefreshLine, RiSearchLine, RiDeleteBin2Line,
  RiStarLine, RiStarFill, RiExternalLinkLine, RiEyeLine, RiSettings4Line,
  RiGlobalLine, RiScanLine, RiFilterLine, RiCheckLine, RiDeleteBinLine,
  RiArrowLeftLine, RiArrowRightLine, RiAlertLine, RiEyeOffLine,
  RiInformationLine, RiAddLine, RiCloseLine, RiBarChartLine,
  RiSortAsc, RiText, RiLink, RiSpeedLine,
} from "@remixicon/react";

// ── Types ─────────────────────────────────────────────────────────────────────

type Lead = {
  id: number;
  domain: string;
  tld: string;
  sld: string;
  char_count: number;
  bl: number | null;
  dp: number | null;
  deleted_date: string | null;
  available_date: string | null;
  status: string;
  seen: boolean;
  starred: boolean;
  notes: string | null;
  crawled_at: string;
};

type Stats = {
  byLength: { char_count: number; cnt: string }[];
  byTld: { tld: string; cnt: string }[];
  total: number;
  starred: number;
  unseen: number;
};

type Settings = {
  expireddomains_username: string;
  expireddomains_password: string;
  expireddomains_max_length: string;
  expireddomains_min_length: string;
  expireddomains_tld_filter: string;
  expireddomains_rows: string;
  expireddomains_prefix_list: string;
};

const DEFAULT_SETTINGS: Settings = {
  expireddomains_username: "",
  expireddomains_password: "",
  expireddomains_max_length: "4",
  expireddomains_min_length: "1",
  expireddomains_tld_filter: "",
  expireddomains_rows: "200",
  expireddomains_prefix_list: "",
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function timeSince(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  const h = Math.floor(diff / 3600000);
  const d = Math.floor(diff / 86400000);
  if (m < 1) return "刚刚";
  if (m < 60) return `${m}分钟前`;
  if (h < 24) return `${h}小时前`;
  return `${d}天前`;
}

function parsePrefixes(raw: string): string[] {
  return raw.split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
}

function formatPrefixes(list: string[]): string {
  return list.join(",");
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ExpiredDomainsPage() {
  // Settings & panels
  const [settings, setSettings]         = React.useState<Settings>(DEFAULT_SETTINGS);
  const [showSettings, setShowSettings] = React.useState(false);
  const [savingSettings, setSavingSettings] = React.useState(false);
  const [crawlTab, setCrawlTab]         = React.useState<"length" | "prefix">("length");

  // Crawl state
  const [crawling, setCrawling]         = React.useState(false);
  const [crawlingPrefix, setCrawlingPrefix] = React.useState<string | null>(null);

  // Leads list
  const [leads, setLeads]               = React.useState<Lead[]>([]);
  const [total, setTotal]               = React.useState(0);
  const [page, setPage]                 = React.useState(1);
  const [loading, setLoading]           = React.useState(true);
  const [stats, setStats]               = React.useState<Stats | null>(() => getPageCache<Stats>("expired_lead_stats"));
  const [showStats, setShowStats]       = React.useState(false);

  // Filters
  const [filterExactLen, setFilterExactLen] = React.useState(0); // 0 = all
  const [filterPrefix,  setFilterPrefix]    = React.useState("");
  const [filterTld,     setFilterTld]       = React.useState("");
  const [filterMinBl,   setFilterMinBl]     = React.useState("");
  const [filterStarred, setFilterStarred]   = React.useState(false);
  const [filterUnseen,  setFilterUnseen]    = React.useState(false);
  const [sortMode,      setSortMode]        = React.useState("value");

  // Prefix chip input
  const [newPrefix, setNewPrefix] = React.useState("");

  const LIMIT = 50;

  // ── Load settings ──────────────────────────────────────────────────────────
  React.useEffect(() => {
    fetch("/api/admin/settings")
      .then(r => r.json())
      .then(d => {
        const s = d.settings ?? {};
        setSettings({
          expireddomains_username:    s.expireddomains_username    ?? "",
          expireddomains_password:    s.expireddomains_password    ?? "",
          expireddomains_max_length:  s.expireddomains_max_length  ?? "4",
          expireddomains_min_length:  s.expireddomains_min_length  ?? "1",
          expireddomains_tld_filter:  s.expireddomains_tld_filter  ?? "",
          expireddomains_rows:        s.expireddomains_rows        ?? "200",
          expireddomains_prefix_list: s.expireddomains_prefix_list ?? "",
        });
      })
      .catch(() => {});
  }, []);

  // ── Load leads ─────────────────────────────────────────────────────────────
  const loadLeads = React.useCallback(async (p: number = 1) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: String(p), limit: String(LIMIT), sort: sortMode });
      if (filterExactLen > 0)   params.set("exactLen", String(filterExactLen));
      if (filterPrefix)         params.set("prefix",   filterPrefix);
      if (filterTld)            params.set("tld",      filterTld);
      if (filterMinBl)          params.set("minBl",    filterMinBl);
      if (filterStarred)        params.set("starred",  "1");
      if (filterUnseen)         params.set("unseen",   "1");
      const r = await fetch(`/api/admin/expired-domains-crawl?${params}`);
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "加载失败");
      setLeads(d.leads ?? []);
      setTotal(d.pagination?.total ?? 0);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  }, [filterExactLen, filterPrefix, filterTld, filterMinBl, filterStarred, filterUnseen, sortMode]);

  React.useEffect(() => {
    setPage(1);
    loadLeads(1);
  }, [filterExactLen, filterPrefix, filterTld, filterMinBl, filterStarred, filterUnseen, sortMode]);

  React.useEffect(() => { loadLeads(page); }, [page]);

  // ── Load stats ─────────────────────────────────────────────────────────────
  const loadStats = React.useCallback(async () => {
    try {
      const r = await fetch("/api/admin/expired-domains-crawl?action=stats");
      const d = await r.json();
      if (r.ok) {
        setStats(d);
        setPageCache("expired_lead_stats", d, 2 * 60_000);
      }
    } catch {}
  }, []);

  React.useEffect(() => {
    // Only fetch stats if we don't already have a fresh cached copy
    if (!stats) loadStats();
  }, []);

  // ── Crawl: length mode ─────────────────────────────────────────────────────
  async function handleCrawlLength() {
    if (crawling) return;
    if (!settings.expireddomains_username || !settings.expireddomains_password) {
      setShowSettings(true);
      toast.error("请先填写 expireddomains.net 账号信息");
      return;
    }
    setCrawling(true);
    try {
      const r = await fetch("/api/admin/expired-domains-crawl?action=crawl&mode=length", { method: "POST" });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "抓取失败");
      toast.success(`按长度抓取完成：新增 ${d.inserted} 条，更新 ${d.updated} 条`);
      loadLeads(1);
      loadStats();
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setCrawling(false);
    }
  }

  // ── Crawl: all prefixes ────────────────────────────────────────────────────
  async function handleCrawlAllPrefixes() {
    if (crawling) return;
    const prefixes = parsePrefixes(settings.expireddomains_prefix_list);
    if (!prefixes.length) { toast.error("请先添加前缀"); return; }
    if (!settings.expireddomains_username || !settings.expireddomains_password) {
      setShowSettings(true);
      toast.error("请先填写账号信息");
      return;
    }
    setCrawling(true);
    try {
      const r = await fetch("/api/admin/expired-domains-crawl?action=crawl&mode=prefix", { method: "POST" });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "抓取失败");
      const summary = (d.results ?? [])
        .map((x: any) => `${x.prefix}(+${x.inserted})`)
        .join(" ");
      toast.success(`前缀抓取完成：${summary}`);
      loadLeads(1);
      loadStats();
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setCrawling(false);
    }
  }

  // ── Crawl: single prefix ───────────────────────────────────────────────────
  async function handleCrawlOnePrefix(pfx: string) {
    if (crawling) return;
    if (!settings.expireddomains_username || !settings.expireddomains_password) {
      setShowSettings(true);
      toast.error("请先填写账号信息");
      return;
    }
    setCrawlingPrefix(pfx);
    setCrawling(true);
    try {
      const r = await fetch(`/api/admin/expired-domains-crawl?action=crawl&prefix=${encodeURIComponent(pfx)}`, { method: "POST" });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "抓取失败");
      toast.success(`"${pfx}" 抓取完成：新增 ${d.inserted} 条，更新 ${d.updated} 条`);
      loadLeads(1);
      loadStats();
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setCrawling(false);
      setCrawlingPrefix(null);
    }
  }

  // ── Prefix list management ─────────────────────────────────────────────────
  function addPrefix() {
    const pfx = newPrefix.trim().toLowerCase();
    if (!pfx) return;
    const list = parsePrefixes(settings.expireddomains_prefix_list);
    if (list.includes(pfx)) { setNewPrefix(""); return; }
    setSettings(s => ({ ...s, expireddomains_prefix_list: formatPrefixes([...list, pfx]) }));
    setNewPrefix("");
  }

  function removePrefix(pfx: string) {
    const list = parsePrefixes(settings.expireddomains_prefix_list).filter(p => p !== pfx);
    setSettings(s => ({ ...s, expireddomains_prefix_list: formatPrefixes(list) }));
  }

  // ── Save settings ──────────────────────────────────────────────────────────
  async function handleSaveSettings() {
    setSavingSettings(true);
    try {
      const r = await fetch("/api/admin/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "保存失败");
      toast.success("配置已保存");
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setSavingSettings(false);
    }
  }

  // ── Lead actions ───────────────────────────────────────────────────────────
  async function patchLead(id: number, updates: Partial<Pick<Lead, "seen" | "starred" | "notes">>) {
    setLeads(prev => prev.map(l => l.id === id ? { ...l, ...updates } : l));
    await fetch("/api/admin/expired-domains-crawl", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, ...updates }),
    }).catch(() => loadLeads(page));
  }

  async function deleteLead(id: number) {
    setLeads(prev => prev.filter(l => l.id !== id));
    setTotal(t => Math.max(0, t - 1));
    await fetch(`/api/admin/expired-domains-crawl?id=${id}`, { method: "DELETE" }).catch(() => {});
  }

  async function clearAll() {
    if (!confirm("确定清空所有过期域名数据？此操作不可撤销")) return;
    await fetch("/api/admin/expired-domains-crawl?action=clear", { method: "DELETE" });
    setLeads([]); setTotal(0); setStats(null);
    toast.success("已清空");
  }

  // ── Derived state ──────────────────────────────────────────────────────────
  const totalPages   = Math.ceil(total / LIMIT);
  const prefixList   = parsePrefixes(settings.expireddomains_prefix_list);

  // ── Length presets ─────────────────────────────────────────────────────────
  const LEN_PRESETS = [
    { label: "全部", value: 0 },
    { label: "1字符", value: 1 },
    { label: "2字符", value: 2 },
    { label: "3字符", value: 3 },
    { label: "4字符", value: 4 },
  ];

  // ── Sort options ───────────────────────────────────────────────────────────
  const SORT_OPTIONS: { label: string; value: string }[] = [
    { label: "综合价值", value: "value" },
    { label: "外链 BL↓", value: "bl" },
    { label: "流行度 DP↓", value: "dp" },
    { label: "最新抓取", value: "newest" },
  ];

  return (
    <AdminLayout>
      <div className="space-y-5">

        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              <RiGlobalLine className="w-5 h-5 text-emerald-500" />
              过期域名挖掘
            </h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              从 expireddomains.net 抓取短域名、高价值域名和自定义前缀域名
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Button variant="outline" size="sm" onClick={() => { setShowStats(v => !v); if (!showStats) loadStats(); }} className="gap-1.5">
              <RiBarChartLine className="w-4 h-4" />{showStats ? "隐藏统计" : "数据统计"}
            </Button>
            <Button variant="outline" size="sm" onClick={() => setShowSettings(v => !v)} className="gap-1.5">
              <RiSettings4Line className="w-4 h-4" />{showSettings ? "关闭配置" : "抓取设置"}
            </Button>
            {(stats?.total ?? 0) > 0 && (
              <Button variant="outline" size="sm" onClick={clearAll}
                className="gap-1.5 text-red-500 hover:text-red-600 border-red-200 dark:border-red-900/40 hover:border-red-300">
                <RiDeleteBinLine className="w-4 h-4" />清空
              </Button>
            )}
          </div>
        </div>

        {/* ── Stats panel ────────────────────────────────────────────────── */}
        {showStats && stats && (
          <div className="rounded-2xl border border-border bg-card p-4 space-y-3">
            <div className="flex items-center gap-6 text-sm flex-wrap">
              <span>总计 <strong className="text-foreground">{stats.total.toLocaleString()}</strong></span>
              <span className="text-primary font-medium">★ {stats.starred}</span>
              <span className="text-amber-600 dark:text-amber-400">未读 {stats.unseen}</span>
            </div>
            {stats.byLength.length > 0 && (
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs text-muted-foreground">按长度：</span>
                {stats.byLength.map(r => (
                  <button
                    key={r.char_count}
                    onClick={() => { setFilterExactLen(filterExactLen === r.char_count ? 0 : r.char_count); }}
                    className={cn(
                      "text-xs px-2.5 py-1 rounded-lg border transition-colors",
                      filterExactLen === r.char_count
                        ? "border-primary bg-primary/10 text-primary font-semibold"
                        : "border-border text-muted-foreground hover:border-primary/40",
                    )}
                  >
                    {r.char_count}字 <span className="opacity-60">·{r.cnt}</span>
                  </button>
                ))}
              </div>
            )}
            {stats.byTld.length > 0 && (
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs text-muted-foreground">热门TLD：</span>
                {stats.byTld.slice(0, 8).map(r => (
                  <button
                    key={r.tld}
                    onClick={() => setFilterTld(filterTld === r.tld ? "" : r.tld)}
                    className={cn(
                      "text-xs px-2 py-0.5 rounded border transition-colors",
                      filterTld === r.tld
                        ? "border-primary bg-primary/10 text-primary font-semibold"
                        : "border-border text-muted-foreground hover:border-primary/40",
                    )}
                  >
                    .{r.tld} <span className="opacity-60">{r.cnt}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── Settings panel ──────────────────────────────────────────────── */}
        {showSettings && (
          <div className="rounded-2xl border border-border bg-card p-5 space-y-5">
            <h2 className="text-sm font-semibold flex items-center gap-2">
              <RiSettings4Line className="w-4 h-4 text-primary" />
              账号与抓取参数
            </h2>

            {/* Account */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground">用户名</label>
                <Input value={settings.expireddomains_username}
                  onChange={e => setSettings(s => ({ ...s, expireddomains_username: e.target.value }))}
                  placeholder="expireddomains.net 用户名" className="h-9 text-sm" />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground">密码</label>
                <Input type="password" value={settings.expireddomains_password}
                  onChange={e => setSettings(s => ({ ...s, expireddomains_password: e.target.value }))}
                  placeholder="expireddomains.net 密码" className="h-9 text-sm" />
              </div>
            </div>

            {/* Crawl mode tabs */}
            <div className="space-y-3">
              <div className="flex gap-1 p-1 bg-muted/50 rounded-xl w-fit">
                {(["length", "prefix"] as const).map(tab => (
                  <button key={tab} onClick={() => setCrawlTab(tab)}
                    className={cn("px-4 py-1.5 rounded-lg text-xs font-medium transition-all",
                      crawlTab === tab ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground"
                    )}>
                    {tab === "length" ? "按长度抓取" : "按前缀抓取"}
                  </button>
                ))}
              </div>

              {/* Length mode */}
              {crawlTab === "length" && (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <p className="text-xs text-muted-foreground">按 SLD 字符数范围批量抓取所有过期可注册域名</p>
                    <div className="flex gap-2 flex-wrap">
                      {[
                        { label: "单字符 (≤1)", min: "1", max: "1" },
                        { label: "双字符 (≤2)", min: "1", max: "2" },
                        { label: "三字符 (≤3)", min: "1", max: "3" },
                        { label: "精品四字 (≤4)", min: "1", max: "4" },
                      ].map(p => (
                        <button key={p.max}
                          onClick={() => setSettings(s => ({ ...s, expireddomains_min_length: p.min, expireddomains_max_length: p.max }))}
                          className={cn(
                            "px-3 py-1.5 text-xs rounded-lg border transition-colors",
                            settings.expireddomains_min_length === p.min && settings.expireddomains_max_length === p.max
                              ? "border-primary bg-primary/10 text-primary font-semibold"
                              : "border-border text-muted-foreground hover:border-primary/40"
                          )}>
                          {p.label}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">最短字符数</label>
                      <Input type="number" min={1} max={20} value={settings.expireddomains_min_length}
                        onChange={e => setSettings(s => ({ ...s, expireddomains_min_length: e.target.value }))}
                        className="h-9 text-sm" />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">最长字符数</label>
                      <Input type="number" min={1} max={20} value={settings.expireddomains_max_length}
                        onChange={e => setSettings(s => ({ ...s, expireddomains_max_length: e.target.value }))}
                        className="h-9 text-sm" />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">TLD 过滤（逗号分隔）</label>
                      <Input value={settings.expireddomains_tld_filter}
                        onChange={e => setSettings(s => ({ ...s, expireddomains_tld_filter: e.target.value }))}
                        placeholder="com,net,org" className="h-9 text-sm" />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">每次抓取数量</label>
                      <Input type="number" min={10} max={500} value={settings.expireddomains_rows}
                        onChange={e => setSettings(s => ({ ...s, expireddomains_rows: e.target.value }))}
                        className="h-9 text-sm" />
                    </div>
                  </div>
                  <Button
                    size="sm"
                    onClick={() => { handleSaveSettings(); handleCrawlLength(); }}
                    disabled={crawling}
                    className="gap-1.5 bg-emerald-600 hover:bg-emerald-700 text-white"
                  >
                    {crawling
                      ? <><RiLoader4Line className="w-4 h-4 animate-spin" />抓取中…</>
                      : <><RiScanLine className="w-4 h-4" />保存并立即抓取</>
                    }
                  </Button>
                </div>
              )}

              {/* Prefix mode */}
              {crawlTab === "prefix" && (
                <div className="space-y-4">
                  <p className="text-xs text-muted-foreground">
                    按前缀搜索，例如「ai」可抓取 ai.com / aix.net / ailab.org 等所有以 ai 开头的域名，
                    结果按外链数量倒序排列
                  </p>

                  {/* Prefix chip list */}
                  <div className="space-y-2">
                    <label className="text-xs font-medium text-muted-foreground">前缀列表</label>
                    <div className="flex flex-wrap gap-2 p-3 min-h-[52px] border border-border rounded-xl bg-muted/20">
                      {prefixList.map(pfx => (
                        <div key={pfx}
                          className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-primary/10 border border-primary/20 text-primary text-xs font-semibold">
                          <span className="font-mono">{pfx}*</span>
                          <div className="flex gap-0.5 ml-1">
                            <button
                              onClick={() => handleCrawlOnePrefix(pfx)}
                              disabled={crawling}
                              className="p-0.5 hover:bg-primary/20 rounded transition-colors"
                              title={`抓取 ${pfx}* 域名`}
                            >
                              {crawlingPrefix === pfx
                                ? <RiLoader4Line className="w-3 h-3 animate-spin" />
                                : <RiScanLine className="w-3 h-3" />
                              }
                            </button>
                            <button
                              onClick={() => removePrefix(pfx)}
                              className="p-0.5 hover:bg-red-100 dark:hover:bg-red-900/20 hover:text-red-600 rounded transition-colors"
                              title="移除"
                            >
                              <RiCloseLine className="w-3 h-3" />
                            </button>
                          </div>
                        </div>
                      ))}
                      {!prefixList.length && (
                        <span className="text-xs text-muted-foreground/60 self-center">暂无前缀，请在下方添加</span>
                      )}
                    </div>
                    {/* Add prefix input */}
                    <div className="flex gap-2">
                      <Input
                        value={newPrefix}
                        onChange={e => setNewPrefix(e.target.value.toLowerCase().replace(/[^a-z0-9\-]/g, ""))}
                        onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); addPrefix(); } }}
                        placeholder="输入前缀，如 ai / gpt / web3 / nft …"
                        className="h-9 text-sm font-mono"
                      />
                      <Button size="sm" variant="outline" onClick={addPrefix} className="gap-1 shrink-0">
                        <RiAddLine className="w-4 h-4" />添加
                      </Button>
                    </div>
                    {/* Common prefix suggestions */}
                    <div className="flex gap-1.5 flex-wrap">
                      <span className="text-xs text-muted-foreground self-center">热门：</span>
                      {["ai", "gpt", "nft", "web3", "dao", "defi", "meta", "crypto", "chat", "api", "dev", "lab", "pro", "go", "my"].map(sug => (
                        <button key={sug}
                          onClick={() => {
                            if (!prefixList.includes(sug)) {
                              setSettings(s => ({
                                ...s,
                                expireddomains_prefix_list: formatPrefixes([...parsePrefixes(s.expireddomains_prefix_list), sug]),
                              }));
                            }
                          }}
                          disabled={prefixList.includes(sug)}
                          className={cn(
                            "text-[11px] px-2 py-0.5 rounded border transition-colors font-mono",
                            prefixList.includes(sug)
                              ? "border-primary/30 bg-primary/5 text-primary/50 cursor-default"
                              : "border-border text-muted-foreground hover:border-primary/40 hover:text-foreground"
                          )}>
                          {sug}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* TLD + rows for prefix mode */}
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">TLD 过滤（留空=全部）</label>
                      <Input value={settings.expireddomains_tld_filter}
                        onChange={e => setSettings(s => ({ ...s, expireddomains_tld_filter: e.target.value }))}
                        placeholder="com,net,org" className="h-9 text-sm" />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">每个前缀抓取数量</label>
                      <Input type="number" min={10} max={500} value={settings.expireddomains_rows}
                        onChange={e => setSettings(s => ({ ...s, expireddomains_rows: e.target.value }))}
                        className="h-9 text-sm" />
                    </div>
                  </div>

                  <Button
                    size="sm"
                    onClick={async () => { await handleSaveSettings(); handleCrawlAllPrefixes(); }}
                    disabled={crawling || !prefixList.length}
                    className="gap-1.5 bg-emerald-600 hover:bg-emerald-700 text-white"
                  >
                    {crawling
                      ? <><RiLoader4Line className="w-4 h-4 animate-spin" />抓取中…</>
                      : <><RiScanLine className="w-4 h-4" />保存并抓取全部前缀 ({prefixList.length})</>
                    }
                  </Button>
                </div>
              )}
            </div>

            <div className="flex items-center gap-2 text-xs text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/20 border border-amber-200/60 dark:border-amber-800/30 rounded-xl px-3 py-2">
              <RiAlertLine className="w-4 h-4 shrink-0" />
              账号信息加密存储在数据库中，仅用于登录 expireddomains.net 获取数据
            </div>
            <Button size="sm" variant="outline" onClick={handleSaveSettings} disabled={savingSettings} className="gap-1.5">
              {savingSettings ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiCheckLine className="w-4 h-4" />}
              保存配置
            </Button>
          </div>
        )}

        {/* ── Filter bar ──────────────────────────────────────────────────── */}
        <div className="space-y-2">
          {/* Length chips */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <RiText className="w-3.5 h-3.5" />长度:
            </span>
            {LEN_PRESETS.map(p => (
              <button key={p.value}
                onClick={() => setFilterExactLen(p.value)}
                className={cn(
                  "h-7 px-3 rounded-lg border text-xs font-medium transition-colors",
                  filterExactLen === p.value
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border text-muted-foreground hover:border-primary/40"
                )}>
                {p.label}
              </button>
            ))}
          </div>

          {/* Other filters */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <RiFilterLine className="w-3.5 h-3.5" />筛选:
            </span>
            <Input
              value={filterPrefix}
              onChange={e => setFilterPrefix(e.target.value.toLowerCase())}
              placeholder="前缀 (如: ai)"
              className="h-8 w-24 text-xs font-mono"
            />
            <Input
              value={filterTld}
              onChange={e => setFilterTld(e.target.value.toLowerCase())}
              placeholder="TLD (如: com)"
              className="h-8 w-24 text-xs"
            />
            <div className="flex items-center gap-1">
              <span className="text-xs text-muted-foreground">BL≥</span>
              <Input
                type="number" min={0}
                value={filterMinBl}
                onChange={e => setFilterMinBl(e.target.value)}
                placeholder="0"
                className="h-8 w-16 text-xs"
              />
            </div>
            <button
              onClick={() => setFilterStarred(v => !v)}
              className={cn(
                "h-8 px-3 rounded-lg border text-xs flex items-center gap-1 transition-colors",
                filterStarred
                  ? "border-amber-400 bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300"
                  : "border-border text-muted-foreground hover:border-primary/40"
              )}>
              <RiStarLine className="w-3.5 h-3.5" />收藏
            </button>
            <button
              onClick={() => setFilterUnseen(v => !v)}
              className={cn(
                "h-8 px-3 rounded-lg border text-xs flex items-center gap-1 transition-colors",
                filterUnseen
                  ? "border-primary/60 bg-primary/5 text-primary"
                  : "border-border text-muted-foreground hover:border-primary/40"
              )}>
              <RiEyeOffLine className="w-3.5 h-3.5" />未读
            </button>
            <button
              onClick={() => {
                setFilterExactLen(0); setFilterPrefix(""); setFilterTld("");
                setFilterMinBl(""); setFilterStarred(false); setFilterUnseen(false);
              }}
              className="h-8 px-2 rounded-lg border border-border text-xs text-muted-foreground hover:border-primary/40 flex items-center gap-1">
              <RiCloseLine className="w-3.5 h-3.5" />重置
            </button>
            <button
              onClick={() => loadLeads(page)}
              className="h-8 px-2 rounded-lg border border-border text-xs text-muted-foreground hover:border-primary/40 flex items-center gap-1">
              <RiRefreshLine className="w-3.5 h-3.5" />刷新
            </button>
          </div>

          {/* Sort */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <RiSortAsc className="w-3.5 h-3.5" />排序:
            </span>
            {SORT_OPTIONS.map(s => (
              <button key={s.value}
                onClick={() => setSortMode(s.value)}
                className={cn(
                  "h-7 px-2.5 rounded-lg border text-xs transition-colors",
                  sortMode === s.value
                    ? "border-primary bg-primary/10 text-primary font-medium"
                    : "border-border text-muted-foreground hover:border-primary/40"
                )}>
                {s.label}
              </button>
            ))}
            <span className="text-xs text-muted-foreground ml-2">
              共 <strong className="text-foreground">{total}</strong> 条
              {stats && stats.unseen > 0 && (
                <span className="ml-2 px-1.5 py-0.5 rounded-full bg-primary/10 text-primary text-[10px] font-semibold">
                  {stats.unseen} 未读
                </span>
              )}
            </span>
          </div>
        </div>

        {/* ── Empty state ──────────────────────────────────────────────────── */}
        {!loading && total === 0 && (
          <div className="rounded-2xl border border-dashed border-border p-12 text-center">
            <RiGlobalLine className="w-10 h-10 text-muted-foreground/30 mx-auto mb-3" />
            <p className="text-sm font-medium text-muted-foreground">还没有过期域名数据</p>
            <p className="text-xs text-muted-foreground/70 mt-1">配置账号信息后点击「抓取设置」开始获取</p>
            <Button size="sm" className="mt-4 gap-1.5" onClick={() => setShowSettings(true)}>
              <RiSettings4Line className="w-4 h-4" />打开配置
            </Button>
          </div>
        )}

        {/* ── Domain table ─────────────────────────────────────────────────── */}
        {(leads.length > 0 || loading) && (
          <div className="rounded-2xl border border-border overflow-hidden">
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border bg-muted/30">
                      <th className="text-left px-4 py-2.5 text-xs font-semibold text-muted-foreground">域名</th>
                      <th className="text-center px-3 py-2.5 text-xs font-semibold text-muted-foreground w-14">长度</th>
                      <th className="text-center px-3 py-2.5 text-xs font-semibold text-muted-foreground w-16">
                        <span className="flex items-center justify-center gap-1"><RiLink className="w-3 h-3" />BL</span>
                      </th>
                      <th className="text-center px-3 py-2.5 text-xs font-semibold text-muted-foreground w-16">
                        <span className="flex items-center justify-center gap-1"><RiSpeedLine className="w-3 h-3" />DP</span>
                      </th>
                      <th className="text-center px-3 py-2.5 text-xs font-semibold text-muted-foreground hidden md:table-cell">删除日期</th>
                      <th className="text-center px-3 py-2.5 text-xs font-semibold text-muted-foreground hidden md:table-cell">可用日期</th>
                      <th className="text-center px-3 py-2.5 text-xs font-semibold text-muted-foreground hidden sm:table-cell">抓取</th>
                      <th className="text-center px-3 py-2.5 text-xs font-semibold text-muted-foreground">操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {leads.map(lead => (
                      <tr
                        key={lead.id}
                        className={cn(
                          "border-b border-border/50 hover:bg-muted/20 transition-colors cursor-pointer",
                          !lead.seen && "bg-primary/[0.02]",
                          lead.starred && "bg-amber-50/60 dark:bg-amber-950/10",
                        )}
                        onClick={() => { if (!lead.seen) patchLead(lead.id, { seen: true }); }}
                      >
                        <td className="px-4 py-2.5">
                          <div className="flex items-center gap-1.5">
                            {!lead.seen && <span className="w-1.5 h-1.5 rounded-full bg-primary shrink-0" />}
                            <span className="font-mono font-bold text-sm">{lead.sld}</span>
                            <span className="text-muted-foreground text-xs">.{lead.tld}</span>
                          </div>
                          {lead.notes && (
                            <p className="text-[11px] text-muted-foreground mt-0.5 truncate max-w-[180px]">{lead.notes}</p>
                          )}
                        </td>
                        <td className="px-3 py-2.5 text-center">
                          <span className={cn(
                            "text-xs font-bold px-2 py-0.5 rounded-full",
                            lead.char_count === 1 ? "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400" :
                            lead.char_count === 2 ? "bg-orange-100 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400" :
                            lead.char_count === 3 ? "bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400" :
                            "bg-muted text-muted-foreground",
                          )}>
                            {lead.char_count}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 text-center">
                          {lead.bl !== null ? (
                            <span className={cn("text-xs font-medium",
                              lead.bl >= 1000 ? "text-emerald-600 dark:text-emerald-400" :
                              lead.bl >= 100  ? "text-primary" : "text-muted-foreground"
                            )}>
                              {lead.bl >= 10000 ? `${(lead.bl / 1000).toFixed(0)}k` : lead.bl.toLocaleString()}
                            </span>
                          ) : <span className="text-muted-foreground/40 text-xs">—</span>}
                        </td>
                        <td className="px-3 py-2.5 text-center text-xs text-muted-foreground">
                          {lead.dp ?? <span className="opacity-40">—</span>}
                        </td>
                        <td className="px-3 py-2.5 text-center text-xs text-muted-foreground hidden md:table-cell">
                          {lead.deleted_date ?? "—"}
                        </td>
                        <td className="px-3 py-2.5 text-center text-xs text-muted-foreground hidden md:table-cell">
                          {lead.available_date ?? "—"}
                        </td>
                        <td className="px-3 py-2.5 text-center text-xs text-muted-foreground hidden sm:table-cell">
                          {timeSince(lead.crawled_at)}
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="flex items-center justify-center gap-0.5" onClick={e => e.stopPropagation()}>
                            <button
                              onClick={() => patchLead(lead.id, { starred: !lead.starred })}
                              className={cn("p-1.5 rounded-lg hover:bg-muted transition-colors",
                                lead.starred ? "text-amber-500" : "text-muted-foreground")}
                              title={lead.starred ? "取消收藏" : "收藏"}>
                              {lead.starred ? <RiStarFill className="w-3.5 h-3.5" /> : <RiStarLine className="w-3.5 h-3.5" />}
                            </button>
                            <a href={`/${lead.domain}`} target="_blank" rel="noopener noreferrer"
                              className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground" title="WHOIS 查询">
                              <RiSearchLine className="w-3.5 h-3.5" />
                            </a>
                            <a href={`https://member.expireddomains.net/domains/combinedexpired/?q=${encodeURIComponent(lead.domain)}&searchby=domainname`}
                              target="_blank" rel="noopener noreferrer"
                              className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground" title="在 expireddomains.net 查看">
                              <RiExternalLinkLine className="w-3.5 h-3.5" />
                            </a>
                            <button
                              onClick={() => patchLead(lead.id, { seen: !lead.seen })}
                              className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground"
                              title={lead.seen ? "标为未读" : "标为已读"}>
                              {lead.seen ? <RiEyeOffLine className="w-3.5 h-3.5" /> : <RiEyeLine className="w-3.5 h-3.5" />}
                            </button>
                            <button
                              onClick={() => deleteLead(lead.id)}
                              className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/20 hover:text-red-500 transition-colors text-muted-foreground"
                              title="删除">
                              <RiDeleteBin2Line className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ── Pagination ───────────────────────────────────────────────────── */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">第 {page} / {totalPages} 页</span>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" disabled={page <= 1}
                onClick={() => setPage(p => Math.max(1, p - 1))} className="gap-1">
                <RiArrowLeftLine className="w-3.5 h-3.5" />上一页
              </Button>
              <Button variant="outline" size="sm" disabled={page >= totalPages}
                onClick={() => setPage(p => Math.min(totalPages, p + 1))} className="gap-1">
                下一页<RiArrowRightLine className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        )}

        {/* ── Info box ─────────────────────────────────────────────────────── */}
        <div className="rounded-xl bg-muted/40 border border-border p-4 text-xs text-muted-foreground space-y-1.5">
          <div className="flex items-center gap-1.5 font-medium text-foreground">
            <RiInformationLine className="w-4 h-4" />使用说明
          </div>
          <ul className="space-y-1 list-disc list-inside leading-relaxed">
            <li>需要 <a href="https://member.expireddomains.net" target="_blank" rel="noopener" className="text-primary underline-offset-2 hover:underline">expireddomains.net</a> 免费会员账号</li>
            <li><strong>按长度抓取</strong>：指定 SLD 字符数范围，适合挖掘单/双/三字符短域名</li>
            <li><strong>按前缀抓取</strong>：如「ai」→ 抓取所有以 ai 开头的域名，结果按外链数量排序，找高价值 AI 域名神器</li>
            <li>BL = 外链数（越高越有历史权重）；DP = 域名流行度（越高曝光越多）</li>
            <li>点击表格行标为已读；🌟 收藏；🔍 查 WHOIS；🔗 跳转 expireddomains.net</li>
          </ul>
        </div>
      </div>
    </AdminLayout>
  );
}

export async function getServerSideProps() { return { props: {} }; }
