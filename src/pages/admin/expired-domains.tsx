/**
 * /admin/expired-domains
 * Crawl expireddomains.net for short/high-value expired domain leads.
 */
import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiRefreshLine, RiSearchLine, RiDeleteBin2Line,
  RiStarLine, RiStarFill, RiExternalLinkLine, RiEyeLine, RiSettings4Line,
  RiGlobalLine, RiScanLine, RiFilterLine, RiCheckLine, RiDeleteBinLine,
  RiArrowLeftLine, RiArrowRightLine, RiDownloadLine, RiAlertLine,
  RiEyeOffLine, RiInformationLine,
} from "@remixicon/react";

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

type Settings = {
  expireddomains_username: string;
  expireddomains_password: string;
  expireddomains_max_length: string;
  expireddomains_min_length: string;
  expireddomains_tld_filter: string;
  expireddomains_rows: string;
};

const DEFAULT_SETTINGS: Settings = {
  expireddomains_username: "",
  expireddomains_password: "",
  expireddomains_max_length: "4",
  expireddomains_min_length: "1",
  expireddomains_tld_filter: "",
  expireddomains_rows: "100",
};

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

export default function ExpiredDomainsPage() {
  const [leads, setLeads]               = React.useState<Lead[]>([]);
  const [total, setTotal]               = React.useState(0);
  const [page, setPage]                 = React.useState(1);
  const [loading, setLoading]           = React.useState(true);
  const [crawling, setCrawling]         = React.useState(false);
  const [showSettings, setShowSettings] = React.useState(false);
  const [settings, setSettings]         = React.useState<Settings>(DEFAULT_SETTINGS);
  const [savingSettings, setSavingSettings] = React.useState(false);

  // Filters
  const [filterMaxLen, setFilterMaxLen] = React.useState("");
  const [filterTld, setFilterTld]       = React.useState("");
  const [filterStarred, setFilterStarred] = React.useState(false);
  const [filterUnseen, setFilterUnseen]   = React.useState(false);

  const LIMIT = 50;

  // ── Load settings ──────────────────────────────────────────────────────────
  React.useEffect(() => {
    fetch("/api/admin/settings")
      .then(r => r.json())
      .then(d => {
        const s = d.settings ?? {};
        setSettings({
          expireddomains_username: s.expireddomains_username ?? "",
          expireddomains_password: s.expireddomains_password ?? "",
          expireddomains_max_length: s.expireddomains_max_length ?? "4",
          expireddomains_min_length: s.expireddomains_min_length ?? "1",
          expireddomains_tld_filter: s.expireddomains_tld_filter ?? "",
          expireddomains_rows: s.expireddomains_rows ?? "100",
        });
      })
      .catch(() => {});
  }, []);

  // ── Load leads ─────────────────────────────────────────────────────────────
  const loadLeads = React.useCallback(async (p = page) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: String(p), limit: String(LIMIT) });
      if (filterMaxLen) params.set("maxLen", filterMaxLen);
      if (filterTld)    params.set("tld", filterTld);
      if (filterStarred) params.set("starred", "1");
      if (filterUnseen)  params.set("unseen", "1");
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
  }, [page, filterMaxLen, filterTld, filterStarred, filterUnseen]);

  React.useEffect(() => { loadLeads(page); }, [page, filterMaxLen, filterTld, filterStarred, filterUnseen]);

  // ── Crawl ──────────────────────────────────────────────────────────────────
  async function handleCrawl() {
    if (crawling) return;
    if (!settings.expireddomains_username || !settings.expireddomains_password) {
      setShowSettings(true);
      toast.error("请先填写 expireddomains.net 账号信息");
      return;
    }
    setCrawling(true);
    try {
      const r = await fetch("/api/admin/expired-domains-crawl?action=crawl", { method: "POST" });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "抓取失败");
      toast.success(`抓取完成：新增 ${d.inserted} 条，更新 ${d.skipped} 条`);
      setPage(1);
      loadLeads(1);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setCrawling(false);
    }
  }

  // ── Save settings ──────────────────────────────────────────────────────────
  async function handleSaveSettings() {
    setSavingSettings(true);
    try {
      const r = await fetch("/api/admin/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ settings }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "保存失败");
      toast.success("配置已保存");
      setShowSettings(false);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setSavingSettings(false);
    }
  }

  // ── Update lead ────────────────────────────────────────────────────────────
  async function patchLead(id: number, updates: Partial<Pick<Lead, "seen" | "starred" | "notes">>) {
    setLeads(prev => prev.map(l => l.id === id ? { ...l, ...updates } : l));
    try {
      await fetch("/api/admin/expired-domains-crawl", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, ...updates }),
      });
    } catch {
      loadLeads(page);
    }
  }

  // ── Delete lead ────────────────────────────────────────────────────────────
  async function deleteLead(id: number) {
    setLeads(prev => prev.filter(l => l.id !== id));
    setTotal(t => t - 1);
    await fetch(`/api/admin/expired-domains-crawl?id=${id}`, { method: "DELETE" }).catch(() => {});
  }

  // ── Clear all ──────────────────────────────────────────────────────────────
  async function clearAll() {
    if (!confirm("确定清空所有过期域名数据？此操作不可撤销")) return;
    await fetch("/api/admin/expired-domains-crawl?action=clear", { method: "DELETE" });
    setLeads([]);
    setTotal(0);
    toast.success("已清空");
  }

  const totalPages = Math.ceil(total / LIMIT);
  const unseenCount = leads.filter(l => !l.seen).length;

  return (
    <AdminLayout>
      <div className="space-y-6">

        {/* Header */}
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              <RiGlobalLine className="w-5 h-5 text-emerald-500" />
              过期域名挖掘
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              从 expireddomains.net 自动抓取短字符、高价值过期可注册域名
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Button
              variant="outline" size="sm"
              onClick={() => setShowSettings(v => !v)}
              className="gap-1.5"
            >
              <RiSettings4Line className="w-4 h-4" />
              {showSettings ? "关闭配置" : "抓取设置"}
            </Button>
            {total > 0 && (
              <Button variant="outline" size="sm" onClick={clearAll} className="gap-1.5 text-red-500 hover:text-red-600 border-red-200 hover:border-red-300">
                <RiDeleteBinLine className="w-4 h-4" />
                清空数据
              </Button>
            )}
            <Button
              size="sm"
              onClick={handleCrawl}
              disabled={crawling}
              className="gap-1.5 bg-emerald-600 hover:bg-emerald-700 text-white"
            >
              {crawling
                ? <><RiLoader4Line className="w-4 h-4 animate-spin" />抓取中…</>
                : <><RiScanLine className="w-4 h-4" />立即抓取</>
              }
            </Button>
          </div>
        </div>

        {/* Settings Panel */}
        {showSettings && (
          <div className="rounded-2xl border border-border bg-card p-5 space-y-4">
            <h2 className="text-sm font-semibold flex items-center gap-2">
              <RiSettings4Line className="w-4 h-4 text-primary" />
              expireddomains.net 账号与抓取参数
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground">用户名</label>
                <Input
                  value={settings.expireddomains_username}
                  onChange={e => setSettings(s => ({ ...s, expireddomains_username: e.target.value }))}
                  placeholder="expireddomains.net 用户名"
                  className="h-9 text-sm"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground">密码</label>
                <Input
                  type="password"
                  value={settings.expireddomains_password}
                  onChange={e => setSettings(s => ({ ...s, expireddomains_password: e.target.value }))}
                  placeholder="expireddomains.net 密码"
                  className="h-9 text-sm"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground">最短字符数 (SLD)</label>
                <Input
                  type="number" min={1} max={10}
                  value={settings.expireddomains_min_length}
                  onChange={e => setSettings(s => ({ ...s, expireddomains_min_length: e.target.value }))}
                  className="h-9 text-sm"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground">最长字符数 (SLD)</label>
                <Input
                  type="number" min={1} max={20}
                  value={settings.expireddomains_max_length}
                  onChange={e => setSettings(s => ({ ...s, expireddomains_max_length: e.target.value }))}
                  className="h-9 text-sm"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground">仅限 TLD（留空=全部，多个用逗号分隔）</label>
                <Input
                  value={settings.expireddomains_tld_filter}
                  onChange={e => setSettings(s => ({ ...s, expireddomains_tld_filter: e.target.value }))}
                  placeholder="例如: com,net,org"
                  className="h-9 text-sm"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground">每次抓取数量（最多 500）</label>
                <Input
                  type="number" min={10} max={500}
                  value={settings.expireddomains_rows}
                  onChange={e => setSettings(s => ({ ...s, expireddomains_rows: e.target.value }))}
                  className="h-9 text-sm"
                />
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/20 border border-amber-200/60 dark:border-amber-800/30 rounded-xl px-3 py-2">
              <RiAlertLine className="w-4 h-4 shrink-0" />
              账号信息加密存储在数据库中，仅用于登录 expireddomains.net 获取数据
            </div>
            <Button size="sm" onClick={handleSaveSettings} disabled={savingSettings} className="gap-1.5">
              {savingSettings ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiCheckLine className="w-4 h-4" />}
              保存配置
            </Button>
          </div>
        )}

        {/* Stats bar */}
        {total > 0 && (
          <div className="flex items-center gap-4 text-sm text-muted-foreground flex-wrap">
            <span>共 <strong className="text-foreground">{total}</strong> 条记录</span>
            {unseenCount > 0 && (
              <span className="px-2 py-0.5 rounded-full bg-primary/10 text-primary text-xs font-semibold">
                {unseenCount} 条未读
              </span>
            )}
          </div>
        )}

        {/* Filters */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <RiFilterLine className="w-3.5 h-3.5" />筛选:
          </div>
          <Input
            value={filterMaxLen}
            onChange={e => { setFilterMaxLen(e.target.value); setPage(1); }}
            placeholder="最长字符 (如: 3)"
            className="h-8 w-28 text-xs"
          />
          <Input
            value={filterTld}
            onChange={e => { setFilterTld(e.target.value.toLowerCase()); setPage(1); }}
            placeholder="TLD (如: com)"
            className="h-8 w-28 text-xs"
          />
          <button
            onClick={() => { setFilterStarred(v => !v); setPage(1); }}
            className={cn(
              "h-8 px-3 rounded-lg border text-xs flex items-center gap-1 transition-colors",
              filterStarred ? "border-amber-400 bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300" : "border-border text-muted-foreground hover:border-primary/40"
            )}
          >
            <RiStarLine className="w-3.5 h-3.5" />已收藏
          </button>
          <button
            onClick={() => { setFilterUnseen(v => !v); setPage(1); }}
            className={cn(
              "h-8 px-3 rounded-lg border text-xs flex items-center gap-1 transition-colors",
              filterUnseen ? "border-primary/60 bg-primary/5 text-primary" : "border-border text-muted-foreground hover:border-primary/40"
            )}
          >
            <RiEyeOffLine className="w-3.5 h-3.5" />未读
          </button>
          <button
            onClick={() => loadLeads(page)}
            className="h-8 px-3 rounded-lg border border-border text-xs text-muted-foreground hover:border-primary/40 flex items-center gap-1"
          >
            <RiRefreshLine className="w-3.5 h-3.5" />刷新
          </button>
        </div>

        {/* Empty state */}
        {!loading && total === 0 && (
          <div className="rounded-2xl border border-dashed border-border p-12 text-center">
            <RiGlobalLine className="w-10 h-10 text-muted-foreground/30 mx-auto mb-3" />
            <p className="text-sm font-medium text-muted-foreground">还没有过期域名数据</p>
            <p className="text-xs text-muted-foreground/70 mt-1">配置账号信息后点击「立即抓取」开始获取</p>
            <Button size="sm" className="mt-4 gap-1.5" onClick={() => setShowSettings(true)}>
              <RiSettings4Line className="w-4 h-4" />配置账号
            </Button>
          </div>
        )}

        {/* Domain table */}
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
                      <th className="text-center px-3 py-2.5 text-xs font-semibold text-muted-foreground">长度</th>
                      <th className="text-center px-3 py-2.5 text-xs font-semibold text-muted-foreground">BL</th>
                      <th className="text-center px-3 py-2.5 text-xs font-semibold text-muted-foreground">DP</th>
                      <th className="text-center px-3 py-2.5 text-xs font-semibold text-muted-foreground">删除日期</th>
                      <th className="text-center px-3 py-2.5 text-xs font-semibold text-muted-foreground">可用日期</th>
                      <th className="text-center px-3 py-2.5 text-xs font-semibold text-muted-foreground">更新</th>
                      <th className="text-center px-3 py-2.5 text-xs font-semibold text-muted-foreground">操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {leads.map(lead => (
                      <tr
                        key={lead.id}
                        className={cn(
                          "border-b border-border/50 hover:bg-muted/20 transition-colors",
                          !lead.seen && "bg-primary/3",
                          lead.starred && "bg-amber-50/50 dark:bg-amber-950/10",
                        )}
                        onClick={() => { if (!lead.seen) patchLead(lead.id, { seen: true }); }}
                      >
                        <td className="px-4 py-2.5">
                          <div className="flex items-center gap-2">
                            {!lead.seen && (
                              <span className="w-1.5 h-1.5 rounded-full bg-primary shrink-0" />
                            )}
                            <span className="font-mono font-semibold text-sm">{lead.domain}</span>
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                              .{lead.tld}
                            </span>
                          </div>
                          {lead.notes && (
                            <p className="text-[11px] text-muted-foreground mt-0.5 truncate max-w-xs">{lead.notes}</p>
                          )}
                        </td>
                        <td className="px-3 py-2.5 text-center">
                          <span className={cn(
                            "text-xs font-bold px-2 py-0.5 rounded-full",
                            lead.char_count === 1 ? "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400" :
                            lead.char_count <= 2 ? "bg-orange-100 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400" :
                            lead.char_count <= 3 ? "bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400" :
                            "bg-muted text-muted-foreground",
                          )}>
                            {lead.char_count}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 text-center text-xs text-muted-foreground">
                          {lead.bl !== null ? lead.bl.toLocaleString() : "—"}
                        </td>
                        <td className="px-3 py-2.5 text-center text-xs text-muted-foreground">
                          {lead.dp !== null ? lead.dp : "—"}
                        </td>
                        <td className="px-3 py-2.5 text-center text-xs text-muted-foreground">{lead.deleted_date ?? "—"}</td>
                        <td className="px-3 py-2.5 text-center text-xs text-muted-foreground">{lead.available_date ?? "—"}</td>
                        <td className="px-3 py-2.5 text-center text-xs text-muted-foreground">{timeSince(lead.crawled_at)}</td>
                        <td className="px-3 py-2.5">
                          <div className="flex items-center justify-center gap-1" onClick={e => e.stopPropagation()}>
                            {/* Star */}
                            <button
                              onClick={() => patchLead(lead.id, { starred: !lead.starred })}
                              className={cn(
                                "p-1.5 rounded-lg hover:bg-muted transition-colors",
                                lead.starred ? "text-amber-500" : "text-muted-foreground"
                              )}
                              title={lead.starred ? "取消收藏" : "收藏"}
                            >
                              {lead.starred ? <RiStarFill className="w-3.5 h-3.5" /> : <RiStarLine className="w-3.5 h-3.5" />}
                            </button>
                            {/* WHOIS lookup on our site */}
                            <a
                              href={`/${lead.domain}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground"
                              title="WHOIS 查询"
                            >
                              <RiSearchLine className="w-3.5 h-3.5" />
                            </a>
                            {/* expireddomains.net link */}
                            <a
                              href={`https://member.expireddomains.net/domains/combinedexpired/?q=${encodeURIComponent(lead.domain)}&searchby=domainname`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground"
                              title="在 expireddomains.net 查看"
                            >
                              <RiExternalLinkLine className="w-3.5 h-3.5" />
                            </a>
                            {/* Mark seen */}
                            <button
                              onClick={() => patchLead(lead.id, { seen: !lead.seen })}
                              className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground"
                              title={lead.seen ? "标记为未读" : "标记为已读"}
                            >
                              {lead.seen ? <RiEyeOffLine className="w-3.5 h-3.5" /> : <RiEyeLine className="w-3.5 h-3.5" />}
                            </button>
                            {/* Delete */}
                            <button
                              onClick={() => deleteLead(lead.id)}
                              className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/20 hover:text-red-500 transition-colors text-muted-foreground"
                              title="删除"
                            >
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

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">
              第 {page} / {totalPages} 页，共 {total} 条
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline" size="sm"
                disabled={page <= 1}
                onClick={() => setPage(p => Math.max(1, p - 1))}
                className="gap-1"
              >
                <RiArrowLeftLine className="w-3.5 h-3.5" />上一页
              </Button>
              <Button
                variant="outline" size="sm"
                disabled={page >= totalPages}
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                className="gap-1"
              >
                下一页<RiArrowRightLine className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        )}

        {/* Info box */}
        <div className="rounded-xl bg-muted/40 border border-border p-4 text-xs text-muted-foreground space-y-1.5">
          <div className="flex items-center gap-1.5 font-medium text-foreground">
            <RiInformationLine className="w-4 h-4" />使用说明
          </div>
          <ul className="space-y-1 list-disc list-inside">
            <li>需要 <a href="https://member.expireddomains.net" target="_blank" rel="noopener noreferrer" className="text-primary underline-offset-2 hover:underline">expireddomains.net</a> 会员账号（免费注册）</li>
            <li>默认抓取长度 1–4 字符的 SLD，排序按域名长度升序（最短优先）</li>
            <li>BL = 外链数量，DP = 域名流行度，数值越高越有价值</li>
            <li>点击任意行标记为已读，星形按钮收藏，🔍 按钮跳转本站 WHOIS 查询</li>
            <li>抓取结果自动去重（同一域名只保留最新数据）</li>
          </ul>
        </div>
      </div>
    </AdminLayout>
  );
}

export async function getServerSideProps() { return { props: {} }; }
