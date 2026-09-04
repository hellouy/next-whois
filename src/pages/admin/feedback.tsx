import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiSearchLine, RiDeleteBinLine,
  RiFeedbackLine, RiMailLine, RiCalendarLine,
  RiFilterLine, RiReplyLine, RiAlertLine, RiCloseLine,
  RiFileCopyLine, RiExternalLinkLine,
  RiCheckboxCircleLine, RiCheckboxBlankCircleLine,
} from "@remixicon/react";

type FeedbackItem = {
  id: string;
  query: string;
  query_type: string | null;
  issue_types: string;
  description: string | null;
  email: string | null;
  created_at: string;
  handled: boolean;
  handled_at: string | null;
};

const ISSUE_META: Record<string, { label: string; color: string; dot: string }> = {
  inaccurate:  { label: "数据不准确",  color: "bg-red-100 dark:bg-red-950/30 text-red-600 dark:text-red-400",         dot: "bg-red-500" },
  incomplete:  { label: "数据不完整",  color: "bg-orange-100 dark:bg-orange-950/30 text-orange-600 dark:text-orange-400", dot: "bg-orange-500" },
  outdated:    { label: "数据已过期",  color: "bg-yellow-100 dark:bg-yellow-950/30 text-yellow-600 dark:text-yellow-400", dot: "bg-yellow-500" },
  parse_error: { label: "解析错误",    color: "bg-blue-100 dark:bg-blue-950/30 text-blue-600 dark:text-blue-400",      dot: "bg-blue-500" },
  other:       { label: "其他",        color: "bg-muted text-muted-foreground",                                         dot: "bg-muted-foreground/50" },
};

const FILTER_TABS: { key: string; label: string }[] = [
  { key: "", label: "全部" },
  { key: "inaccurate",  label: "数据不准确" },
  { key: "incomplete",  label: "数据不完整" },
  { key: "outdated",    label: "数据已过期" },
  { key: "parse_error", label: "解析错误" },
  { key: "other",       label: "其他" },
];

export default function AdminFeedbackPage() {
  const [items, setItems] = React.useState<FeedbackItem[]>([]);
  const [total, setTotal] = React.useState(0);
  const [typeCounts, setTypeCounts] = React.useState<Record<string, number>>({});
  const [search, setSearch] = React.useState("");
  const [activeType, setActiveType] = React.useState("");
  const [activeHandled, setActiveHandled] = React.useState<"" | "false" | "true">("");
  const [loading, setLoading] = React.useState(false);
  const [deleting, setDeleting] = React.useState<string | null>(null);
  const [expanded, setExpanded] = React.useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = React.useState<string | null>(null);
  const pendingDeleteTimer = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  const PAGE_SIZE = 30;
  const [offset, setOffset] = React.useState(0);
  const [loadingMore, setLoadingMore] = React.useState(false);

  function load(q: string, type: string, append = false, off = 0, handled: "" | "false" | "true" = "") {
    if (append) setLoadingMore(true); else setLoading(true);
    const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(off) });
    if (q) params.set("search", q);
    if (type) params.set("issue_type", type);
    if (handled) params.set("handled", handled);
    fetch(`/api/admin/feedback?${params}`)
      .then(r => r.json())
      .then(data => {
        if (data.error) toast.error(data.error);
        else {
          if (append) {
            setItems(prev => [...prev, ...(data.feedback || [])]);
          } else {
            setItems(data.feedback || []);
            if (data.typeCounts) setTypeCounts(data.typeCounts);
          }
          setTotal(data.total || 0);
        }
      })
      .catch(() => toast.error("加载失败"))
      .finally(() => { if (append) setLoadingMore(false); else setLoading(false); });
  }

  React.useEffect(() => { setOffset(0); load("", ""); }, []);

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setOffset(0);
    load(search, activeType, false, 0, activeHandled);
  }

  function selectType(type: string) {
    setActiveType(type);
    setOffset(0);
    load(search, type, false, 0, activeHandled);
  }

  function selectHandled(h: "" | "false" | "true") {
    setActiveHandled(h);
    setOffset(0);
    load(search, activeType, false, 0, h);
  }

  function loadMore() {
    const newOffset = offset + PAGE_SIZE;
    setOffset(newOffset);
    load(search, activeType, true, newOffset, activeHandled);
  }

  function requestDelete(id: string) {
    if (pendingDelete === id) {
      if (pendingDeleteTimer.current) clearTimeout(pendingDeleteTimer.current);
      setPendingDelete(null);
      executeDelete(id);
    } else {
      setPendingDelete(id);
      if (pendingDeleteTimer.current) clearTimeout(pendingDeleteTimer.current);
      pendingDeleteTimer.current = setTimeout(() => setPendingDelete(null), 4000);
    }
  }

  async function executeDelete(id: string) {
    setDeleting(id);
    try {
      const res = await fetch(`/api/admin/feedback?id=${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error((await res.json()).error);
      setItems(prev => prev.filter(f => f.id !== id));
      setTotal(prev => prev - 1);
      toast.success("反馈已删除");
    } catch (e: any) {
      toast.error(e.message || "删除失败");
    } finally {
      setDeleting(null);
    }
  }

  const [togglingHandled, setTogglingHandled] = React.useState<string | null>(null);

  async function toggleHandled(item: FeedbackItem) {
    setTogglingHandled(item.id);
    try {
      const newHandled = !item.handled;
      const res = await fetch(`/api/admin/feedback?id=${item.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ handled: newHandled }),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      setItems(prev => prev.map(f => f.id === item.id
        ? { ...f, handled: newHandled, handled_at: newHandled ? new Date().toISOString() : null }
        : f
      ));
      toast.success(newHandled ? "已标记为已处理" : "已取消处理标记");
    } catch (e: any) {
      toast.error(e.message || "操作失败");
    } finally {
      setTogglingHandled(null);
    }
  }

  function buildMailtoReply(item: FeedbackItem): string {
    const subject = encodeURIComponent(`关于您反馈的域名 ${item.query}`);
    const body = encodeURIComponent(`您好，\n\n感谢您反馈了关于域名 ${item.query} 的问题。\n\n`);
    return `mailto:${item.email}?subject=${subject}&body=${body}`;
  }

  function fmt(d: string) {
    return new Date(d).toLocaleString("zh-CN", {
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit",
    });
  }

  function parseIssues(raw: string): string[] {
    try { return JSON.parse(raw); } catch { return raw ? [raw] : []; }
  }

  const grandTotal = Object.values(typeCounts).reduce((a, b) => a + b, 0) || total;

  return (
    <AdminLayout title="用户反馈">
      <div className="space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h2 className="text-lg font-bold">用户反馈</h2>
            <p className="text-xs text-muted-foreground mt-0.5">共 {total.toLocaleString()} 条记录</p>
          </div>
          <form onSubmit={handleSearch} className="flex items-center gap-2">
            <div className="relative">
              <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/60" />
              <Input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="搜索查询、邮箱或描述…"
                className="pl-8 h-9 rounded-xl text-sm w-52"
              />
            </div>
            <Button type="submit" size="sm" className="h-9 rounded-xl px-4">搜索</Button>
          </form>
        </div>

        {/* Stats bar */}
        {grandTotal > 0 && (
          <div className="grid grid-cols-3 sm:grid-cols-5 gap-2">
            {(["inaccurate", "incomplete", "outdated", "parse_error", "other"] as const).map(key => {
              const meta = ISSUE_META[key];
              const count = typeCounts[key] ?? 0;
              const pct = grandTotal > 0 ? Math.round((count / grandTotal) * 100) : 0;
              return (
                <button
                  key={key}
                  onClick={() => selectType(activeType === key ? "" : key)}
                  className={cn(
                    "glass-panel border rounded-xl p-3 text-left transition-all hover:border-primary/30",
                    activeType === key ? "border-primary/50 bg-primary/5" : "border-border"
                  )}
                >
                  <div className="flex items-center gap-1.5 mb-1">
                    <span className={cn("w-2 h-2 rounded-full shrink-0", meta.dot)} />
                    <span className="text-[10px] font-semibold text-muted-foreground truncate">{meta.label}</span>
                  </div>
                  <p className="text-xl font-bold tabular-nums">{count}</p>
                  <p className="text-[10px] text-muted-foreground/60">{pct}%</p>
                </button>
              );
            })}
          </div>
        )}

        {/* Filter tabs — issue type */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <RiFilterLine className="w-3.5 h-3.5 text-muted-foreground/60 shrink-0" />
          {FILTER_TABS.map(tab => (
            <button
              key={tab.key}
              onClick={() => selectType(tab.key)}
              className={cn(
                "text-xs px-3 py-1.5 rounded-full font-medium transition-all",
                activeType === tab.key
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted/60 text-muted-foreground hover:bg-muted hover:text-foreground"
              )}
            >
              {tab.label}
              {tab.key && typeCounts[tab.key] ? (
                <span className={cn("ml-1.5 text-[10px]", activeType === tab.key ? "opacity-70" : "opacity-60")}>
                  {typeCounts[tab.key]}
                </span>
              ) : tab.key === "" && total > 0 ? (
                <span className="ml-1.5 text-[10px] opacity-60">{total}</span>
              ) : null}
            </button>
          ))}
        </div>

        {/* Filter row — handled status */}
        <div className="flex items-center gap-1.5">
          {([ 
            { key: "" as const,       label: "全部状态" },
            { key: "false" as const,  label: "未处理" },
            { key: "true" as const,   label: "已处理" },
          ]).map(opt => (
            <button
              key={opt.key}
              onClick={() => selectHandled(opt.key)}
              className={cn(
                "text-xs px-3 py-1.5 rounded-full font-medium transition-all",
                activeHandled === opt.key
                  ? opt.key === "false"
                    ? "bg-amber-500 text-white"
                    : opt.key === "true"
                      ? "bg-emerald-500 text-white"
                      : "bg-primary text-primary-foreground"
                  : "bg-muted/60 text-muted-foreground hover:bg-muted hover:text-foreground"
              )}
            >
              {opt.label}
            </button>
          ))}
        </div>

        {/* List */}
        {loading ? (
          <div className="flex justify-center py-12">
            <RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : items.length === 0 ? (
          <div className="text-center py-12 space-y-2">
            <RiFeedbackLine className="w-10 h-10 text-muted-foreground/30 mx-auto" />
            <p className="text-sm text-muted-foreground">
              {activeHandled === "false" ? "没有待处理的反馈" : activeHandled === "true" ? "没有已处理的反馈" : activeType ? "该分类暂无反馈记录" : "暂无反馈记录"}
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {items.map(item => {
              const issues = parseIssues(item.issue_types);
              const isExpanded = expanded === item.id;
              return (
                <div key={item.id}
                  className="glass-panel border border-border rounded-xl overflow-hidden group">
                  <button
                    className="w-full p-4 flex items-start gap-3 text-left hover:bg-muted/30 transition-colors"
                    onClick={() => setExpanded(isExpanded ? null : item.id)}
                  >
                    <div className="w-8 h-8 rounded-full bg-gradient-to-br from-pink-500/20 to-rose-500/20 flex items-center justify-center shrink-0 mt-0.5">
                      <RiFeedbackLine className="w-4 h-4 text-pink-500" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs text-muted-foreground uppercase font-medium shrink-0">
                          {item.query_type || "domain"}
                        </span>
                        <p className="text-sm font-semibold font-mono truncate">{item.query}</p>
                      </div>
                      <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
                        {issues.map(issue => {
                          const meta = ISSUE_META[issue] || ISSUE_META.other;
                          return (
                            <span key={issue} className={cn("text-[10px] px-1.5 py-0.5 rounded font-semibold", meta.color)}>
                              {meta.label}
                            </span>
                          );
                        })}
                      </div>
                      <div className="flex items-center gap-3 mt-1 flex-wrap">
                        {item.email && (
                          <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                            <RiMailLine className="w-3 h-3" />{item.email}
                          </span>
                        )}
                        <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                          <RiCalendarLine className="w-3 h-3" />{fmt(item.created_at)}
                        </span>
                      </div>
                    </div>
                    <div
                      className="flex items-center gap-1 shrink-0 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity"
                      onClick={e => e.stopPropagation()}
                    >
                      <button
                        onClick={() => toggleHandled(item)}
                        disabled={togglingHandled === item.id}
                        className={cn(
                          "p-2 rounded-lg transition-colors",
                          item.handled
                            ? "text-emerald-500 hover:bg-emerald-50 dark:hover:bg-emerald-950/20"
                            : "text-muted-foreground hover:bg-emerald-50 dark:hover:bg-emerald-950/20 hover:text-emerald-500"
                        )}
                        title={item.handled ? "取消已处理标记" : "标记为已处理"}
                      >
                        {togglingHandled === item.id
                          ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                          : item.handled
                            ? <RiCheckboxCircleLine className="w-3.5 h-3.5" />
                            : <RiCheckboxBlankCircleLine className="w-3.5 h-3.5" />
                        }
                      </button>
                      {item.email && (
                        <a
                          href={buildMailtoReply(item)}
                          className="p-2 rounded-lg transition-colors text-muted-foreground hover:bg-blue-50 dark:hover:bg-blue-950/20 hover:text-blue-500"
                          title="回复邮件"
                        >
                          <RiReplyLine className="w-3.5 h-3.5" />
                        </a>
                      )}
                      {pendingDelete === item.id ? (
                        <div className="flex items-center gap-1 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 rounded-lg px-1.5 py-1">
                          <RiAlertLine className="w-3 h-3 text-red-500 shrink-0" />
                          <button
                            onClick={() => requestDelete(item.id)}
                            disabled={deleting === item.id}
                            className="text-[10px] text-red-600 dark:text-red-400 font-semibold whitespace-nowrap hover:underline"
                          >
                            确认删除
                          </button>
                          <button onClick={() => setPendingDelete(null)} className="ml-0.5 text-red-300 hover:text-red-500">
                            <RiCloseLine className="w-3 h-3" />
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => requestDelete(item.id)}
                          disabled={deleting === item.id}
                          className="p-2 rounded-lg transition-colors text-muted-foreground hover:bg-red-50 dark:hover:bg-red-950/30 hover:text-red-500"
                          title="删除反馈"
                        >
                          {deleting === item.id
                            ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                            : <RiDeleteBinLine className="w-3.5 h-3.5" />
                          }
                        </button>
                      )}
                    </div>
                  </button>

                  {isExpanded && (
                    <div className="px-4 pb-4 pt-0 border-t border-border/50 space-y-3">
                      {item.description ? (
                        <>
                          <p className="text-xs text-muted-foreground mt-3 mb-1 font-medium">用户描述</p>
                          <p className="text-sm text-foreground/80 bg-muted/30 rounded-xl px-3 py-2 leading-relaxed">
                            {item.description}
                          </p>
                        </>
                      ) : (
                        <p className="text-xs text-muted-foreground mt-3 italic">用户未填写描述</p>
                      )}
                      <div className="flex items-center gap-2 flex-wrap pt-1">
                        <button
                          onClick={() => { navigator.clipboard.writeText(item.query); toast.success("域名已复制"); }}
                          className="flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-all"
                        >
                          <RiFileCopyLine className="w-3 h-3" />复制域名
                        </button>
                        <a
                          href={`https://rdap.org/domain/${item.query}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-all"
                        >
                          <RiExternalLinkLine className="w-3 h-3" />RDAP 查看
                        </a>
                        {item.email && (
                          <a
                            href={buildMailtoReply(item)}
                            className="flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded-lg border border-blue-200 dark:border-blue-800 text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-950/20 transition-all"
                          >
                            <RiReplyLine className="w-3 h-3" />回复 {item.email}
                          </a>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
            {items.length < total && (
              <button
                onClick={loadMore}
                disabled={loadingMore}
                className="w-full py-2.5 text-sm text-muted-foreground border border-dashed border-border rounded-xl hover:bg-muted/40 transition-colors flex items-center justify-center gap-2"
              >
                {loadingMore ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : null}
                {loadingMore ? "加载中…" : `加载更多（已显示 ${items.length} / ${total}）`}
              </button>
            )}
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
