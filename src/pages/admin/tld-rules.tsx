import React from "react";
import Head from "next/head";
import { AdminLayout } from "@/components/admin-layout";
import { PageTabs } from "@/components/page-tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  RiLoader4Line,
  RiSearchLine,
  RiDeleteBinLine,
  RiRefreshLine,
  RiRobot2Line,
  RiExternalLinkLine,
  RiCheckboxCircleLine,
  RiErrorWarningLine,
  RiPlayCircleLine,
  RiStopCircleLine,
  RiTimeLine,
  RiBarChartLine,
  RiGlobalLine,
  RiMapPin2Line,
  RiEditLine,
  RiSaveLine,
  RiCloseLine,
  RiUserLine,
  RiLockLine,
} from "@remixicon/react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import type { CompareRow } from "@/pages/api/admin/tld-lifecycle-compare";

const TLD_TABS = [
  { href: "/admin/tld-lifecycle",          label: "生命周期" },
  { href: "/admin/tld-rules",              label: "TLD 规则" },
  { href: "/admin/tld-fallback",           label: "查询兜底" },
  { href: "/admin/tld-lifecycle-feedback", label: "纠错反馈" },
];

type TldRule = {
  tld: string;
  grace_period_days: number;
  redemption_period_days: number;
  pending_delete_days: number;
  total_release_days: number;
  source_url: string | null;
  confidence: "high" | "ai" | "est";
  drop_hour: number | null;
  drop_minute: number | null;
  drop_second: number | null;
  drop_timezone: string | null;
  pre_expiry_days: number | null;
  scraped_at: string | null;
  updated_at: string;
  model_used: string | null;
  ai_reasoning: string | null;
  manually_edited: boolean;
  scrape_status: "ok" | "warn_defaults" | "failed" | "pending" | "no_data";
  failure_reason: string | null;
  fetch_strategy: string | null;
  scrape_attempts: number;
  needs_admin_review: boolean;
};

type ScrapeStats = {
  total: number;
  ok: number;
  warn_defaults: number;
  failed: number;
  pending: number;
  no_data: number;
  manually_edited: number;
};

type EditForm = {
  grace_period_days: string;
  redemption_period_days: string;
  pending_delete_days: string;
  drop_hour: string;
  drop_minute: string;
  drop_second: string;
  drop_timezone: string;
  pre_expiry_days: string;
  source_url: string;
};

type AiModelInfo = {
  id: string;
  name: string;
  provider: string;
  env_var: string;
  configured: boolean;
  priority: number;
};

// ── ccTLD batch list: all IANA-delegated 2-letter country codes ──────────────
const CC_TLDS: { tld: string }[] = [
  // A
  { tld: "ac" }, { tld: "ad" }, { tld: "ae" }, { tld: "af" }, { tld: "ag" },
  { tld: "ai" }, { tld: "al" }, { tld: "am" }, { tld: "ao" }, { tld: "aq" },
  { tld: "ar" }, { tld: "as" }, { tld: "at" }, { tld: "au" }, { tld: "aw" },
  { tld: "ax" }, { tld: "az" },
  // B
  { tld: "ba" }, { tld: "bb" }, { tld: "bd" }, { tld: "be" }, { tld: "bf" },
  { tld: "bg" }, { tld: "bh" }, { tld: "bi" }, { tld: "bj" }, { tld: "bm" },
  { tld: "bn" }, { tld: "bo" }, { tld: "br" }, { tld: "bs" }, { tld: "bt" },
  { tld: "bw" }, { tld: "by" }, { tld: "bz" },
  // C
  { tld: "ca" }, { tld: "cc" }, { tld: "cd" }, { tld: "cf" }, { tld: "cg" },
  { tld: "ch" }, { tld: "ci" }, { tld: "ck" }, { tld: "cl" }, { tld: "cm" },
  { tld: "cn" }, { tld: "co" }, { tld: "cr" }, { tld: "cu" }, { tld: "cv" },
  { tld: "cw" }, { tld: "cx" }, { tld: "cy" }, { tld: "cz" },
  // D
  { tld: "de" }, { tld: "dj" }, { tld: "dk" }, { tld: "dm" }, { tld: "do" },
  { tld: "dz" },
  // E
  { tld: "ec" }, { tld: "ee" }, { tld: "eg" }, { tld: "er" }, { tld: "es" },
  { tld: "et" }, { tld: "eu" },
  // F
  { tld: "fi" }, { tld: "fj" }, { tld: "fk" }, { tld: "fm" }, { tld: "fo" },
  { tld: "fr" },
  // G
  { tld: "ga" }, { tld: "gd" }, { tld: "ge" }, { tld: "gf" }, { tld: "gg" },
  { tld: "gh" }, { tld: "gi" }, { tld: "gl" }, { tld: "gm" }, { tld: "gn" },
  { tld: "gp" }, { tld: "gq" }, { tld: "gr" }, { tld: "gs" }, { tld: "gt" },
  { tld: "gu" }, { tld: "gw" }, { tld: "gy" },
  // H
  { tld: "hk" }, { tld: "hm" }, { tld: "hn" }, { tld: "hr" }, { tld: "ht" },
  { tld: "hu" },
  // I
  { tld: "id" }, { tld: "ie" }, { tld: "il" }, { tld: "im" }, { tld: "in" },
  { tld: "io" }, { tld: "iq" }, { tld: "ir" }, { tld: "is" }, { tld: "it" },
  // J
  { tld: "je" }, { tld: "jm" }, { tld: "jo" }, { tld: "jp" },
  // K
  { tld: "ke" }, { tld: "kg" }, { tld: "kh" }, { tld: "ki" }, { tld: "km" },
  { tld: "kn" }, { tld: "kp" }, { tld: "kr" }, { tld: "kw" }, { tld: "ky" },
  { tld: "kz" },
  // L
  { tld: "la" }, { tld: "lb" }, { tld: "lc" }, { tld: "li" }, { tld: "lk" },
  { tld: "lr" }, { tld: "ls" }, { tld: "lt" }, { tld: "lu" }, { tld: "lv" },
  { tld: "ly" },
  // M
  { tld: "ma" }, { tld: "mc" }, { tld: "md" }, { tld: "me" }, { tld: "mg" },
  { tld: "mh" }, { tld: "mk" }, { tld: "ml" }, { tld: "mm" }, { tld: "mn" },
  { tld: "mo" }, { tld: "mp" }, { tld: "mq" }, { tld: "mr" }, { tld: "ms" },
  { tld: "mt" }, { tld: "mu" }, { tld: "mv" }, { tld: "mw" }, { tld: "mx" },
  { tld: "my" }, { tld: "mz" },
  // N
  { tld: "na" }, { tld: "nc" }, { tld: "ne" }, { tld: "nf" }, { tld: "ng" },
  { tld: "ni" }, { tld: "nl" }, { tld: "no" }, { tld: "np" }, { tld: "nr" },
  { tld: "nu" }, { tld: "nz" },
  // O
  { tld: "om" },
  // P
  { tld: "pa" }, { tld: "pe" }, { tld: "pf" }, { tld: "pg" }, { tld: "ph" },
  { tld: "pk" }, { tld: "pl" }, { tld: "pm" }, { tld: "pn" }, { tld: "pr" },
  { tld: "ps" }, { tld: "pt" }, { tld: "pw" }, { tld: "py" },
  // Q
  { tld: "qa" },
  // R
  { tld: "re" }, { tld: "ro" }, { tld: "rs" }, { tld: "ru" }, { tld: "rw" },
  // S
  { tld: "sa" }, { tld: "sb" }, { tld: "sc" }, { tld: "sd" }, { tld: "se" },
  { tld: "sg" }, { tld: "sh" }, { tld: "si" }, { tld: "sk" }, { tld: "sl" },
  { tld: "sm" }, { tld: "sn" }, { tld: "so" }, { tld: "sr" }, { tld: "ss" },
  { tld: "st" }, { tld: "su" }, { tld: "sv" }, { tld: "sx" }, { tld: "sy" },
  { tld: "sz" },
  // T
  { tld: "tc" }, { tld: "td" }, { tld: "tf" }, { tld: "tg" }, { tld: "th" },
  { tld: "tj" }, { tld: "tk" }, { tld: "tl" }, { tld: "tm" }, { tld: "tn" },
  { tld: "to" }, { tld: "tr" }, { tld: "tt" }, { tld: "tv" }, { tld: "tw" },
  { tld: "tz" },
  // U
  { tld: "ua" }, { tld: "ug" }, { tld: "uk" }, { tld: "us" }, { tld: "uy" },
  { tld: "uz" },
  // V
  { tld: "va" }, { tld: "vc" }, { tld: "ve" }, { tld: "vg" }, { tld: "vi" },
  { tld: "vn" }, { tld: "vu" },
  // W
  { tld: "wf" }, { tld: "ws" },
  // Y
  { tld: "ye" }, { tld: "yt" },
  // Z
  { tld: "za" }, { tld: "zm" }, { tld: "zw" },
];

// ── gTLD batch list: major generic TLDs from LIFECYCLE_TABLE ─────────────────
const G_TLDS: { tld: string; source_url?: string }[] = [
  // Tier-1
  { tld: "com", source_url: "https://www.verisign.com/en_US/domain-names/com-domain-names/index.xhtml" },
  { tld: "net", source_url: "https://www.verisign.com/en_US/domain-names/com-domain-names/index.xhtml" },
  { tld: "org", source_url: "https://www.pir.org/resources/org-policies/" },
  { tld: "info" }, { tld: "biz" }, { tld: "name" }, { tld: "mobi" }, { tld: "tel" },
  { tld: "pro" }, { tld: "jobs" }, { tld: "travel" }, { tld: "museum" },
  { tld: "coop" }, { tld: "aero" }, { tld: "int" }, { tld: "edu" }, { tld: "gov" },
  { tld: "mil" }, { tld: "xxx" }, { tld: "post" }, { tld: "cat" },
  // Google / popular new gTLDs
  { tld: "app", source_url: "https://get.app/intl/en/domain-information/" },
  { tld: "dev", source_url: "https://get.dev/intl/en/domain-information/" },
  { tld: "page" }, { tld: "zip" }, { tld: "dad" }, { tld: "phd" }, { tld: "nexus" },
  { tld: "web" },
  // Very popular new gTLDs
  { tld: "xyz" }, { tld: "club" }, { tld: "fun" }, { tld: "icu" }, { tld: "top" },
  { tld: "vip" }, { tld: "wiki" }, { tld: "ink" }, { tld: "buzz" }, { tld: "website" },
  { tld: "uno" }, { tld: "bio" }, { tld: "ski" }, { tld: "ltd" }, { tld: "llc" },
  { tld: "srl" }, { tld: "gmbh" }, { tld: "inc" }, { tld: "bar" }, { tld: "fit" },
  { tld: "fan" }, { tld: "bet" }, { tld: "best" }, { tld: "cash" }, { tld: "deal" },
  // Business & professional
  { tld: "shop" }, { tld: "blog" }, { tld: "cloud" }, { tld: "tech" },
  { tld: "online" }, { tld: "site" }, { tld: "store" }, { tld: "live" },
  { tld: "link" }, { tld: "media" }, { tld: "news" }, { tld: "email" },
  { tld: "space" }, { tld: "world" }, { tld: "work" }, { tld: "tools" },
  { tld: "run" }, { tld: "team" }, { tld: "digital" }, { tld: "global" },
  { tld: "network" }, { tld: "host" }, { tld: "studio" }, { tld: "design" },
  { tld: "agency" }, { tld: "group" }, { tld: "plus" }, { tld: "guru" },
  { tld: "expert" }, { tld: "solutions" }, { tld: "systems" }, { tld: "services" },
  { tld: "support" }, { tld: "help" }, { tld: "guide" }, { tld: "review" },
  { tld: "reviews" }, { tld: "social" }, { tld: "photos" }, { tld: "video" },
  { tld: "audio" }, { tld: "music" }, { tld: "art" }, { tld: "gallery" },
  { tld: "sale" }, { tld: "deals" }, { tld: "events" }, { tld: "fashion" },
  { tld: "sport" }, { tld: "health" }, { tld: "care" }, { tld: "yoga" },
  { tld: "finance" }, { tld: "money" }, { tld: "fund" }, { tld: "capital" },
  { tld: "bank" }, { tld: "law" }, { tld: "legal" }, { tld: "academy" },
  { tld: "school" }, { tld: "university" }, { tld: "college" }, { tld: "mba" },
  { tld: "doctor" }, { tld: "dental" }, { tld: "healthcare" }, { tld: "clinic" },
  // Geographic / city
  { tld: "london" }, { tld: "tokyo" }, { tld: "nyc" }, { tld: "paris" },
  { tld: "berlin" }, { tld: "amsterdam" }, { tld: "dubai" }, { tld: "moscow" },
  { tld: "osaka" }, { tld: "nagoya" }, { tld: "yokohama" }, { tld: "vegas" },
  { tld: "miami" }, { tld: "boston" }, { tld: "quebec" }, { tld: "barcelona" },
  { tld: "brussels" }, { tld: "istanbul" }, { tld: "capetown" }, { tld: "rio" },
  { tld: "wien" }, { tld: "koeln" }, { tld: "cologne" }, { tld: "zuerich" },
  { tld: "tirol" }, { tld: "saarland" }, { tld: "nrw" },
  { tld: "wales" }, { tld: "scot" }, { tld: "irish" }, { tld: "eus" },
  { tld: "africa" }, { tld: "arab" }, { tld: "asia" },
  // Amazon registry
  { tld: "free" }, { tld: "fast" }, { tld: "hot" }, { tld: "spot" },
  { tld: "talk" }, { tld: "you" },
];

type BatchStatus = "idle" | "running" | "done";
type BatchItem = {
  tld: string;
  status: "pending" | "ok" | "error" | "skipped";
  msg?: string;
};

type Tab = "cc" | "gtld" | "compare";

type CompareData = {
  total: number;
  scraped: number;
  conflicts: number;
  rows: CompareRow[];
};

export default function AdminTldRulesPage() {
  const [tab, setTab] = React.useState<Tab>("cc");
  const [rules, setRules] = React.useState<TldRule[]>([]);
  const [scrapeStats, setScrapeStats] = React.useState<ScrapeStats | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [search, setSearch] = React.useState("");
  const [scraping, setScraping] = React.useState(false);
  const [deleting, setDeleting] = React.useState<string | null>(null);
  const [form, setForm] = React.useState({ tld: "", source_url: "", force: false });
  const [lastResult, setLastResult] = React.useState<any>(null);

  // Inline edit state
  const [editingTld, setEditingTld] = React.useState<string | null>(null);
  const [editForm, setEditForm] = React.useState<EditForm>({
    grace_period_days: "", redemption_period_days: "", pending_delete_days: "",
    drop_hour: "", drop_minute: "", drop_second: "", drop_timezone: "", pre_expiry_days: "", source_url: "",
  });
  const [saving, setSaving] = React.useState(false);

  // AI model state
  const [aiModels, setAiModels] = React.useState<AiModelInfo[]>([]);
  const [selectedModel, setSelectedModel] = React.useState<string>(""); // "" = auto (priority order)
  const [batchModel, setBatchModel] = React.useState<string>("");

  // Batch state
  const [batchStatus, setBatchStatus] = React.useState<BatchStatus>("idle");
  const [batchItems, setBatchItems] = React.useState<BatchItem[]>([]);
  const [batchIdx, setBatchIdx] = React.useState(0);
  const [batchList, setBatchList] = React.useState<{ tld: string; source_url?: string }[]>([]);
  const batchAbortRef = React.useRef(false);

  // IANA gTLD list (dynamically fetched, 1000+)
  const [ianaGtlds, setIanaGtlds] = React.useState<{ tld: string }[]>([]);
  const [ianaLoading, setIanaLoading] = React.useState(false);
  const [ianaFetchedAt, setIanaFetchedAt] = React.useState<string | null>(null);

  // Compare state
  const [compareData, setCompareData] = React.useState<CompareData | null>(null);
  const [compareLoading, setCompareLoading] = React.useState(false);
  const [compareSearch, setCompareSearch] = React.useState("");
  const [showOnlyConflicts, setShowOnlyConflicts] = React.useState(false);
  const [showOnlyScraped, setShowOnlyScraped] = React.useState(false);
  const [showOnlyDefaults, setShowOnlyDefaults] = React.useState(false);

  async function load() {
    setLoading(true);
    try {
      const res = await fetch("/api/admin/tld-rules");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "加载失败");
      setRules(data.rules ?? []);
      if (data.stats) setScrapeStats(data.stats);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }

  async function loadCompare() {
    setCompareLoading(true);
    try {
      const res = await fetch("/api/admin/tld-lifecycle-compare");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "加载失败");
      setCompareData(data);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "对比数据加载失败");
    } finally {
      setCompareLoading(false);
    }
  }

  React.useEffect(() => { load(); }, []);
  React.useEffect(() => { if (tab === "compare" && !compareData) loadCompare(); }, [tab]);

  // Load AI model list on mount
  React.useEffect(() => {
    fetch("/api/admin/ai-models")
      .then(r => r.json())
      .then(d => { if (d.providers) setAiModels(d.providers); })
      .catch(() => {});
  }, []);

  // Load full IANA gTLD list when gtld tab opens (1000+)
  React.useEffect(() => {
    if (tab !== "gtld" || ianaGtlds.length > 0) return;
    setIanaLoading(true);
    fetch("/api/admin/tld-list")
      .then(r => r.json())
      .then(d => {
        if (d.tlds) {
          setIanaGtlds((d.tlds as string[]).map(t => ({ tld: t })));
          setIanaFetchedAt(d.fetched_at ?? null);
        } else {
          throw new Error(d.error || "加载失败");
        }
      })
      .catch(e => toast.error(`IANA 列表加载失败: ${e.message}`))
      .finally(() => setIanaLoading(false));
  }, [tab]);

  // Export helpers
  function exportAs(format: "json" | "csv") {
    const link = document.createElement("a");
    link.href = `/api/admin/tld-rules?format=${format}`;
    link.download = "";
    link.click();
  }

  async function handleScrape(e: React.FormEvent) {
    e.preventDefault();
    const tld = form.tld.toLowerCase().replace(/^\./, "").trim();
    if (!tld) { toast.error("请填写 TLD"); return; }
    setScraping(true);
    setLastResult(null);
    try {
      const res = await fetch("/api/admin/tld-rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, source_url: form.source_url.trim() || undefined, force: form.force, model: selectedModel || undefined }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "抓取失败");
      if (data.skipped) {
        if (data.reason === "manually_edited") {
          toast.info(`.${tld} 已被手动修改，自动爬取已跳过。勾选"强制重爬"可覆盖并重新抓取。`);
        } else {
          toast.info(`.${tld} 数据仍有效（有效至 ${data.fresh_until?.slice(0,10) ?? "—"}），跳过重爬。勾选"强制重爬"可覆盖。`);
        }
        setLastResult(data);
      } else {
        setLastResult(data);
        toast.success(`.${tld} 规则提取成功！`);
      }
      setForm({ tld: "", source_url: "", force: false });
      load();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "抓取失败";
      toast.error(msg);
      setLastResult({ error: msg });
    } finally {
      setScraping(false);
    }
  }

  async function handleDelete(tld: string) {
    if (!confirm(`确定删除 .${tld} 的规则吗？`)) return;
    setDeleting(tld);
    try {
      const res = await fetch("/api/admin/tld-rules", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "删除失败");
      toast.success(`已删除 .${tld}`);
      load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "删除失败");
    } finally {
      setDeleting(null);
    }
  }

  // ── Inline edit ───────────────────────────────────────────────────────────
  function startEdit(r: TldRule) {
    setEditingTld(r.tld);
    setEditForm({
      grace_period_days: String(r.grace_period_days),
      redemption_period_days: String(r.redemption_period_days),
      pending_delete_days: String(r.pending_delete_days),
      drop_hour: r.drop_hour !== null ? String(r.drop_hour) : "",
      drop_minute: r.drop_minute !== null ? String(r.drop_minute) : "",
      drop_second: r.drop_second !== null ? String(r.drop_second) : "",
      drop_timezone: r.drop_timezone ?? "",
      pre_expiry_days: r.pre_expiry_days !== null ? String(r.pre_expiry_days) : "",
      source_url: r.source_url ?? "",
    });
  }

  async function handleSaveEdit(tld: string) {
    setSaving(true);
    try {
      const body: Record<string, unknown> = {
        tld,
        grace_period_days: parseInt(editForm.grace_period_days) || 0,
        redemption_period_days: parseInt(editForm.redemption_period_days) || 0,
        pending_delete_days: parseInt(editForm.pending_delete_days) || 0,
        drop_hour: editForm.drop_hour !== "" ? parseInt(editForm.drop_hour) : null,
        drop_minute: editForm.drop_minute !== "" ? parseInt(editForm.drop_minute) : null,
        drop_second: editForm.drop_second !== "" ? parseInt(editForm.drop_second) : null,
        drop_timezone: editForm.drop_timezone || null,
        pre_expiry_days: editForm.pre_expiry_days !== "" ? parseInt(editForm.pre_expiry_days) : null,
        source_url: editForm.source_url || null,
      };
      const res = await fetch("/api/admin/tld-rules", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "保存失败");
      toast.success(`.${tld} 已手动修改保存（后续爬取将跳过此记录）`);
      setEditingTld(null);
      load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "保存失败");
    } finally {
      setSaving(false);
    }
  }

  // ── Batch scrape ──────────────────────────────────────────────────────────
  // A TLD is "already done" only if scrape_status='ok' (real data) or manually_edited
  function isTldDone(tld: string): boolean {
    const rule = rules.find(r => r.tld === tld);
    if (!rule) return false;
    if (rule.manually_edited) return true;
    return rule.scrape_status === "ok";
  }

  // Single TLD retry scrape (for failed/warn records)
  const [retrying, setRetrying] = React.useState<string | null>(null);
  async function handleRetry(tld: string) {
    setRetrying(tld);
    try {
      const res = await fetch("/api/admin/tld-rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, force: true, model: selectedModel || undefined }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "重新抓取失败");
      if (data.scrape_status === "ok") {
        toast.success(`.${tld} 重新抓取成功！宽限${data.grace_period_days}d 赎回${data.redemption_period_days}d 待删${data.pending_delete_days}d`);
      } else {
        toast.warning(`.${tld} 抓取完成但仅获得默认值，AI未找到具体政策数据`);
      }
      load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "重新抓取失败");
    } finally {
      setRetrying(null);
    }
  }

  function startBatch(list: typeof batchList) {
    // Build full item list: mark done ones (ok/manually-edited) immediately as "skipped"
    const items: BatchItem[] = list.map(t => {
      const rule = rules.find(r => r.tld === t.tld);
      if (rule?.manually_edited) {
        return { tld: t.tld, status: "skipped" as const, msg: "手动修改，已跳过" };
      }
      if (isTldDone(t.tld)) {
        const dateStr = rule?.scraped_at ? new Date(rule.scraped_at).toISOString().slice(0, 10) : "—";
        return { tld: t.tld, status: "skipped" as const, msg: `已成功抓取 (${dateStr})` };
      }
      return { tld: t.tld, status: "pending" as const };
    });
    const pending = items.filter(i => i.status === "pending");
    if (pending.length === 0) {
      toast.info(`所有 ${list.length} 个 TLD 已成功抓取，无需重新抓取`);
      return;
    }
    toast.info(`跳过 ${items.length - pending.length} 个已成功 TLD，准备抓取/重试 ${pending.length} 个`);
    batchAbortRef.current = false;
    setBatchList(list);
    setBatchItems(items);
    // Start from first pending item
    const firstPending = items.findIndex(i => i.status === "pending");
    setBatchIdx(firstPending);
    setBatchStatus("running");
  }

  function stopBatch() {
    batchAbortRef.current = true;
    setBatchStatus("done");
    toast.info("已停止批量抓取");
  }

  React.useEffect(() => {
    if (batchStatus !== "running") return;
    // Find next pending item starting from batchIdx
    const nextPending = batchItems.findIndex((it, i) => i >= batchIdx && it.status === "pending");
    if (nextPending === -1) {
      setBatchStatus("done");
      const doneCount = batchItems.filter(i => i.status === "ok").length;
      const skipCount = batchItems.filter(i => i.status === "skipped").length;
      toast.success(`批量抓取完成：成功 ${doneCount} 个，跳过 ${skipCount} 个`);
      load();
      return;
    }
    if (batchAbortRef.current) return;
    if (nextPending !== batchIdx) { setBatchIdx(nextPending); return; }

    const item = batchItems[batchIdx];
    const meta = batchList.find(t => t.tld === item.tld);

    (async () => {
      try {
        const res = await fetch("/api/admin/tld-rules", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tld: item.tld, source_url: meta?.source_url, model: batchModel || undefined }),
        });
        const data = await res.json();
        if (!res.ok) {
          setBatchItems(prev => prev.map((it, i) =>
            i === batchIdx ? { ...it, status: res.status === 429 ? "skipped" : "error", msg: data.error } : it
          ));
        } else if (data.skipped) {
          const skipMsg = data.reason === "manually_edited"
            ? "手动修改，已保护"
            : data.reason === "already_ok"
            ? `已成功抓取 (${data.scraped_at?.slice(0,10) ?? "—"})`
            : `已跳过`;
          setBatchItems(prev => prev.map((it, i) =>
            i === batchIdx ? { ...it, status: "skipped", msg: skipMsg } : it
          ));
        } else {
          setBatchItems(prev => prev.map((it, i) =>
            i === batchIdx ? { ...it, status: "ok", msg: `${data.total_release_days}d` } : it
          ));
        }
      } catch (err: any) {
        setBatchItems(prev => prev.map((it, i) =>
          i === batchIdx ? { ...it, status: "error", msg: err.message } : it
        ));
      } finally {
        if (!batchAbortRef.current) {
          await new Promise(r => setTimeout(r, 1200));
          setBatchIdx(i => i + 1);
        }
      }
    })();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [batchStatus, batchIdx]);

  const filtered = React.useMemo(() => {
    const q = search.toLowerCase().trim();
    let rows = q ? rules.filter(r => r.tld.includes(q)) : rules;
    if (showOnlyDefaults) rows = rows.filter(r =>
      !r.manually_edited && r.grace_period_days === 30 && r.redemption_period_days === 30 && r.pending_delete_days === 5
    );
    return rows;
  }, [rules, search, showOnlyDefaults]);

  const filteredCompare = React.useMemo(() => {
    if (!compareData) return [];
    let rows = compareData.rows;
    if (showOnlyConflicts) rows = rows.filter(r => r.hasConflict);
    if (showOnlyScraped) rows = rows.filter(r => r.db_grace !== null);
    const q = compareSearch.toLowerCase().trim();
    if (q) rows = rows.filter(r => r.tld.includes(q));
    return rows;
  }, [compareData, showOnlyConflicts, showOnlyScraped, compareSearch]);

  // Is this record using all-default values (likely means no real data found)?
  function isDefaultValues(r: TldRule) {
    return r.grace_period_days === 30 && r.redemption_period_days === 30 && r.pending_delete_days === 5;
  }

  function confidenceBadge(r: TldRule) {
    const c = r.confidence;
    let badge: React.ReactNode;
    if (c === "high") badge = <span className="text-xs px-1.5 py-0.5 rounded bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400">官方</span>;
    else if (c === "ai") badge = <span className="text-xs px-1.5 py-0.5 rounded bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">AI</span>;
    else badge = <span className="text-xs px-1.5 py-0.5 rounded bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400">估算</span>;
    const parts = [
      `置信度: ${c}`,
      r.model_used ? `模型: ${r.model_used}` : "",
      r.fetch_strategy ? `策略: ${r.fetch_strategy}` : "",
      r.scrape_attempts > 1 ? `尝试 ${r.scrape_attempts} 次` : "",
    ].filter(Boolean).join(" · ");
    return <span title={parts}>{badge}</span>;
  }

  function qualityBadge(r: TldRule) {
    if (r.manually_edited) return null; // manually edited is always trustworthy
    if (!r.scraped_at) return null;
    if (isDefaultValues(r) && r.confidence !== "high") {
      return (
        <span className="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded-full bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 font-medium"
          title={r.ai_reasoning ?? "AI 未找到具体政策数据，使用行业默认值"}>
          <RiErrorWarningLine className="w-2.5 h-2.5" />默认值
        </span>
      );
    }
    return null;
  }

  function sourceBadge(r: TldRule) {
    if (r.manually_edited) {
      return (
        <span className="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400 font-medium">
          <RiUserLine className="w-2.5 h-2.5" />手动修改
        </span>
      );
    }
    if (r.scrape_status === "failed") {
      return (
        <span className="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded-full bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 font-medium"
          title={r.failure_reason ?? "抓取失败"}>
          <RiErrorWarningLine className="w-2.5 h-2.5" />失败
        </span>
      );
    }
    if (r.scrape_status === "warn_defaults") {
      return (
        <div className="flex flex-wrap gap-0.5">
          <span className="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded-full bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 font-medium"
            title={r.ai_reasoning ?? "仅获得行业默认值，未找到注册局具体政策"}>
            <RiErrorWarningLine className="w-2.5 h-2.5" />仅默认值
          </span>
        </div>
      );
    }
    if (r.scrape_status === "ok") {
      return (
        <span className="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded-full bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 font-medium"
          title={`${r.fetch_strategy ?? "ai"} · ${r.model_used ?? ""}`}>
          <RiCheckboxCircleLine className="w-2.5 h-2.5" />已确认
        </span>
      );
    }
    if (r.scraped_at) {
      return (
        <span className="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded-full bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 font-medium">
          <RiRobot2Line className="w-2.5 h-2.5" />已爬取
        </span>
      );
    }
    return null;
  }

  function formatDropTime(r: TldRule | CompareRow, prefix: "db_" | "" = "") {
    const h = prefix === "db_" ? (r as CompareRow).db_dropHour : (r as TldRule).drop_hour;
    const m = prefix === "db_" ? null : (r as TldRule).drop_minute;
    const tz = prefix === "db_" ? (r as CompareRow).db_dropTimezone : (r as TldRule).drop_timezone;
    if (h === null || h === undefined) return null;
    return `${String(h).padStart(2,"0")}:${String(m??0).padStart(2,"0")} ${tz ?? "UTC"}`;
  }

  const batchDone = batchItems.filter(i => i.status === "ok").length;
  const batchErr = batchItems.filter(i => i.status === "error").length;
  const batchSkip = batchItems.filter(i => i.status === "skipped").length;
  const batchPct = batchItems.length
    ? Math.round(((batchDone + batchErr + batchSkip) / batchItems.length) * 100) : 0;

  function BatchPanel({ list, label }: { list: typeof batchList; label: string }) {
    return (
      <div className="border rounded-xl p-5 space-y-4 bg-card">
        <div className="flex items-center justify-between">
          <h2 className="font-medium flex items-center gap-2">
            <RiPlayCircleLine className="w-4 h-4 text-violet-500" />
            {label}
            <span className="text-xs text-muted-foreground font-normal">
              — {list.length} 个 · 已成功(ok)的自动跳过，失败/默认值记录自动重试，无时效限制
            </span>
          </h2>
          <div className="flex items-center gap-2 flex-wrap">
            {aiModels.filter(m => m.configured).length > 0 && batchStatus !== "running" && (
              <select
                value={batchModel}
                onChange={e => setBatchModel(e.target.value)}
                className="h-7 rounded border text-xs px-2 bg-background"
              >
                <option value="">AI 自动选择</option>
                {aiModels.filter(m => m.configured).map(m => (
                  <option key={m.id} value={m.id}>{m.name}</option>
                ))}
              </select>
            )}
            {batchStatus === "running" ? (
              <Button variant="outline" size="sm" onClick={stopBatch} className="gap-1.5 text-red-600 border-red-300 hover:bg-red-50">
                <RiStopCircleLine className="w-4 h-4" />停止
              </Button>
            ) : (
              <Button variant="outline" size="sm" onClick={() => startBatch(list)} className="gap-1.5">
                <RiPlayCircleLine className="w-4 h-4" />
                {batchStatus === "done" ? "重新批量" : "开始批量抓取"}
              </Button>
            )}
          </div>
        </div>

        {batchItems.length > 0 && (
          <div className="space-y-3">
            <div className="space-y-1">
              <div className="flex justify-between text-xs text-muted-foreground">
                <span>
                  {batchStatus === "running"
                    ? `正在处理 .${batchItems[batchIdx]?.tld ?? "…"} (${batchIdx + 1}/${batchItems.length})`
                    : `完成 ${batchDone}  失败 ${batchErr}  跳过 ${batchSkip}`}
                </span>
                <span>{batchPct}%</span>
              </div>
              <div className="w-full h-1.5 rounded-full bg-muted overflow-hidden">
                <div className="h-full bg-violet-500 transition-all duration-300" style={{ width: `${batchPct}%` }} />
              </div>
            </div>
            <div className="max-h-48 overflow-y-auto grid grid-cols-3 sm:grid-cols-6 gap-1">
              {batchItems.map((it, i) => (
                <div key={it.tld} title={it.msg} className={cn(
                  "text-xs px-2 py-1 rounded flex items-center gap-1",
                  it.status === "ok" && "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
                  it.status === "error" && "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
                  it.status === "skipped" && "bg-yellow-100 text-yellow-700",
                  it.status === "pending" && i === batchIdx && batchStatus === "running" && "bg-violet-100 text-violet-700 dark:bg-violet-900/30",
                  it.status === "pending" && i !== batchIdx && "bg-muted text-muted-foreground",
                )}>
                  {it.status === "pending" && i === batchIdx && batchStatus === "running"
                    ? <RiLoader4Line className="w-3 h-3 animate-spin shrink-0" />
                    : it.status === "ok" ? <RiCheckboxCircleLine className="w-3 h-3 shrink-0" />
                    : it.status === "error" ? <RiErrorWarningLine className="w-3 h-3 shrink-0" />
                    : null}
                  .{it.tld}
                </div>
              ))}
            </div>
          </div>
        )}

        {batchItems.length === 0 && (
          <p className="text-xs text-muted-foreground">
            点击"开始批量抓取"——已成功确认(scrape_status=ok)的记录直接跳过，失败/仅默认值/未抓取的记录都会重新尝试。每条间隔 1.2 秒，无时效限制。每次成功抓取同时写入数据库和本地 JSON 文件备份。
          </p>
        )}
      </div>
    );
  }

  return (
    <AdminLayout title="TLD 管理">
      <Head><title>TLD 生命周期规则 - AI 抓取</title></Head>

      <div className="space-y-6 max-w-6xl">
        <PageTabs tabs={TLD_TABS} />
        <div>
          <h1 className="text-xl font-semibold">TLD 生命周期规则 — AI 自动抓取</h1>
          <p className="text-sm text-muted-foreground mt-1">
            爬取注册局页面，多模型 AI（GLM/Groq/Gemini/DeepSeek 自动回退）提取宽限期、赎回期、精确掉落时间和时区，IANA 页面自动发现注册局生命周期子页。
          </p>
        </div>

        {/* ── Stats Overview ──────────────────────────────────────────────── */}
        {scrapeStats && (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {[
              { label: "✅ 已确认", value: scrapeStats.ok, cls: "bg-green-50 border-green-200 text-green-700 dark:bg-green-950/20 dark:border-green-900 dark:text-green-400", desc: "真实数据，可信" },
              { label: "⚠ 仅默认值", value: scrapeStats.warn_defaults, cls: "bg-orange-50 border-orange-200 text-orange-700 dark:bg-orange-950/20 dark:border-orange-900 dark:text-orange-400", desc: "AI未找到具体政策，使用30/30/5行业默认值，仍在重试" },
              { label: "🚫 无数据", value: scrapeStats.no_data, cls: "bg-rose-50 border-rose-200 text-rose-700 dark:bg-rose-950/20 dark:border-rose-900 dark:text-rose-400", desc: "多次重试失败，需人工核查或手动录入" },
              { label: "❌ 失败", value: scrapeStats.failed, cls: "bg-red-50 border-red-200 text-red-700 dark:bg-red-950/20 dark:border-red-900 dark:text-red-400", desc: "网络/AI错误，需重试或手动填写" },
              { label: "⏳ 待抓取", value: scrapeStats.pending, cls: "bg-muted border-border text-muted-foreground", desc: "尚未抓取" },
              { label: "✏ 手动修改", value: scrapeStats.manually_edited, cls: "bg-amber-50 border-amber-200 text-amber-700 dark:bg-amber-950/20 dark:border-amber-900 dark:text-amber-400", desc: "管理员手动录入，受保护" },
            ].map(({ label, value, cls, desc }) => (
              <div key={label} className={cn("border rounded-xl px-4 py-3 text-center", cls)} title={desc}>
                <div className="text-2xl font-bold">{value}</div>
                <div className="text-xs mt-0.5 font-medium">{label}</div>
              </div>
            ))}
          </div>
        )}

        {/* ── Failed / Warn / No-data records panel ───────────────────────── */}
        {!loading && rules.filter(r => !r.manually_edited && (r.scrape_status === "failed" || r.scrape_status === "warn_defaults" || r.scrape_status === "no_data")).length > 0 && (
          <div className="border rounded-xl overflow-hidden bg-card">
            <div className="flex items-center gap-3 px-4 py-3 border-b bg-red-50/50 dark:bg-red-950/10">
              <RiErrorWarningLine className="w-4 h-4 text-red-500" />
              <span className="font-medium text-sm text-red-700 dark:text-red-400">
                需要关注的记录
              </span>
              <span className="text-xs text-muted-foreground">
                — 失败、默认值或已穷尽重试的 TLD，建议手动录入或重置后再次抓取
              </span>
            </div>
            <div className="divide-y divide-border">
              {rules
                .filter(r => !r.manually_edited && (r.scrape_status === "failed" || r.scrape_status === "warn_defaults" || r.scrape_status === "no_data"))
                .map(r => (
                  <div key={r.tld} className={cn(
                    "flex items-start gap-3 px-4 py-3",
                    r.scrape_status === "failed"        && "bg-red-50/30 dark:bg-red-950/10",
                    r.scrape_status === "warn_defaults" && "bg-orange-50/30 dark:bg-orange-950/10",
                    r.scrape_status === "no_data"       && "bg-rose-50/40 dark:bg-rose-950/10",
                  )}>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono font-bold text-sm">.{r.tld}</span>
                        {sourceBadge(r)}
                        {r.scrape_attempts > 0 && (
                          <span className="text-[10px] text-muted-foreground">尝试 {r.scrape_attempts} 次</span>
                        )}
                        {r.scrape_status === "no_data" && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-100 dark:bg-rose-950/30 text-rose-700 dark:text-rose-300 font-medium">已穷尽重试</span>
                        )}
                        {r.fetch_strategy && r.scrape_status !== "failed" && r.scrape_status !== "no_data" && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">{r.fetch_strategy}</span>
                        )}
                        {r.model_used && r.scrape_status !== "failed" && r.scrape_status !== "no_data" && (
                          <span className="text-[10px] text-muted-foreground">{r.model_used}</span>
                        )}
                      </div>
                      {r.scrape_status === "failed" && r.failure_reason && (
                        <p className="text-xs text-red-600 dark:text-red-400 mt-1 font-mono break-all">
                          {r.failure_reason}
                        </p>
                      )}
                      {r.scrape_status === "no_data" && r.failure_reason && (
                        <p className="text-xs text-rose-600 dark:text-rose-400 mt-1 italic">
                          {r.failure_reason}
                        </p>
                      )}
                      {r.scrape_status === "warn_defaults" && r.ai_reasoning && (
                        <p className="text-xs text-orange-700 dark:text-orange-400 mt-1 italic">
                          {r.ai_reasoning}
                        </p>
                      )}
                      {(r.scrape_status === "warn_defaults" || r.scrape_status === "no_data") && (
                        <p className="text-xs text-muted-foreground mt-0.5">
                          当前值: {r.grace_period_days}d / {r.redemption_period_days}d / {r.pending_delete_days}d
                          {r.source_url && (() => { try { return <> · <a href={r.source_url!} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">{new URL(r.source_url!).hostname}</a></>; } catch { return null; } })()}
                        </p>
                      )}
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0 mt-0.5">
                      {r.scrape_status === "no_data" ? (
                        <Button
                          variant="outline" size="sm"
                          className="h-7 gap-1 text-xs border-rose-300 text-rose-700 hover:bg-rose-50 dark:border-rose-800 dark:text-rose-400"
                          disabled={retrying === r.tld}
                          onClick={async () => {
                            setRetrying(r.tld);
                            try {
                              const res = await fetch("/api/admin/tld-rules", {
                                method: "PATCH",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({ action: "reset-to-pending", tld: r.tld }),
                              });
                              const data = await res.json();
                              if (data.ok) { toast.success(data.message); load(); }
                              else toast.error(data.error ?? "重置失败");
                            } catch { toast.error("重置失败"); }
                            finally { setRetrying(null); }
                          }}
                        >
                          {retrying === r.tld
                            ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                            : <RiRefreshLine className="w-3.5 h-3.5" />}
                          重置重抓
                        </Button>
                      ) : (
                        <Button
                          variant="outline" size="sm"
                          className={cn(
                            "h-7 gap-1 text-xs",
                            r.scrape_status === "failed"
                              ? "border-red-300 text-red-700 hover:bg-red-50 dark:border-red-800 dark:text-red-400"
                              : "border-orange-300 text-orange-700 hover:bg-orange-50 dark:border-orange-800 dark:text-orange-400"
                          )}
                          disabled={retrying === r.tld}
                          onClick={() => handleRetry(r.tld)}
                        >
                          {retrying === r.tld
                            ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                            : <RiRefreshLine className="w-3.5 h-3.5" />}
                          重新抓取
                        </Button>
                      )}
                      <Button
                        variant="ghost" size="sm"
                        className="h-7 gap-1 text-xs text-blue-600 hover:bg-blue-50"
                        title="手动填写正确数据"
                        onClick={() => startEdit(r)}
                      >
                        <RiEditLine className="w-3.5 h-3.5" />手动填写
                      </Button>
                    </div>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* Tab bar */}
        <div className="flex gap-1 border-b">
          {([
            { id: "cc", label: "国别域名 (ccTLD)", icon: RiMapPin2Line },
            { id: "gtld", label: "通用顶级域 (gTLD)", icon: RiGlobalLine },
            { id: "compare", label: "对比分析", icon: RiBarChartLine },
          ] as const).map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={cn(
                "flex items-center gap-1.5 px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors",
                tab === id
                  ? "border-primary text-primary"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              )}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          ))}
        </div>

        {/* ── ccTLD tab ────────────────────────────────────────────────────── */}
        {tab === "cc" && (
          <>
            {/* Single scrape form */}
            <div className="border rounded-xl p-5 space-y-4 bg-card">
              <h2 className="font-medium flex items-center gap-2">
                <RiRobot2Line className="w-4 h-4 text-blue-500" />
                抓取单个 TLD
              </h2>
              <form onSubmit={handleScrape} className="grid grid-cols-1 sm:grid-cols-[120px_1fr_auto] gap-3 items-end">
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">TLD（不含点）</Label>
                  <Input placeholder="如 mk" value={form.tld}
                    onChange={e => setForm(f => ({ ...f, tld: e.target.value }))} className="h-9" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">
                    注册局页面 URL
                    <span className="ml-1 text-muted-foreground/60">（可选，留空自动用 IANA 页）</span>
                  </Label>
                  <Input
                    placeholder={form.tld
                      ? `https://www.iana.org/domains/root/db/${form.tld.toLowerCase().replace(/^\./, "")}.html`
                      : "留空则自动使用 IANA 官方页面"}
                    value={form.source_url}
                    onChange={e => setForm(f => ({ ...f, source_url: e.target.value }))}
                    className="h-9"
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Button type="submit" disabled={scraping} className="h-9 gap-1.5 shrink-0">
                    {scraping ? <><RiLoader4Line className="w-4 h-4 animate-spin" />抓取中…</>
                      : <><RiRobot2Line className="w-4 h-4" />抓取</>}
                  </Button>
                  <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer select-none">
                    <input type="checkbox" checked={form.force}
                      onChange={e => setForm(f => ({ ...f, force: e.target.checked }))} />
                    强制重爬
                  </label>
                </div>
              </form>

              {/* AI Model selector */}
              <div className="flex flex-wrap items-center gap-3 pt-1">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <RiRobot2Line className="w-3.5 h-3.5" />
                  <span>AI 模型：</span>
                  <select
                    value={selectedModel}
                    onChange={e => setSelectedModel(e.target.value)}
                    className="h-7 rounded border text-xs px-2 bg-background"
                  >
                    <option value="">自动选择（按优先级）</option>
                    {aiModels.filter(m => m.configured).map(m => (
                      <option key={m.id} value={m.id}>{m.name} ({m.provider})</option>
                    ))}
                    {aiModels.filter(m => !m.configured).map(m => (
                      <option key={m.id} value={m.id} disabled>🔒 {m.name} (需 {m.env_var})</option>
                    ))}
                  </select>
                </div>
                <div className="flex gap-1 flex-wrap">
                  {aiModels.slice(0, 6).map(m => (
                    <span key={m.id} className={cn(
                      "text-[10px] px-1.5 py-0.5 rounded-full border",
                      m.configured
                        ? "bg-green-50 border-green-200 text-green-700 dark:bg-green-900/20 dark:border-green-800 dark:text-green-400"
                        : "bg-muted border-border text-muted-foreground"
                    )}>
                      {m.configured ? "✓" : "✗"} {m.name}
                    </span>
                  ))}
                  {aiModels.length > 6 && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded-full border bg-muted text-muted-foreground">
                      +{aiModels.length - 6} 个
                    </span>
                  )}
                </div>
              </div>

              {scraping && <p className="text-xs text-muted-foreground animate-pulse">正在爬取页面，调用 AI 提取规则（支持自动回退到备用模型），请稍等 5-20 秒…</p>}

              {lastResult && (
                <div className={cn("rounded-lg p-4 text-sm border",
                  lastResult.error
                    ? "bg-red-50 border-red-200 dark:bg-red-900/20 dark:border-red-800"
                    : lastResult.skipped
                    ? "bg-yellow-50 border-yellow-200 dark:bg-yellow-900/20 dark:border-yellow-800"
                    : "bg-green-50 border-green-200 dark:bg-green-900/20 dark:border-green-800"
                )}>
                  {lastResult.error ? (
                    <div className="flex items-start gap-2 text-red-700 dark:text-red-400">
                      <RiErrorWarningLine className="w-4 h-4 mt-0.5 shrink-0" />{lastResult.error}
                    </div>
                  ) : lastResult.skipped ? (
                    <div className="flex items-start gap-2 text-yellow-700 dark:text-yellow-400">
                      <RiTimeLine className="w-4 h-4 mt-0.5 shrink-0" />
                      {lastResult.reason === "already_ok"
                        ? `.${lastResult.tld} 已成功抓取（${lastResult.scraped_at?.slice(0,10) ?? "—"}），跳过重爬。勾选"强制重爬"可强制覆盖。`
                        : lastResult.reason === "manually_edited"
                        ? `.${lastResult.tld} 已被手动修改，自动爬取已跳过。勾选"强制重爬"可覆盖并重新抓取。`
                        : `.${lastResult.tld} 已跳过重爬。勾选"强制重爬"可强制覆盖。`}
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 font-medium text-green-700 dark:text-green-400">
                        <RiCheckboxCircleLine className="w-4 h-4" />.{lastResult.tld} 提取成功
                        {lastResult.model_used && (
                          <span className="text-xs font-normal text-muted-foreground ml-1">via {lastResult.model_used}</span>
                        )}
                        {lastResult.has_lifecycle_info === false && (
                          <span className="text-xs font-normal text-amber-600 ml-1">⚠ 页面无明确生命周期数据，已用行业默认值</span>
                        )}
                      </div>
                      {lastResult.source_url && lastResult.source_url !== lastResult.source_url_requested && (
                        <p className="text-xs text-blue-600 dark:text-blue-400">
                          🔍 自动发现注册局生命周期页面：{lastResult.source_url}
                        </p>
                      )}
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                        {[
                          ["宽限期", `${lastResult.grace_period_days}天`],
                          ["赎回期", `${lastResult.redemption_period_days}天`],
                          ["待删期", `${lastResult.pending_delete_days}天`],
                          ["总天数", `${lastResult.total_release_days}天`],
                        ].map(([label, val]) => (
                          <div key={label} className="bg-white dark:bg-black/20 rounded px-3 py-2">
                            <div className="text-muted-foreground">{label}</div>
                            <div className="font-bold text-lg">{val}</div>
                          </div>
                        ))}
                      </div>
                      {(lastResult.drop_hour !== null && lastResult.drop_hour !== undefined) && (
                        <div className="flex items-center gap-1.5 text-xs text-blue-700 dark:text-blue-400">
                          <RiTimeLine className="w-3.5 h-3.5" />
                          掉落时间: {String(lastResult.drop_hour).padStart(2,"0")}:{String(lastResult.drop_minute??0).padStart(2,"0")} {lastResult.drop_timezone ?? "UTC"}
                          {lastResult.pre_expiry_days > 0 && ` · 提前 ${lastResult.pre_expiry_days} 天删除`}
                        </div>
                      )}
                      {lastResult.reasoning && <p className="text-xs text-muted-foreground italic">{lastResult.reasoning}</p>}
                    </div>
                  )}
                </div>
              )}
            </div>

            <BatchPanel list={CC_TLDS} label={`国别域名 (ccTLD) 批量 — 全部 ${CC_TLDS.length} 个`} />
          </>
        )}

        {/* ── gTLD tab ─────────────────────────────────────────────────────── */}
        {tab === "gtld" && (
          <div className="space-y-4">
            {ianaLoading && (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <RiLoader4Line className="w-4 h-4 animate-spin" />
                正在从 IANA 获取完整 gTLD 列表…
              </div>
            )}
            {!ianaLoading && ianaGtlds.length > 0 && (
              <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                <RiGlobalLine className="w-3.5 h-3.5" />
                IANA 列表：<strong className="text-foreground">{ianaGtlds.length} 个 gTLD</strong>
                {ianaFetchedAt && <span>· 获取时间 {ianaFetchedAt.slice(0,10)} （24小时缓存）</span>}
              </div>
            )}
            {!ianaLoading && ianaGtlds.length === 0 && (
              <div className="text-sm text-muted-foreground">
                IANA 列表加载失败，使用内置列表（{G_TLDS.length} 个）作为回退
              </div>
            )}
            <BatchPanel
              list={ianaGtlds.length > 0 ? ianaGtlds : G_TLDS}
              label={`通用顶级域 (gTLD) 批量 — ${ianaGtlds.length > 0 ? ianaGtlds.length : G_TLDS.length} 个`}
            />
          </div>
        )}

        {/* ── Compare tab ──────────────────────────────────────────────────── */}
        {tab === "compare" && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <Button variant="outline" size="sm" onClick={loadCompare} disabled={compareLoading} className="gap-1.5">
                {compareLoading ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiRefreshLine className="w-4 h-4" />}
                刷新对比
              </Button>
              <Button variant="outline" size="sm" onClick={() => exportAs("json")} className="gap-1.5 text-blue-600 border-blue-300 hover:bg-blue-50">
                <RiExternalLinkLine className="w-3.5 h-3.5" />导出 JSON
              </Button>
              <Button variant="outline" size="sm" onClick={() => exportAs("csv")} className="gap-1.5 text-green-700 border-green-300 hover:bg-green-50">
                <RiExternalLinkLine className="w-3.5 h-3.5" />导出 CSV
              </Button>
              {compareData && (
                <div className="flex gap-2 text-xs text-muted-foreground">
                  <span>静态库: <strong>{compareData.total}</strong> 条</span>
                  <span>已抓取: <strong>{compareData.scraped}</strong> 条</span>
                  <span className={compareData.conflicts > 0 ? "text-orange-600 font-medium" : ""}>
                    数据冲突: <strong>{compareData.conflicts}</strong> 条
                  </span>
                </div>
              )}
              <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                <input type="checkbox" checked={showOnlyConflicts} onChange={e => setShowOnlyConflicts(e.target.checked)} />
                仅显示冲突
              </label>
              <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                <input type="checkbox" checked={showOnlyScraped} onChange={e => setShowOnlyScraped(e.target.checked)} />
                仅显示已抓取
              </label>
            </div>

            <div className="flex items-center gap-2">
              <RiSearchLine className="w-4 h-4 text-muted-foreground shrink-0" />
              <Input placeholder="搜索 TLD…" value={compareSearch}
                onChange={e => setCompareSearch(e.target.value)}
                className="h-8 text-sm max-w-xs" />
              <span className="text-xs text-muted-foreground">{filteredCompare.length} 条</span>
            </div>

            {compareLoading ? (
              <div className="flex items-center gap-2 py-12 justify-center text-muted-foreground">
                <RiLoader4Line className="w-5 h-5 animate-spin" />加载对比数据…
              </div>
            ) : !compareData ? (
              <div className="text-center py-12 text-sm text-muted-foreground">点击"刷新对比"加载数据</div>
            ) : (
              <div className="border rounded-xl overflow-hidden bg-card">
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead className="bg-muted/50 text-muted-foreground">
                      <tr>
                        <th className="text-left px-3 py-2.5 font-medium">TLD</th>
                        <th className="text-center px-2 py-2.5 font-medium" colSpan={3}>静态数据（宽/赎/删）</th>
                        <th className="text-center px-2 py-2.5 font-medium" colSpan={3}>AI 数据（宽/赎/删）</th>
                        <th className="text-left px-2 py-2.5 font-medium">掉落时间</th>
                        <th className="text-left px-2 py-2.5 font-medium">差异</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {filteredCompare.map(r => (
                        <tr key={r.tld} className={cn(
                          "hover:bg-muted/30 transition-colors",
                          r.hasConflict && "bg-orange-50/50 dark:bg-orange-950/20"
                        )}>
                          <td className="px-3 py-2 font-mono font-medium">
                            .{r.tld}
                            <div className="text-muted-foreground text-[10px]">{r.s_registry ?? ""}</div>
                          </td>
                          {/* Static */}
                          <td className="px-2 py-2 text-center">{r.s_grace}d</td>
                          <td className="px-2 py-2 text-center">{r.s_redemption}d</td>
                          <td className="px-2 py-2 text-center">{r.s_pending}d</td>
                          {/* DB */}
                          {r.db_grace !== null ? (
                            <>
                              <td className={cn("px-2 py-2 text-center", r.db_grace !== r.s_grace && "text-orange-600 font-medium")}>{r.db_grace}d</td>
                              <td className={cn("px-2 py-2 text-center", r.db_redemption !== r.s_redemption && "text-orange-600 font-medium")}>{r.db_redemption}d</td>
                              <td className={cn("px-2 py-2 text-center", r.db_pending !== r.s_pending && "text-orange-600 font-medium")}>{r.db_pending}d</td>
                            </>
                          ) : (
                            <td className="px-2 py-2 text-center text-muted-foreground" colSpan={3}>未抓取</td>
                          )}
                          {/* Drop time */}
                          <td className="px-2 py-2">
                            {r.s_dropHour !== null ? (
                              <span className="flex items-center gap-1 text-blue-600">
                                <RiTimeLine className="w-3 h-3" />
                                {String(r.s_dropHour).padStart(2,"0")}:00 {r.s_dropTimezone ?? "UTC"}
                                <span className="text-muted-foreground">(静)</span>
                              </span>
                            ) : r.db_dropHour !== null ? (
                              <span className="flex items-center gap-1 text-violet-600">
                                <RiTimeLine className="w-3 h-3" />
                                {String(r.db_dropHour).padStart(2,"0")}:00 {r.db_dropTimezone ?? "UTC"}
                                <span className="text-muted-foreground">(AI)</span>
                              </span>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </td>
                          {/* Diffs */}
                          <td className="px-2 py-2 max-w-[180px]">
                            {r.hasConflict ? (
                              <div className="space-y-0.5">
                                {r.diffs.map((d, i) => (
                                  <div key={i} className="text-orange-700 dark:text-orange-400 text-[10px]">{d}</div>
                                ))}
                              </div>
                            ) : r.db_grace !== null ? (
                              <span className="text-green-600 text-[10px]">一致</span>
                            ) : (
                              <span className="text-muted-foreground text-[10px]">—</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            <div className="rounded-xl border bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-900 p-4 text-xs text-blue-800 dark:text-blue-300 space-y-1">
              <p className="font-medium text-sm">如何处理冲突？</p>
              <ul className="list-disc list-inside space-y-0.5 leading-relaxed">
                <li>橙色行表示 AI 抓取数据与本地静态数据存在差异</li>
                <li>若 AI 数据来自注册局官方政策页面（confidence=high），建议以 AI 数据为准并更新 lifecycle.ts</li>
                <li>若 AI 数据仅为估算（confidence=ai），仍以本地静态数据为基准</li>
                <li>掉落时间（蓝色）精确到分秒，是域名进入公开抢注阶段的时刻</li>
                <li>优先级: 手动覆盖表 &gt; AI 抓取 (tld_rules) &gt; 静态 lifecycle.ts &gt; 默认值</li>
              </ul>
            </div>
          </div>
        )}

        {/* ── Rules table (all tabs) ───────────────────────────────────────── */}
        <div className="border rounded-xl overflow-hidden bg-card">
          <div className="flex items-center gap-3 px-4 py-3 border-b">
            <RiSearchLine className="w-4 h-4 text-muted-foreground" />
            <Input placeholder="搜索已抓取的 TLD…" value={search}
              onChange={e => setSearch(e.target.value)}
              className="h-8 border-0 shadow-none focus-visible:ring-0 p-0 text-sm" />
            <button
              onClick={() => setShowOnlyDefaults(v => !v)}
              title="仅显示使用默认值 (30/30/5) 的条目"
              className={cn(
                "flex items-center gap-1 text-xs px-2 py-1 rounded-md border whitespace-nowrap transition-colors",
                showOnlyDefaults
                  ? "bg-orange-100 text-orange-700 border-orange-300 dark:bg-orange-900/30 dark:text-orange-400 dark:border-orange-700"
                  : "text-muted-foreground border-transparent hover:border-border hover:bg-muted/50"
              )}>
              <RiErrorWarningLine className="w-3.5 h-3.5" />仅显示默认值
            </button>
            <span className="text-xs text-muted-foreground whitespace-nowrap">{filtered.length} 条</span>
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={load}>
              <RiRefreshLine className="w-3.5 h-3.5" />
            </Button>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-12 text-muted-foreground">
              <RiLoader4Line className="w-5 h-5 animate-spin mr-2" />加载中…
            </div>
          ) : filtered.length === 0 ? (
            <div className="text-center py-12 text-sm text-muted-foreground">
              {rules.length === 0 ? "暂无数据，请先抓取" : "无匹配结果"}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-muted/50 text-xs text-muted-foreground">
                  <tr>
                    <th className="text-left px-4 py-2.5 font-medium">TLD</th>
                    <th className="text-right px-3 py-2.5 font-medium">宽限</th>
                    <th className="text-right px-3 py-2.5 font-medium">赎回</th>
                    <th className="text-right px-3 py-2.5 font-medium">待删</th>
                    <th className="text-right px-3 py-2.5 font-medium">总天</th>
                    <th className="text-left px-3 py-2.5 font-medium">掉落时间</th>
                    <th className="text-right px-3 py-2.5 font-medium">提前删</th>
                    <th className="text-left px-3 py-2.5 font-medium">来源</th>
                    <th className="text-left px-3 py-2.5 font-medium">置信</th>
                    <th className="text-left px-3 py-2.5 font-medium">更新</th>
                    <th className="px-3 py-2.5" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filtered.map(r => {
                    const dt = formatDropTime(r);
                    const isEditing = editingTld === r.tld;
                    return (
                      <React.Fragment key={r.tld}>
                        <tr className={cn(
                          "hover:bg-muted/30 transition-colors",
                          r.manually_edited && "bg-amber-50/40 dark:bg-amber-950/10",
                          !r.manually_edited && r.scrape_status === "failed" && "bg-red-50/30 dark:bg-red-950/10",
                          !r.manually_edited && r.scrape_status === "warn_defaults" && "bg-orange-50/30 dark:bg-orange-950/10",
                          isEditing && "bg-blue-50/60 dark:bg-blue-950/20"
                        )}>
                          <td className="px-4 py-2.5">
                            <div className="flex flex-col gap-0.5">
                              <span className="font-mono font-medium">.{r.tld}</span>
                              {sourceBadge(r)}
                            </div>
                          </td>
                          <td className="px-3 py-2.5 text-right">{r.grace_period_days}d</td>
                          <td className="px-3 py-2.5 text-right">{r.redemption_period_days}d</td>
                          <td className="px-3 py-2.5 text-right">{r.pending_delete_days}d</td>
                          <td className="px-3 py-2.5 text-right font-medium">{r.total_release_days}d</td>
                          <td className="px-3 py-2.5">
                            {dt ? (
                              <span className="flex items-center gap-1 text-xs text-blue-600">
                                <RiTimeLine className="w-3 h-3 shrink-0" />{dt}
                              </span>
                            ) : <span className="text-muted-foreground text-xs">—</span>}
                          </td>
                          <td className="px-3 py-2.5 text-right text-xs">
                            {r.pre_expiry_days ? `${r.pre_expiry_days}d` : "—"}
                          </td>
                          <td className="px-3 py-2.5">
                            {r.source_url ? (
                              <a href={r.source_url} target="_blank" rel="noopener noreferrer"
                                className="flex items-center gap-1 text-xs text-blue-600 hover:underline max-w-[120px] truncate">
                                <RiExternalLinkLine className="w-3 h-3 shrink-0" />
                                <span className="truncate">{new URL(r.source_url).hostname}</span>
                              </a>
                            ) : <span className="text-muted-foreground text-xs">—</span>}
                          </td>
                          <td className="px-3 py-2.5">{confidenceBadge(r)}</td>
                          <td className="px-3 py-2.5 text-xs text-muted-foreground">
                            {r.updated_at ? new Date(r.updated_at).toLocaleDateString("zh-CN") : "—"}
                          </td>
                          <td className="px-3 py-2.5">
                            <div className="flex items-center gap-1">
                              {isEditing ? (
                                <>
                                  <Button variant="ghost" size="icon" className="h-7 w-7 text-green-600 hover:text-green-700 hover:bg-green-50"
                                    disabled={saving} onClick={() => handleSaveEdit(r.tld)}>
                                    {saving ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiSaveLine className="w-3.5 h-3.5" />}
                                  </Button>
                                  <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-foreground"
                                    onClick={() => setEditingTld(null)}>
                                    <RiCloseLine className="w-3.5 h-3.5" />
                                  </Button>
                                </>
                              ) : (
                                <>
                                  <Button variant="ghost" size="icon" className="h-7 w-7 text-blue-500 hover:text-blue-600 hover:bg-blue-50"
                                    title="手动编辑" onClick={() => startEdit(r)}>
                                    <RiEditLine className="w-3.5 h-3.5" />
                                  </Button>
                                  <Button variant="ghost" size="icon" className="h-7 w-7 text-red-500 hover:text-red-600 hover:bg-red-50"
                                    disabled={deleting === r.tld} onClick={() => handleDelete(r.tld)}>
                                    {deleting === r.tld
                                      ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                                      : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                                  </Button>
                                </>
                              )}
                            </div>
                          </td>
                        </tr>

                        {/* Inline edit form row */}
                        {isEditing && (
                          <tr className="bg-blue-50/80 dark:bg-blue-950/30">
                            <td colSpan={11} className="px-4 py-3">
                              <div className="space-y-3">
                                <div className="flex items-center gap-2 text-xs font-medium text-blue-700 dark:text-blue-400">
                                  <RiEditLine className="w-3.5 h-3.5" />
                                  手动编辑 .{r.tld} — 保存后此记录将被标记为"手动修改"，自动爬取将跳过
                                  {r.manually_edited && (
                                    <span className="flex items-center gap-1 ml-2 text-amber-600">
                                      <RiLockLine className="w-3 h-3" />已受保护
                                    </span>
                                  )}
                                </div>
                                <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
                                  {[
                                    { label: "宽限期(天)", key: "grace_period_days" as const, placeholder: "30" },
                                    { label: "赎回期(天)", key: "redemption_period_days" as const, placeholder: "30" },
                                    { label: "待删期(天)", key: "pending_delete_days" as const, placeholder: "5" },
                                    { label: "提前删(天)", key: "pre_expiry_days" as const, placeholder: "0" },
                                    { label: "掉落时(h)", key: "drop_hour" as const, placeholder: "如 16" },
                                    { label: "掉落分(m)", key: "drop_minute" as const, placeholder: "如 0" },
                                    { label: "掉落秒(s)", key: "drop_second" as const, placeholder: "如 0" },
                                  ].map(({ label, key, placeholder }) => (
                                    <div key={key} className="space-y-1">
                                      <Label className="text-[10px] text-muted-foreground">{label}</Label>
                                      <Input
                                        type="number"
                                        className="h-7 text-xs px-2"
                                        placeholder={placeholder}
                                        value={editForm[key]}
                                        onChange={e => setEditForm(f => ({ ...f, [key]: e.target.value }))}
                                      />
                                    </div>
                                  ))}
                                </div>
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                  <div className="space-y-1">
                                    <Label className="text-[10px] text-muted-foreground">时区 (IANA格式，如 UTC / Europe/Berlin)</Label>
                                    <Input
                                      className="h-7 text-xs px-2"
                                      placeholder="如 Asia/Tokyo，留空则无"
                                      value={editForm.drop_timezone}
                                      onChange={e => setEditForm(f => ({ ...f, drop_timezone: e.target.value }))}
                                    />
                                  </div>
                                  <div className="space-y-1">
                                    <Label className="text-[10px] text-muted-foreground">来源 URL（政策页链接）</Label>
                                    <Input
                                      className="h-7 text-xs px-2"
                                      placeholder="https://..."
                                      value={editForm.source_url}
                                      onChange={e => setEditForm(f => ({ ...f, source_url: e.target.value }))}
                                    />
                                  </div>
                                </div>
                                <div className="flex gap-2">
                                  <Button size="sm" className="h-7 gap-1.5 text-xs" disabled={saving}
                                    onClick={() => handleSaveEdit(r.tld)}>
                                    {saving ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiSaveLine className="w-3.5 h-3.5" />}
                                    保存手动修改
                                  </Button>
                                  <Button size="sm" variant="ghost" className="h-7 gap-1.5 text-xs"
                                    onClick={() => setEditingTld(null)}>
                                    <RiCloseLine className="w-3.5 h-3.5" />取消
                                  </Button>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </AdminLayout>
  );
}
