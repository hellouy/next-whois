import React from "react";
import Head from "next/head";
import Link from "next/link";
import { getCached, setCached } from "@/lib/client-cache";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";
import {
  RiArrowLeftSLine,
  RiGlobalLine,
  RiSearchLine,
  RiLoader4Line,
  RiFlagLine,
  RiStarLine,
  RiCheckboxCircleLine,
  RiCloseCircleLine,
} from "@remixicon/react";
import type { TldInfo, IanaTldsResponse } from "./api/iana-tlds";

type FilterType = "all" | "cctld" | "gtld";
type TabType = "supported" | "unsupported";

const isSupported = (e: TldInfo) => e.hasWhois || e.hasRdap;

const TldCard = React.memo(function TldCard({ entry, isChinese }: { entry: TldInfo; isChinese: boolean }) {
  const isCc = entry.type === "cctld";
  const isIdn = entry.tld.startsWith("xn--");
  const countryLabel = isChinese ? entry.country : entry.countryEn;
  return (
    <div className="glass-panel border border-border rounded-xl p-3 flex flex-col gap-1.5">
      <div className="flex items-center justify-between gap-1">
        <span className="font-mono text-sm font-bold truncate">.{entry.tld}</span>
        {isCc && countryLabel ? (
          <span className="text-[9px] px-1.5 py-0 h-4 leading-4 rounded-sm bg-blue-500/12 text-blue-600 dark:text-blue-400 border border-blue-400/30 truncate max-w-[80px] inline-block">
            {countryLabel}
          </span>
        ) : isIdn ? (
          <span className="text-[9px] px-1.5 py-0 h-4 leading-4 rounded-sm bg-teal-500/12 text-teal-600 dark:text-teal-400 border border-teal-400/30 inline-block">
            IDN
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
  const { locale } = useTranslation();
  const settings = useSiteSettings();
  const isChinese = locale === "zh" || locale === "zh-tw";
  const siteName = settings.site_logo_text || "WHOIS";

  const [tab, setTab] = React.useState<TabType>("supported");

  const [search, setSearch] = React.useState("");
  const [typeFilter, setTypeFilter] = React.useState<FilterType>("all");
  const [uSearch, setUSearch] = React.useState("");
  const IANA_CACHE_TTL = 5 * 60_000;
  const [data, setData] = React.useState<IanaTldsResponse | null>(
    () => getCached<IanaTldsResponse>("iana_tlds", IANA_CACHE_TTL)
  );
  const [loading, setLoading] = React.useState(
    () => !getCached<IanaTldsResponse>("iana_tlds", IANA_CACHE_TTL)
  );

  React.useEffect(() => {
    if (getCached("iana_tlds", IANA_CACHE_TTL)) return;
    fetch("/api/iana-tlds")
      .then((r) => r.json())
      .then((d: IanaTldsResponse) => { setCached("iana_tlds", d); setData(d); })
      .catch(() => {})
      .finally(() => setLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const supported = React.useMemo(
    () => (data ? data.tlds.filter(isSupported) : []),
    [data],
  );
  const unsupported = React.useMemo(
    () => (data ? data.tlds.filter((e) => !isSupported(e)) : []),
    [data],
  );
  const whoisCount = supported.filter((e) => e.hasWhois).length;
  const rdapCount = supported.filter((e) => e.hasRdap).length;

  const filtered = React.useMemo(() => {
    const q = search.trim().toLowerCase().replace(/^\./, "");
    let list = supported;
    if (typeFilter !== "all") list = list.filter((t) => t.type === typeFilter);
    if (!q) return list;
    return list.filter(
      (t) => t.tld.includes(q) || (t.country && t.country.includes(q)) || (t.countryEn && t.countryEn.toLowerCase().includes(q)),
    );
  }, [supported, search, typeFilter]);

  const filteredUnsupported = React.useMemo(() => {
    const q = uSearch.trim().toLowerCase().replace(/^\./, "");
    if (!q) return unsupported;
    return unsupported.filter(
      (t) => t.tld.includes(q) || (t.country && t.country.includes(q)) || (t.countryEn && t.countryEn.toLowerCase().includes(q)),
    );
  }, [unsupported, uSearch]);

  const handleFilterClick = (f: FilterType) => setTypeFilter((prev) => (prev === f ? "all" : f));

  const pageTitle =
    tab === "supported"
      ? (isChinese ? "支持查询后缀" : "Supported Suffixes")
      : (isChinese ? "不支持查询后缀" : "Unsupported Suffixes");

  return (
    <>
      <Head>
        <title key="title">{`${pageTitle} — ${siteName}`}</title>
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
                <RiGlobalLine className="w-5 h-5" />
              </div>
              <div className="min-w-0">
                <h1 className="text-lg font-bold leading-none">{pageTitle}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5 break-words">
                  {isChinese
                    ? "IANA 全量后缀，按是否具备可查询的 WHOIS/RDAP 通道区分"
                    : "Full IANA suffix list, split by WHOIS/RDAP query availability"}
                </p>
              </div>
            </div>
          </div>

          {/* At-a-glance totals */}
          {!loading && data && (
            <div className="grid grid-cols-2 gap-2.5 mb-5">
              <button
                onClick={() => setTab("supported")}
                className={[
                  "glass-panel border rounded-xl p-3 text-center transition-all cursor-pointer",
                  tab === "supported"
                    ? "border-emerald-500/60 bg-emerald-500/8 ring-1 ring-emerald-500/30"
                    : "border-border hover:border-emerald-400/40 hover:bg-emerald-500/5",
                ].join(" ")}
              >
                <RiCheckboxCircleLine className={["w-4 h-4 mx-auto mb-1 transition-colors", tab === "supported" ? "text-emerald-500" : "text-emerald-400/70"].join(" ")} />
                <p className="text-lg font-bold tabular-nums">{data.supportedCount ?? supported.length}</p>
                <p className="text-[10px] text-muted-foreground">{isChinese ? "支持查询后缀" : "Queryable"}</p>
              </button>
              <button
                onClick={() => setTab("unsupported")}
                className={[
                  "glass-panel border rounded-xl p-3 text-center transition-all cursor-pointer",
                  tab === "unsupported"
                    ? "border-red-500/60 bg-red-500/8 ring-1 ring-red-500/30"
                    : "border-border hover:border-red-400/40 hover:bg-red-500/5",
                ].join(" ")}
              >
                <RiCloseCircleLine className={["w-4 h-4 mx-auto mb-1 transition-colors", tab === "unsupported" ? "text-red-500" : "text-red-400/70"].join(" ")} />
                <p className="text-lg font-bold tabular-nums">{data.unsupportedCount ?? unsupported.length}</p>
                <p className="text-[10px] text-muted-foreground">{isChinese ? "不支持查询后缀" : "Not queryable"}</p>
              </button>
            </div>
          )}

          {/* Detail counts for queryable set */}
          {!loading && supported.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 mb-5">
              <span className="text-[10px] px-2 py-1 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-400/20 inline-flex items-center gap-1">
                WHOIS {whoisCount}
              </span>
              <span className="text-[10px] px-2 py-1 rounded-full bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-400/20 inline-flex items-center gap-1">
                RDAP {rdapCount}
              </span>
              <span className="text-[11px] text-muted-foreground ml-1">
                {isChinese
                  ? `共 ${data?.total ?? 0} 个 IANA 后缀 · 至少一种协议可查的后缀可在此页列出`
                  : `${data?.total ?? 0} IANA suffixes total · listed here when queryable via at least one protocol`}
              </span>
            </div>
          )}

          <div className="flex items-center gap-1 mb-5 p-1 glass-panel border border-border rounded-xl">
            {(["supported", "unsupported"] as TabType[]).map((key) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                className={[
                  "flex-1 flex items-center justify-center gap-1.5 px-2 sm:px-4 py-2 rounded-lg text-sm font-medium transition-all min-w-0 overflow-hidden touch-manipulation select-none active:scale-[0.97]",
                  tab === key
                    ? "bg-primary text-primary-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted/60",
                ].join(" ")}
              >
                {key === "supported"
                  ? <RiCheckboxCircleLine className="w-4 h-4 shrink-0" />
                  : <RiCloseCircleLine className="w-4 h-4 shrink-0" />}
                <span className="truncate">
                  {key === "supported"
                    ? (isChinese ? "支持查询后缀" : "Queryable Suffixes")
                    : (isChinese ? "不支持查询后缀" : "Unsupported Suffixes")}
                </span>
              </button>
            ))}
          </div>

          {tab === "supported" ? (
            <div>
              {!loading && data && (
                <div className="flex items-center gap-1.5 mb-4">
                  <button
                    onClick={() => handleFilterClick("cctld")}
                    className={[
                      "inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border text-xs font-medium transition-colors",
                      typeFilter === "cctld"
                        ? "border-blue-500/50 bg-blue-500/10 text-blue-600 dark:text-blue-400"
                        : "border-border text-muted-foreground hover:text-foreground",
                    ].join(" ")}
                  >
                    <RiFlagLine className="w-3.5 h-3.5" />
                    {isChinese ? "国别域名" : "ccTLD"}
                    <span className="font-mono tabular-nums">{supported.filter((x) => x.type === "cctld").length}</span>
                  </button>
                  <button
                    onClick={() => handleFilterClick("gtld")}
                    className={[
                      "inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border text-xs font-medium transition-colors",
                      typeFilter === "gtld"
                        ? "border-violet-500/50 bg-violet-500/10 text-violet-600 dark:text-violet-400"
                        : "border-border text-muted-foreground hover:text-foreground",
                    ].join(" ")}
                  >
                    <RiStarLine className="w-3.5 h-3.5" />
                    {isChinese ? "通用顶级" : "gTLD"}
                    <span className="font-mono tabular-nums">{supported.filter((x) => x.type === "gtld").length}</span>
                  </button>
                </div>
              )}

              <div className="mb-4">
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
                  <p className="text-sm text-muted-foreground">{isChinese ? "未找到匹配的后缀" : "No matching suffixes found"}</p>
                </div>
              ) : (
                <>
                  <p className="text-[11px] text-muted-foreground mb-3">
                    {isChinese
                      ? `显示 ${filtered.length} 个可查询后缀（共 ${supported.length} 个）`
                      : `Showing ${filtered.length} of ${supported.length} queryable suffixes`}
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
                  {isChinese
                    ? "标注 WHOIS/RDAP 表示该后缀存在可用的查询通道 · 数据来源 IANA"
                    : "WHOIS/RDAP badges mean a usable query path exists · Data source: IANA"}
                </p>
              </div>
            </div>
          ) : (
            <div>
              <div className="mb-4">
                <div className="relative">
                  <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                  <Input
                    value={uSearch}
                    onChange={(e) => setUSearch(e.target.value)}
                    placeholder={isChinese ? "搜索后缀或国家名称..." : "Search suffix or country..."}
                    className="pl-9 h-9 text-sm"
                  />
                </div>
              </div>

              {loading ? (
                <div className="flex flex-col items-center justify-center py-20 gap-3">
                  <RiLoader4Line className="w-6 h-6 text-muted-foreground animate-spin" />
                  <p className="text-sm text-muted-foreground">{isChinese ? "正在加载 IANA 后缀列表..." : "Loading IANA TLD list..."}</p>
                </div>
              ) : filteredUnsupported.length === 0 ? (
                <div className="text-center py-16">
                  <RiCheckboxCircleLine className="w-8 h-8 mx-auto text-emerald-500/50 mb-3" />
                  <p className="text-sm text-muted-foreground">
                    {isChinese ? "没有不可查询的后缀" : "No unsupported suffixes"}
                  </p>
                </div>
              ) : (
                <>
                  <p className="text-[11px] text-muted-foreground mb-3">
                    {isChinese
                      ? `显示 ${filteredUnsupported.length} 个（共 ${unsupported.length} 个）`
                      : `Showing ${filteredUnsupported.length} of ${unsupported.length}`}
                  </p>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {filteredUnsupported.map((entry) => (
                      <TldCard key={entry.tld} entry={entry} isChinese={isChinese} />
                    ))}
                  </div>
                </>
              )}

              <div className="mt-10 pt-6 border-t border-border/40 text-center">
                <p className="text-[11px] text-muted-foreground/50">
                  {isChinese
                    ? "这些后缀在 IANA 注册，但公开渠道无可用 WHOIS/RDAP 服务器，暂无法查询"
                    : "Registered at IANA but expose no WHOIS/RDAP server — not queryable at present"}
                </p>
              </div>
            </div>
          )}
        </main>
      </ScrollArea>
    </>
  );
}
