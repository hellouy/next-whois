import React from "react";
import Head from "next/head";
import { useRouter } from "next/router";
import { AdminLayout } from "@/components/admin-layout";
import { cn } from "@/lib/utils";
import {
  RiGlobalLine,
  RiRobot2Line,
  RiAlertLine,
  RiServerLine,
  RiBarChartLine,
  RiSettings3Line,
} from "@remixicon/react";
import { CrawlTab } from "@/components/admin/hub/crawl-tab";
import { LifecycleTab } from "@/components/admin/hub/lifecycle-tab";
import { FailuresTab } from "@/components/admin/hub/failures-tab";
import { WhoisTab } from "@/components/admin/hub/whois-tab";
import { CompareTab } from "@/components/admin/hub/compare-tab";

type HubTab = "crawl" | "lifecycle" | "failures" | "whois" | "compare";

const TABS: { key: HubTab; label: string; icon: React.ElementType; desc: string }[] = [
  { key: "crawl",     label: "AI 批量抓取", icon: RiRobot2Line,    desc: "覆盖率 + 真实进度" },
  { key: "lifecycle", label: "生命周期规划", icon: RiSettings3Line, desc: "AI 导入/覆盖/反馈" },
  { key: "failures",  label: "失败记录",     icon: RiAlertLine,     desc: "失败统计与操练" },
  { key: "whois",     label: "WHOIS 服务器", icon: RiServerLine,   desc: "自定义服务器" },
  { key: "compare",   label: "对比分析",     icon: RiBarChartLine,  desc: "生命周期对比" },
];

function matchTab(v: string | undefined): HubTab {
  if (v === "lifecycle" || v === "failures" || v === "whois" || v === "compare") return v;
  return "crawl";
}

export default function TldsHubPage() {
  const router = useRouter();
  const tabParam = router.query.tab as string | undefined;
  const [activeTab, setActiveTab] = React.useState<HubTab>(() => matchTab(tabParam));

  React.useEffect(() => {
    setActiveTab(matchTab(tabParam));
  }, [tabParam]);

  return (
    <AdminLayout title="域名与 TLD">
      <Head><title>域名与 TLD · Admin</title></Head>
      <div className="space-y-5">
        <div>
          <h1 className="text-lg font-bold flex items-center gap-2">
            <RiGlobalLine className="w-5 h-5 text-primary" />域名与 TLD
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">TLD 生命周期规划、AI 批量抓取（实时覆盖率）、失败记录、WHOIS 服务器、对比分析统一管理</p>
        </div>

        {/* Tab selector */}
        <div className="flex gap-1.5 p-1 rounded-2xl bg-muted/40 border border-border overflow-x-auto">
          {TABS.map(t => (
            <button key={t.key} onClick={() => setActiveTab(t.key)}
              className={cn(
                "flex-1 flex items-center justify-center gap-1.5 py-2.5 px-3 rounded-xl text-xs font-semibold transition-all whitespace-nowrap",
                activeTab === t.key
                  ? "bg-background shadow-sm text-foreground border border-border"
                  : "text-muted-foreground hover:text-foreground"
              )}>
              <t.icon className="w-3.5 h-3.5 shrink-0" />
              <span className="hidden sm:inline">{t.label}</span>
              <span className="sm:hidden">{t.label.split(" ")[0]}</span>
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div className="space-y-5">
          {activeTab === "crawl" && <CrawlTab />}
          {activeTab === "lifecycle" && <LifecycleTab />}
          {activeTab === "failures" && <FailuresTab />}
          {activeTab === "whois" && <WhoisTab />}
          {activeTab === "compare" && <CompareTab />}
        </div>
      </div>
    </AdminLayout>
  );
}