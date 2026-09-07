import React from "react";
import { cn } from "@/lib/utils";
import { RiRobot2Line, RiRefreshLine } from "@remixicon/react";
import { TldRulesWorkspace } from "@/pages/admin/tld-rules";

interface CrawlProgress {
  status: string;
  done: number;
  total: number;
  ok: number;
  skipped: number;
  errors: number;
  default_only: number;
  current_tld: string | null;
  pid: number | null;
  started_at: string | null;
  updated_at: string | null;
}

const POLL_MS = 15_000;

export function CrawlTab() {
  const [progress, setProgress] = React.useState<CrawlProgress | null>(null);
  const [stale, setStale] = React.useState(false);

  React.useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setInterval> | null = null;
    const progressRef = { current: progress };
    progressRef.current = progress;

    const poll = async () => {
      try {
        const res = await fetch("/api/admin/tld-crawl-progress");
        const data = await res.json();
        if (!res.ok || !active) return;
        progressRef.current = data.progress ?? null;
        setProgress(data.progress ?? null);
        setStale(false);
      } catch {
        if (active) setStale(true);
      }
    };

    poll();
    timer = setInterval(async () => {
      await poll();
      if (progressRef.current?.status !== "running") clearInterval(timer!);
    }, POLL_MS);

    return () => { active = false; if (timer) clearInterval(timer); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const pct = progress && progress.total > 0
    ? Math.min(100, Math.round((progress.done / progress.total) * 100))
    : 0;
  const showBanner = !!progress && (progress.status === "running" || (progress.status !== "done" && !stale));

  return (
    <div className="space-y-4">
      {showBanner && (
        <div className="border rounded-xl bg-card overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b bg-muted/30 gap-2 flex-wrap">
            <div className="flex items-center gap-2 min-w-0">
              <RiRobot2Line className={cn("w-4 h-4 shrink-0", progress.status === "running" ? "text-violet-500 animate-pulse" : "text-violet-500")} />
              <span className="font-medium text-sm">后台脚本进度</span>
              <span className="text-xs text-muted-foreground hidden sm:inline">
                {stale ? "— 进度暂不可用" : `— ${progress.status === "running" ? "抓取中" : progress.status === "done" ? "已完成" : progress.status}`}
              </span>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <span className="text-xs font-mono font-bold text-muted-foreground">{progress.done} / {progress.total}</span>
              {progress.status === "running" && (
                <span className="inline-flex items-center gap-1 text-[11px] px-2.5 py-1 rounded-lg bg-violet-100 dark:bg-violet-950/30 text-violet-700 dark:text-violet-400 font-medium">
                  <RiRefreshLine className="w-3 h-3 animate-spin" />每 15s 刷新
                </span>
              )}
            </div>
          </div>
          {progress.total > 0 && (
            <div className="h-1.5 bg-muted">
              <div className="h-full bg-violet-500 transition-all" style={{ width: `${pct}%` }} />
            </div>
          )}
          <div className="px-5 py-3 flex flex-wrap gap-x-5 gap-y-1.5 text-xs text-muted-foreground">
            {progress.status === "running" && progress.current_tld && (
              <span className="truncate max-w-xs">当前: {progress.current_tld}</span>
            )}
            {progress.started_at && <span>开始 {new Date(progress.started_at).toLocaleTimeString()}</span>}
            {progress.updated_at && <span>更新 {new Date(progress.updated_at).toLocaleTimeString()}</span>}
            <span>成功 {progress.ok} · 跳过 {progress.skipped} · 错误 {progress.errors} · 默认值 {progress.default_only}</span>
          </div>
        </div>
      )}
      <TldRulesWorkspace embedded initialTab="cc" workspaceTabs={["cc", "gtld"]} />
    </div>
  );
}

export default CrawlTab;