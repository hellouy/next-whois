/**
 * Admin: Domain Drop Snipe Targets
 * /admin/snipe-targets
 *
 * Manage domains targeted for automated drop-sniping: add targets (WHOIS
 * initialised), track drop ETA / price / balance, and pause / resume / cancel.
 * The hunt itself runs via Vercel cron + GitHub Actions; this page is the
 * control surface.
 */

import React, { useCallback, useEffect, useState } from "react";
import Head from "next/head";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  RiLoader4Line,
  RiAddLine,
  RiPauseLine,
  RiPlayLine,
  RiCloseLine,
  RiFlashlightLine,
  RiAlertLine,
} from "@remixicon/react";
import { toast } from "sonner";

interface SnipeTarget {
  id: string;
  domain: string;
  tld: string;
  status: string;
  max_price: number | null;
  est_price: number | null;
  is_premium: boolean | null;
  expiration_date: string | null;
  drop_eta: string | null;
  hunt_start: string | null;
  hunt_end: string | null;
  last_epp: string | null;
  last_whois_at: string | null;
  whois_fails: number;
  registered_at: string | null;
  netim_ope_id: string | null;
  final_price: number | null;
  fail_reason: string | null;
  notes: string | null;
  recharge_alerted_at: string | null;
  created_at: string;
  last_probe_result: string | null;
  last_probe_channel: string | null;
  last_probe_at: string | null;
}

const STATUS_META: Record<string, { label: string; cls: string }> = {
  watching:        { label: "观察中",      cls: "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300" },
  armed:           { label: "已就绪",      cls: "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300" },
  blocked_balance: { label: "余额不足",    cls: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300" },
  sniping:         { label: "抢注中",      cls: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300" },
  succeeded:       { label: "已注册",      cls: "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300" },
  failed:          { label: "失败",        cls: "bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300" },
  cancelled:       { label: "已取消",      cls: "bg-gray-200 text-gray-600 dark:bg-gray-800 dark:text-gray-400" },
  paused:          { label: "已暂停",      cls: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300" },
};

const TERMINAL = new Set(["succeeded", "failed", "cancelled"]);

export default function AdminSnipeTargetsPage() {
  const [targets, setTargets] = useState<SnipeTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [newDomain, setNewDomain] = useState("");
  const [newMaxPrice, setNewMaxPrice] = useState("");
  const [adding, setAdding] = useState(false);
  const [runningProbe, setRunningProbe] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/snipe-targets");
      const data = await r.json();
      setTargets(data.targets ?? []);
    } catch {
      toast.error("加载抢注目标失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const action = useCallback(async (id: string, act: string, extra?: { max_price?: number }) => {
    const r = await fetch(`/api/admin/snipe-targets?id=${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: act, ...extra }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error ?? "操作失败");
    return data;
  }, []);

  async function addTarget() {
    const domain = newDomain.trim();
    if (!domain) { toast.error("请输入域名"); return; }
    setAdding(true);
    try {
      const r = await fetch("/api/admin/snipe-targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, max_price: newMaxPrice || null }),
      });
      const data = await r.json();
      if (!r.ok) { toast.error(data.error ?? "新增失败"); return; }
      toast.success("已添加目标");
      setNewDomain(""); setNewMaxPrice(""); setShowAdd(false);
      await load();
    } catch {
      toast.error("新增失败");
    } finally {
      setAdding(false);
    }
  }

  async function act(id: string, fn: () => Promise<void>, okMsg: string) {
    try {
      await fn();
      toast.success(okMsg);
      await load();
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  async function setMaxPrice(id: string) {
    const v = window.prompt("设置抢注价格上限（欧元，空为不设限）");
    if (v === null) return;
    const num = v === "" ? null : Number(v);
    if (num !== null && (!Number.isFinite(num) || num <= 0)) {
      toast.error("请输入正数或留空");
      return;
    }
    await act(id, () => action(id, "max_price", { max_price: num ?? undefined }), "上限已更新");
  }

  async function runProbe(mode: "daily" | "hunt") {
    setRunningProbe(mode);
    try {
      const r = await fetch(`/api/cron/snipe-probe?mode=${mode}`, { method: "POST" });
      const data = await r.json();
      if (!r.ok) { toast.error(data.error ?? "触发失败"); return; }
      const counts = data.results ?? [];
      toast.success(`探测完成：${data.checked ?? 0} 个目标（干跑=${data.dryRun ? "是" : "否"}）`);
      await load();
    } catch {
      toast.error("触发探测失败");
    } finally {
      setRunningProbe(null);
    }
  }

  return (
    <AdminLayout title="抢注目标">
      <Head><title>抢注目标 · Admin</title></Head>

      <div className="space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-bold">域名掉落抢注</h2>
            <p className="text-sm text-muted-foreground mt-1">
              到期域名自动抢注。常规期由 Vercel cron 每日跟踪，掉落窗口（ETA−1d 至 ETA+2d）由 GitHub Actions 高频探测并触发注册。
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" className="rounded-xl h-9 gap-2"
              disabled={!!runningProbe}
              onClick={() => runProbe("daily")}>
              {runningProbe === "daily" ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiFlashlightLine className="w-4 h-4" />}
              立即日探测
            </Button>
            <Button variant="outline" size="sm" className="rounded-xl h-9 gap-2"
              disabled={!!runningProbe}
              onClick={() => runProbe("hunt")}>
              {runningProbe === "hunt" ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiFlashlightLine className="w-4 h-4" />}
              立即竞速探测
            </Button>
            <Button size="sm" className="rounded-xl h-9 gap-2" onClick={() => setShowAdd(v => !v)}>
              <RiAddLine className="w-4 h-4" />新增目标
            </Button>
          </div>
        </div>

        {showAdd && (
          <div className="border border-border rounded-2xl p-4 space-y-3 bg-card">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <Label className="text-xs">域名</Label>
                <Input className="rounded-xl mt-1" placeholder="example.sb" value={newDomain}
                  onChange={e => setNewDomain(e.target.value)} onKeyDown={e => { if (e.key === "Enter") void addTarget(); }} />
              </div>
              <div>
                <Label className="text-xs">价格上限（欧元，可空）</Label>
                <Input className="rounded-xl mt-1" placeholder="如 80（空 = 不设限）" value={newMaxPrice}
                  onChange={e => setNewMaxPrice(e.target.value)} onKeyDown={e => { if (e.key === "Enter") void addTarget(); }} />
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" size="sm" className="rounded-xl" onClick={() => setShowAdd(false)}>取消</Button>
              <Button size="sm" className="rounded-xl gap-2" disabled={adding} onClick={() => void addTarget()}>
                {adding ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : null}添加
              </Button>
            </div>
          </div>
        )}

        <div className="border border-border rounded-2xl overflow-hidden bg-card">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/40 text-left text-xs text-muted-foreground">
                  <th className="px-4 py-3 font-semibold">域名</th>
                  <th className="px-4 py-3 font-semibold">状态</th>
                  <th className="px-4 py-3 font-semibold">预计掉落</th>
                  <th className="px-4 py-3 font-semibold">预估价 / 上限</th>
                  <th className="px-4 py-3 font-semibold">最近探测</th>
                  <th className="px-4 py-3 font-semibold">操作</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                    <RiLoader4Line className="w-4 h-4 animate-spin inline mr-1" />加载中…
                  </td></tr>
                ) : targets.length === 0 ? (
                  <tr><td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">暂无目标，点击右上角新增</td></tr>
                ) : targets.map(t => {
                  const meta = STATUS_META[t.status] ?? { label: t.status, cls: "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300" };
                  const terminal = TERMINAL.has(t.status);
                  return (
                    <tr key={t.id} className="border-b border-border/60 hover:bg-muted/30">
                      <td className="px-4 py-3">
                        <div className="font-mono font-semibold">{t.domain}</div>
                        {t.is_premium ? <span className="text-[10px] text-amber-600 dark:text-amber-400">premium</span> : null}
                        {t.fail_reason ? (
                          <div className="text-[11px] text-rose-600 dark:text-rose-400 flex items-center gap-1 mt-0.5">
                            <RiAlertLine className="w-3 h-3" />{t.fail_reason}
                          </div>
                        ) : null}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-medium ${meta.cls}`}>{meta.label}</span>
                        {t.whois_fails >= 3 ? <div className="text-[10px] text-amber-600 mt-1">WHOIS 连续失败 {t.whois_fails} 次</div> : null}
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-mono">{t.drop_eta ?? "—"}</div>
                        <div className="text-[11px] text-muted-foreground mt-0.5">到期 {t.expiration_date ?? "—"}</div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-mono">
                          {t.est_price != null ? `€ ${t.est_price}` : "—"}
                          {t.max_price != null ? <span className="text-muted-foreground"> / € {t.max_price}</span> : null}
                        </div>
                        {t.final_price != null ? <div className="text-[11px] text-emerald-600">成交 € {t.final_price}</div> : null}
                      </td>
                      <td className="px-4 py-3">
                        {t.last_probe_at ? (
                          <>
                            <span className={`text-xs ${t.last_probe_result === "available" ? "text-emerald-600" : t.last_probe_result === "error" ? "text-rose-600" : "text-muted-foreground"}`}>
                              {t.last_probe_result ?? "—"} / {t.last_probe_channel ?? "—"}
                            </span>
                            <div className="text-[11px] text-muted-foreground mt-0.5">
                              {new Date(t.last_probe_at).toLocaleString("zh-CN", { hour12: false })}
                            </div>
                          </>
                        ) : <span className="text-muted-foreground">—</span>}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          {t.status === "paused" ? (
                            <Button variant="ghost" size="sm" className="rounded-lg h-8 gap-1 text-xs"
                              onClick={() => act(t.id, () => action(t.id, "resume"), "已恢复")}>
                              <RiPlayLine className="w-3.5 h-3.5" />恢复
                            </Button>
                          ) : !terminal && (
                            <Button variant="ghost" size="sm" className="rounded-lg h-8 gap-1 text-xs"
                              onClick={() => act(t.id, () => action(t.id, "pause"), "已暂停")}>
                              <RiPauseLine className="w-3.5 h-3.5" />暂停
                            </Button>
                          )}
                          {!terminal && (
                            <Button variant="ghost" size="sm" className="rounded-lg h-8 gap-1 text-xs"
                              onClick={() => act(t.id, () => action(t.id, "cancel"), "已取消")}>
                              <RiCloseLine className="w-3.5 h-3.5" />取消
                            </Button>
                          )}
                          <Button variant="ghost" size="sm" className="rounded-lg h-8 text-xs"
                            onClick={() => void setMaxPrice(t.id)}>
                            上限
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </AdminLayout>
  );
}
