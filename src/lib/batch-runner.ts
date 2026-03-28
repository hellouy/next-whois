/**
 * batch-runner.ts — Client-side singleton batch scraper
 *
 * Lives at module level, so it survives Next.js client-side navigation.
 * Navigating from /admin/tld-rules to any other admin page and back will
 * find the batch still running and its progress intact.
 *
 * Stops only when:
 *  a) The admin clicks "Stop"
 *  b) All TLDs in the list have been processed
 *  c) The browser tab is closed / hard-refreshed (F5)
 */

export type BatchItem = {
  tld: string;
  status: "pending" | "ok" | "error" | "skipped";
  msg?: string;
};

export type BatchStatus = "idle" | "running" | "stopped" | "done";

export interface BatchState {
  status: BatchStatus;
  items: BatchItem[];
  idx: number;
  model?: string;
}

type Listener = () => void;

// ── Singleton state ───────────────────────────────────────────────────────────
let _state: BatchState = { status: "idle", items: [], idx: 0, model: "" };
let _list: { tld: string; source_url?: string }[] = [];
let _aborted = false;
const _listeners = new Set<Listener>();

function _notify() {
  _listeners.forEach(fn => fn());
}

// ── Public API ────────────────────────────────────────────────────────────────

/** Subscribe to state changes. Returns an unsubscribe function. */
export function subscribe(fn: Listener): () => void {
  _listeners.add(fn);
  return () => { _listeners.delete(fn); };
}

/** Read current state (call getBatchState() inside render or event handlers). */
export function getState(): Readonly<BatchState> {
  return _state;
}

/**
 * Populate the grid from the current DB state without starting the batch.
 * Called on page load and after tab changes. Ignored when a batch is running.
 */
export function initFromDb(
  list: { tld: string }[],
  rules: {
    tld: string;
    scrape_status: string;
    failure_reason?: string | null;
    scraped_at?: string | null;
    manually_edited?: boolean;
  }[]
) {
  if (_state.status === "running") return;
  if (list.length === 0 || rules.length === 0) return;

  const items: BatchItem[] = list.map(t => {
    const r = rules.find(x => x.tld === t.tld);
    if (r?.manually_edited)
      return { tld: t.tld, status: "skipped" as const, msg: "手动修改" };
    if (r?.scrape_status === "ok")
      return { tld: t.tld, status: "ok" as const, msg: r.scraped_at?.slice(0, 10) ?? "" };
    if (r?.scrape_status === "failed" || r?.scrape_status === "no_data")
      return { tld: t.tld, status: "error" as const, msg: r.failure_reason ?? r.scrape_status };
    if (r?.scrape_status === "warn_defaults")
      return { tld: t.tld, status: "error" as const, msg: "仅默认值" };
    return { tld: t.tld, status: "pending" as const };
  });

  _state = { ..._state, items };
  _notify();
}

/**
 * Start the batch. Skips TLDs that are already ok or manually-edited.
 * Retries all failed / warn_defaults / pending TLDs.
 */
export function start(
  list: { tld: string; source_url?: string }[],
  rules: {
    tld: string;
    scrape_status: string;
    scraped_at?: string | null;
    manually_edited?: boolean;
  }[],
  model?: string
) {
  if (_state.status === "running") return;

  _list = list;
  _aborted = false;

  const items: BatchItem[] = list.map(t => {
    const r = rules.find(x => x.tld === t.tld);
    if (r?.manually_edited)
      return { tld: t.tld, status: "skipped" as const, msg: "手动修改，已跳过" };
    if (r?.scrape_status === "ok")
      return { tld: t.tld, status: "skipped" as const, msg: `已成功 (${r.scraped_at?.slice(0, 10) ?? "—"})` };
    return { tld: t.tld, status: "pending" as const };
  });

  const pending = items.filter(i => i.status === "pending");
  if (pending.length === 0) {
    _state = { status: "done", items, idx: items.length, model };
    _notify();
    return;
  }

  const firstPending = items.findIndex(i => i.status === "pending");
  _state = { status: "running", items, idx: firstPending, model };
  _notify();

  _runLoop().catch(err => console.error("[BatchRunner] Loop error:", err));
}

/** Stop the running batch. Progress up to this point is preserved. */
export function stop() {
  _aborted = true;
  _state = { ..._state, status: "stopped" };
  _notify();
}

// ── Internal loop (pure async, no React dependency) ──────────────────────────
async function _runLoop() {
  while (true) {
    if (_aborted || _state.status !== "running") break;

    const { items, idx } = _state;
    const nextPending = items.findIndex((it, i) => i >= idx && it.status === "pending");

    if (nextPending === -1) {
      _state = { ..._state, status: "done" };
      _notify();
      break;
    }

    // Jump forward to next pending without making an API call
    if (nextPending !== idx) {
      _state = { ..._state, idx: nextPending };
      _notify();
      continue;
    }

    const item = items[idx];
    const meta = _list.find(t => t.tld === item.tld);

    try {
      const res = await fetch("/api/admin/tld-rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tld: item.tld,
          source_url: meta?.source_url,
          model: _state.model || undefined,
        }),
      });

      if (_aborted) break;

      const data = await res.json();
      const newItems = [..._state.items];

      if (!res.ok) {
        newItems[idx] = {
          ...item,
          status: res.status === 429 ? "skipped" : "error",
          msg: data.error ?? `HTTP ${res.status}`,
        };
      } else if (data.skipped) {
        const msg =
          data.reason === "manually_edited" ? "手动修改，已保护" :
          data.reason === "already_ok"      ? `已成功 (${data.scraped_at?.slice(0, 10) ?? "—"})` :
                                              "已跳过";
        newItems[idx] = { ...item, status: "skipped", msg };
      } else {
        newItems[idx] = { ...item, status: "ok", msg: `${data.total_release_days}d` };
      }

      _state = { ..._state, items: newItems };
      _notify();
    } catch (err: unknown) {
      if (_aborted) break;
      const newItems = [..._state.items];
      newItems[idx] = {
        ...item,
        status: "error",
        msg: err instanceof Error ? err.message : "网络错误",
      };
      _state = { ..._state, items: newItems };
      _notify();
    }

    if (!_aborted) {
      await new Promise(r => setTimeout(r, 800));
      _state = { ..._state, idx: _state.idx + 1 };
      _notify();
    }
  }
}
