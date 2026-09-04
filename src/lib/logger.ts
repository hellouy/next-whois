/**
 * Lightweight structured JSON logger.
 * Server-side: emits newline-delimited JSON (NDJSON) — compatible with
 * Vercel log aggregation, Datadog, Loki, etc. `error` level also reports
 * to Sentry when SENTRY_DSN is configured (lazy SDK import).
 * Client-side: falls back to the browser console methods so DevTools stay readable.
 *
 * Method signature intentionally mirrors console.* (msg, ...args) so
 * migrating a call site is a pure textual rename with zero semantic risk.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogEntry {
  ts: string;
  level: LogLevel;
  ctx: string;
  msg: string;
  [key: string]: unknown;
}

const LEVELS: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };

const IS_SERVER = typeof window === "undefined";
const IS_DEV    = process.env.NODE_ENV === "development";

function minLevel(): LogLevel {
  const env = process.env.LOG_LEVEL as LogLevel | undefined;
  if (env && env in LEVELS) return env;
  return IS_DEV ? "debug" : "info";
}

function serializeArg(a: unknown): unknown {
  if (a instanceof Error) {
    return {
      name: a.name,
      message: a.message,
      stack: a.stack ? a.stack.split("\n").slice(0, 10).join("\n") : undefined,
    };
  }
  if (a === null || a === undefined) return a;
  switch (typeof a) {
    case "string":
    case "number":
    case "boolean":
      return a;
    default:
      try {
        return JSON.parse(JSON.stringify(a));
      } catch {
        return String(a);
      }
  }
}

function emit(level: LogLevel, ctx: string, msg: string, args: unknown[]) {
  if (LEVELS[level] < LEVELS[minLevel()]) return;

  if (IS_SERVER) {
    const entry: LogEntry = { ts: new Date().toISOString(), level, ctx, msg };
    if (args.length === 1) entry.arg = serializeArg(args[0]);
    else if (args.length > 1) entry.args = args.map(serializeArg);
    const line = JSON.stringify(entry);

    // Edge runtime (middleware) has no process.stdout — console fallback.
    const out = level === "error" || level === "warn" ? process.stderr : process.stdout;
    if (typeof out !== "undefined" && out && typeof out.write === "function") {
      out.write(line + "\n");
    } else {
      (level === "error" ? console.error : level === "warn" ? console.warn : console.log)(line);
    }

    if (level === "error" && process.env.SENTRY_DSN) {
      const errArg = args.find(a => a instanceof Error);
      // Fire-and-forget: server-only chunk; the client bundle never
      // downloads it because non-NEXT_PUBLIC env vars compile away.
      void import("./monitoring-server")
        .then(m =>
          errArg
            ? m.captureException(errArg, { ctx, msg })
            : m.captureMessage(msg, { ctx, args: args.map(serializeArg) }),
        )
        .catch(() => {});
    }
  } else {
    if (level === "debug" && !IS_DEV) return;
    const fn = level === "error" ? console.error
             : level === "warn"  ? console.warn
             : level === "debug" ? console.debug
             : console.log;
    const prefix = `[${ctx}]`;
    args.length ? fn(prefix, msg, ...args) : fn(prefix, msg);
  }
}

export function createLogger(ctx: string) {
  return {
    debug: (msg: string, ...args: unknown[]) => emit("debug", ctx, msg, args),
    info:  (msg: string, ...args: unknown[]) => emit("info",  ctx, msg, args),
    warn:  (msg: string, ...args: unknown[]) => emit("warn",  ctx, msg, args),
    error: (msg: string, ...args: unknown[]) => emit("error", ctx, msg, args),
  };
}

export type Logger = ReturnType<typeof createLogger>;
