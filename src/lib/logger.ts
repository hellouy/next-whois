/**
 * Lightweight structured JSON logger.
 * Server-side: emits newline-delimited JSON (NDJSON) — compatible with
 * Vercel log aggregation, Datadog, Loki, etc.
 * Client-side: falls back to the browser console methods so DevTools stay readable.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogEntry {
  ts: string;
  level: LogLevel;
  ctx: string;
  msg: string;
  [key: string]: unknown;
}

const IS_SERVER = typeof window === "undefined";
const IS_DEV    = process.env.NODE_ENV === "development";

function emit(level: LogLevel, ctx: string, msg: string, meta?: Record<string, unknown>) {
  if (IS_SERVER) {
    const entry: LogEntry = {
      ts:    new Date().toISOString(),
      level,
      ctx,
      msg,
      ...meta,
    };
    const line = JSON.stringify(entry);
    if (level === "error" || level === "warn") {
      process.stderr.write(line + "\n");
    } else {
      process.stdout.write(line + "\n");
    }
  } else {
    const prefix = `[${ctx}]`;
    if (level === "debug" && !IS_DEV) return;
    const fn = level === "error" ? console.error
             : level === "warn"  ? console.warn
             : level === "debug" ? console.debug
             : console.log;
    meta ? fn(prefix, msg, meta) : fn(prefix, msg);
  }
}

export function createLogger(ctx: string) {
  return {
    debug: (msg: string, meta?: Record<string, unknown>) => emit("debug", ctx, msg, meta),
    info:  (msg: string, meta?: Record<string, unknown>) => emit("info",  ctx, msg, meta),
    warn:  (msg: string, meta?: Record<string, unknown>) => emit("warn",  ctx, msg, meta),
    error: (msg: string, meta?: Record<string, unknown>) => emit("error", ctx, msg, meta),
  };
}

export type Logger = ReturnType<typeof createLogger>;
