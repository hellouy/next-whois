/**
 * Server-side Sentry integration (lazy, no-op without SENTRY_DSN).
 *
 * Used by src/lib/logger.ts (error level) and any API route that wants
 * explicit capture. The SDK is initialized on first capture so no global
 * bootstrap module is required on the pages router.
 *
 * Source-map upload to Sentry is intentionally not configured (needs
 * SENTRY_AUTH_TOKEN); stack traces reference built files.
 */
import * as Sentry from "@sentry/nextjs";

let initialized = false;

function ensureInit(): boolean {
  if (initialized) return !!process.env.SENTRY_DSN;
  initialized = true;
  const dsn = process.env.SENTRY_DSN;
  if (!dsn) return false;
  try {
    Sentry.init({
      dsn,
      environment: process.env.NODE_ENV,
      tracesSampleRate: 0, // error reporting only, no tracing
      spotlight: false,
    });
  } catch {
    return false;
  }
  return true;
}

export function captureException(err: unknown, context?: Record<string, unknown>) {
  if (!ensureInit()) return;
  try {
    const error = err instanceof Error ? err : new Error(String(err));
    Sentry.captureException(error, { extra: context });
  } catch {
    // Never let telemetry break the request path.
  }
}

/** Report an error-level log line that has no Error object attached. */
export function captureMessage(msg: string, context?: Record<string, unknown>) {
  if (!ensureInit()) return;
  try {
    Sentry.withScope(scope => {
      if (context) {
        for (const [k, v] of Object.entries(context)) scope.setExtra(k, v);
      }
      Sentry.captureMessage(msg, "error");
    });
  } catch {
    // Never let telemetry break the request path.
  }
}
