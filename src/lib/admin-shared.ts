// Warn once per process — not on every hot-reload or API call.
import { createLogger } from "@/lib/logger";

const logger = createLogger("admin-shared");

let _warnedOnce = false;
if (!process.env.ADMIN_EMAIL && !_warnedOnce) {
  _warnedOnce = true;
  logger.warn(
    "[admin] ADMIN_EMAIL environment variable is not set. " +
    "Please configure it to secure the admin account."
  );
}

export const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();

export function isAdmin(email?: string | null): boolean {
  if (!ADMIN_EMAIL) return false;
  return !!email && email.toLowerCase().trim() === ADMIN_EMAIL;
}
