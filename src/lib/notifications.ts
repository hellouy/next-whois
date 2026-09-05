import { randomBytes } from "crypto";
import { run } from "@/lib/db-query";
import { createLogger } from "@/lib/logger";

const logger = createLogger("lib/notifications");

export type NotificationType =
  | "threshold"
  | "grace"
  | "redemption"
  | "pending_delete"
  | "drop_soon"
  | "dropped"
  | "hold"
  | "reserved"
  | "membership";

/**
 * Insert a notification row for an account. Best-effort: failures are logged
 * and swallowed so notification recording never breaks the reminder pipeline.
 */
export async function recordNotification(p: {
  email: string;
  type: NotificationType;
  title: string;
  body?: string;
  domain?: string;
}): Promise<void> {
  const id = randomBytes(10).toString("hex");
  try {
    await run(
      `INSERT INTO user_notifications (id, email, type, title, body, domain)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [id, p.email, p.type, p.title, p.body ?? null, p.domain ?? null],
    );
  } catch (err) {
    logger.warn("[notifications] record failed:", err instanceof Error ? err.message : String(err));
  }
}

/** Marks a single notification as read. */
export async function markNotificationRead(id: string, email: string): Promise<void> {
  try {
    await run(
      `UPDATE user_notifications SET read_at = NOW() WHERE id = $1 AND email = $2`,
      [id, email],
    );
  } catch (err) {
    logger.warn("[notifications] mark read failed:", err instanceof Error ? err.message : String(err));
  }
}

/** Marks all notifications for an account as read. */
export async function markAllNotificationsRead(email: string): Promise<void> {
  try {
    await run(
      `UPDATE user_notifications SET read_at = NOW() WHERE email = $1 AND read_at IS NULL`,
      [email],
    );
  } catch (err) {
    logger.warn("[notifications] mark-all read failed:", err instanceof Error ? err.message : String(err));
  }
}
