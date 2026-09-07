/**
 * Shared helpers for human-friendly access codes (invite codes / activation codes).
 */
import { randomBytes } from "crypto";

/** Generate a readable code like "ABC123-DEF456-GHI789" from three random bytes. */
export function genHumanCode(): string {
  const seg = () => randomBytes(3).toString("hex").toUpperCase();
  return `${seg()}-${seg()}-${seg()}`;
}

const DURATION_DAYS: Record<string, number> = {
  "1d": 1,
  "7d": 7,
  "30d": 30,
  "365d": 365,
};

/**
 * Resolve a duration token ("1d" | "7d" | "30d" | "365d" | "permanent") to an
 * ISO expiry timestamp, or null when the code never expires.
 * Returns null for unknown durations as well.
 */
export function parseExpiresAt(duration: string | undefined): string | null {
  if (!duration || duration === "permanent") return null;
  const days = DURATION_DAYS[duration];
  if (!days) return null;
  const now = new Date();
  now.setDate(now.getDate() + days);
  return now.toISOString();
}