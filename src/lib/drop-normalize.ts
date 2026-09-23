/**
 * Normalization helpers for drop-calendar leads: date parsing, stage
 * classification and source-vs-derived date resolution.
 */

import type { DateType, DropStage } from "@/lib/drop-types";

const MONTHS: Record<string, number> = {
  jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6,
  jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12,
};

/** Build a validated ISO date (UTC) or null when the calendar date is invalid. */
function buildUtcDate(year: number, month: number, day: number): string | null {
  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  const dt = new Date(Date.UTC(year, month - 1, day));
  if (
    dt.getUTCFullYear() !== year ||
    dt.getUTCMonth() !== month - 1 ||
    dt.getUTCDate() !== day
  ) {
    return null;
  }
  return dt.toISOString().slice(0, 10);
}

/**
 * Parse a drop date into `YYYY-MM-DD`.
 *
 * Year-only values (e.g. "2018") return null: they carry no calendar
 * precision and must not be advertised as an upcoming drop date.
 */
export function parseDropDate(input: string | null | undefined): string | null {
  if (input === null || input === undefined) return null;
  const s = String(input).trim();
  if (!s || s === "-" || /^n\/?a$/i.test(s)) return null;

  // ISO — 2026-09-25
  let m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
  if (m) return buildUtcDate(+m[1], +m[2], +m[3]);

  // Slashed ISO — 2026/09/25
  m = s.match(/^(\d{4})\/(\d{1,2})\/(\d{1,2})$/);
  if (m) return buildUtcDate(+m[1], +m[2], +m[3]);

  // Day-first textual — 25-Sep-2026 / 25 Sep 2026
  m = s.match(/^(\d{1,2})[-\s]([A-Za-z]{3,})[-\s](\d{4})$/);
  if (m) {
    const mon = MONTHS[m[2].slice(0, 3).toLowerCase()];
    if (mon) return buildUtcDate(+m[3], mon, +m[1]);
  }

  // Month-first textual — Sep 25, 2026 / Sep 25 2026
  m = s.match(/^([A-Za-z]{3,})\s+(\d{1,2}),?\s+(\d{4})$/);
  if (m) {
    const mon = MONTHS[m[1].slice(0, 3).toLowerCase()];
    if (mon) return buildUtcDate(+m[3], mon, +m[2]);
  }

  // US numeric — 09/25/2026
  m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (m) return buildUtcDate(+m[3], +m[1], +m[2]);

  return null;
}

const STAGE_LABELS: Array<[RegExp, DropStage]> = [
  [/pending[\s_-]?delete|redemption/i, "pending_delete"],
  [/pre[\s_-]?release|expir|grace|soon/i, "expiring"],
  [/delet|drop|availab|releas/i, "deleted"],
];

/** Normalize a source-specific status label into a DropStage, or null. */
export function classifyStage(raw: string | null | undefined): DropStage | null {
  if (!raw) return null;
  const s = String(raw).trim();
  if (!s) return null;
  for (const [re, stage] of STAGE_LABELS) {
    if (re.test(s)) return stage;
  }
  return null;
}

export interface ResolvedDropDate {
  dropDate: string | null;
  dateType: DateType;
  deviationDays: number | null;
}

/**
 * Resolve the effective drop date. A source-provided date always wins over a
 * lifecycle-derived date; the deviation between the two is reported so the
 * admin can audit derived estimates.
 */
export function resolveDropDate(
  sourceDate: string | null | undefined,
  derivedDate: string | null | undefined,
): ResolvedDropDate {
  const src = sourceDate ?? null;
  const der = derivedDate ?? null;

  if (src && der) {
    return { dropDate: src, dateType: "source", deviationDays: diffDays(src, der) };
  }
  if (src) return { dropDate: src, dateType: "source", deviationDays: null };
  if (der) return { dropDate: der, dateType: "derived", deviationDays: null };
  return { dropDate: null, dateType: "source", deviationDays: null };
}

/** Absolute day difference between two ISO dates. */
export function diffDays(a: string, b: string): number {
  const ta = Date.parse(`${a}T00:00:00Z`);
  const tb = Date.parse(`${b}T00:00:00Z`);
  if (Number.isNaN(ta) || Number.isNaN(tb)) return 0;
  return Math.round(Math.abs(ta - tb) / 86_400_000);
}

/** Whether an ISO date falls inside the inclusive [today, today+days] window. */
export function inWindow(date: string, today: string, days: number): boolean {
  if (date < today) return false;
  const end = new Date(Date.parse(`${today}T00:00:00Z`) + days * 86_400_000)
    .toISOString()
    .slice(0, 10);
  return date <= end;
}
