/**
 * Shared types for the domain drop calendar.
 *
 * DropStage:
 *   pending_delete — entered the registry's pending-delete phase, drops within days
 *   expiring       — approaching expiry, drop date derived via TLD lifecycle rules
 *   deleted        — already deleted and re-open for registration (today's drops)
 */

export type DropStage = "pending_delete" | "expiring" | "deleted";

export type DateType = "source" | "derived";

export interface DropLeadView {
  domain: string;
  tld: string;
  dropDate: string;
  dropTime: string | null;
  dateType: DateType;
  source: string;
  valueScore: number;
  valueTier: string;
  reasons: string[];
}

export interface DropSourceStatusView {
  source: string;
  stage: DropStage;
  lastSuccessAt: string | null;
  stale: boolean;
}

export interface DropDayGroup {
  date: string;
  total: number;
  topTier: string;
  domains: DropLeadView[];
}

export interface DropStats {
  total: number;
  today: number;
  tlds: Array<{ tld: string; count: number }>;
  top: DropLeadView[];
}

export interface UserDropGroup {
  date: string;
  domains: Array<{ domain: string; reminder_id: string }>;
}

export interface DropsResponse {
  today: string;
  days: number;
  public_locked: boolean;
  sources: DropSourceStatusView[];
  drops: DropDayGroup[];
  stats: DropStats;
  user_drops: UserDropGroup[];
}
