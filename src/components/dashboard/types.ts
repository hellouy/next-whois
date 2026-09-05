import type { TranslationKey, InterpolationValues } from "@/lib/i18n";

export type Subscription = {
  id: string; domain: string; expiration_date: string | null;
  active: boolean; created_at: string; cancel_token: string;
  drop_date: string | null; grace_end: string | null; redemption_end: string | null;
  phase: string | null; days_to_expiry: number | null; days_to_drop: number | null;
  tld_confidence: string | null;
  days_before: number | null;
  sent_keys: number[];
  last_reminded_at: string | null;
  next_reminder_at: string | null;
  next_reminder_days: number | null;
  thresholds: number[];
  phase_flags: Record<string, boolean>;
  notify_email: string | null;
  paused: boolean;
  nameservers: string[];
  registrar: string | null;
  creation_date: string | null;
  whois_synced_at: string | null;
};

export type Order = {
  id: string;
  plan_name: string;
  amount: number;
  currency: string;
  provider: string;
  status: string;
  paid_at: string | null;
  created_at: string;
};

export type BalanceTx = {
  id: number;
  amount_cents: number;
  type: string;
  description: string | null;
  created_at: string;
};

export type Plan = {
  id: string;
  name: string;
  price: number;
  currency: string;
  duration_days: number | null;
  description: string | null;
  is_recurring: boolean;
  grants_subscription: boolean;
  balance_grant_cents: number;
};

export type Stamp = {
  id: string; domain: string; tag_name: string; tag_style: string; card_theme: string;
  link: string | null; description: string | null; nickname: string;
  verified: boolean; verified_at: string | null; created_at: string;
};

export const PHASE_LABEL: Record<string, { color: string }> = {
  active: { color: "text-emerald-600 dark:text-emerald-400" },
  grace: { color: "text-amber-600 dark:text-amber-400" },
  redemption: { color: "text-orange-600 dark:text-orange-400" },
  pendingDelete: { color: "text-red-600 dark:text-red-400" },
  dropped: { color: "text-muted-foreground" },
};

export const AVATAR_COLORS: { key: string; bg: string; text: string; label: string }[] = [
  { key: "violet", bg: "bg-violet-500", text: "text-white", label: "Aa" },
  { key: "blue",   bg: "bg-blue-500",   text: "text-white", label: "Aa" },
  { key: "emerald",bg: "bg-emerald-500",text: "text-white", label: "Aa" },
  { key: "orange", bg: "bg-orange-500", text: "text-white", label: "Aa" },
  { key: "pink",   bg: "bg-pink-500",   text: "text-white", label: "Aa" },
  { key: "red",    bg: "bg-red-500",    text: "text-white", label: "Aa" },
  { key: "yellow", bg: "bg-yellow-400", text: "text-black", label: "Aa" },
  { key: "slate",  bg: "bg-slate-600",  text: "text-white", label: "Aa" },
];

export const TAG_COLORS: Record<string, string> = {
  personal: "bg-teal-500 text-white",
  official: "bg-blue-500 text-white",
  brand:    "bg-violet-500 text-white",
  verified: "bg-emerald-500 text-white",
  partner:  "bg-orange-500 text-white",
  dev:      "bg-sky-500 text-white",
  warning:  "bg-amber-400 text-white",
  premium:  "bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white",
};

export function fmt(d: Date, locale?: string) {
  return d.toLocaleDateString(locale, { year: "numeric", month: "2-digit", day: "2-digit" });
}

export function daysUntilExpiry(sub: Subscription): number | null {
  return sub.days_to_expiry ?? null;
}

export interface DashboardUser {
  id?: string;
  name?: string | null;
  email?: string | null;
  image?: string | null;
  subscriptionAccess?: boolean;
}

export type TFunction = (key: TranslationKey, params?: InterpolationValues) => string;
