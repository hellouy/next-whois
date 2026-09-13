/**
 * snipe-pricing.ts — user-facing domain preorder pricing.
 *
 * Service price for a user-snipe target = EUR registration price from Netim
 * (queryDomainPrice) × fixed FX rate (snipe_eur_fx_rate) × markup (snipe_markup).
 * Pricing is always recomputed server-side so a client can never lower it.
 */

import { getSetting } from "@/lib/server/site-settings-server";
import { netimQueryDomainPrice } from "@/lib/server/netim-client";
import { createLogger } from "@/lib/logger";

const logger = createLogger("server/snipe-pricing");

export const DEFAULT_FX_RATE = 8.0;
export const DEFAULT_MARKUP = 4;
export const FX_RATE_SETTING_KEY = "snipe_eur_fx_rate";
export const MARKUP_SETTING_KEY = "snipe_markup";

/** Read the configured EUR→CNY FX rate from site_settings, falling back to 8.0. */
export async function getFxRate(): Promise<number> {
  const raw = await getSetting(FX_RATE_SETTING_KEY, String(DEFAULT_FX_RATE));
  const n = Number(raw.trim());
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_FX_RATE;
}

/** Read the configured markup (how many × the CNY cost is charged), default 4. */
export async function getMarkup(): Promise<number> {
  const raw = await getSetting(MARKUP_SETTING_KEY, String(DEFAULT_MARKUP));
  const n = Number(raw.trim());
  return Number.isFinite(n) && n >= 1 ? Math.round(n) : DEFAULT_MARKUP;
}

export interface SnipeQuote {
  domain: string;
  eurCost: number | null;      // Netim registration fee, EUR
  cnyCost: number | null;      // eurCost × fxRate
  serviceCents: number | null; // round(cnyCost × markup × 100)
  fxRate: number;
  markup: number;
  isPremium: boolean | null;
  error?: string;
}

/**
 * Compute the service price for a user preorder. Returns null when the Netim
 * price query fails (no usable quote) so callers can keep the previous price.
 */
export async function snipeServicePrice(domain: string): Promise<SnipeQuote | null> {
  const [fxRate, markup, price] = await Promise.all([getFxRate(), getMarkup(), netimQueryDomainPrice(domain)]);

  if (!price) {
    return {
      domain,
      eurCost: null,
      cnyCost: null,
      serviceCents: null,
      fxRate,
      markup,
      isPremium: null,
      error: "无法获取该域名的注册报价",
    };
  }

  const eurCost = price.price ?? null;
  const cnyCost = eurCost === null || eurCost < 0 ? null : eurCost * fxRate;
  const serviceCents =
    cnyCost === null ? null : Math.max(1, Math.round(cnyCost * markup * 100));

  return {
    domain,
    eurCost,
    cnyCost,
    serviceCents,
    fxRate,
    markup,
    isPremium: price.isPremium ?? null,
  };
}