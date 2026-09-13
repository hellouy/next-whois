import { describe, it, expect, vi, beforeEach } from "vitest";

const mocks = {
  getSetting: vi.fn(),
  netimQueryDomainPrice: vi.fn(),
};

vi.mock("@/lib/server/site-settings-server", () => ({
  getSetting: (...a: unknown[]) => mocks.getSetting(...a),
}));

vi.mock("@/lib/server/netim-client", () => ({
  netimQueryDomainPrice: (...a: unknown[]) => mocks.netimQueryDomainPrice(...a),
}));

import {
  getFxRate,
  getMarkup,
  snipeServicePrice,
  DEFAULT_FX_RATE,
  DEFAULT_MARKUP,
} from "../server/snipe-pricing";

describe("snipe-pricing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("getFxRate", () => {
    it("returns the configured rate from site_settings", async () => {
      mocks.getSetting.mockResolvedValue("7.5");
      await expect(getFxRate()).resolves.toBe(7.5);
      expect(mocks.getSetting).toHaveBeenCalledWith("snipe_eur_fx_rate", "8");
    });

    it("falls back to the default when unset", async () => {
      mocks.getSetting.mockResolvedValue(String(DEFAULT_FX_RATE));
      await expect(getFxRate()).resolves.toBe(DEFAULT_FX_RATE);
    });

    it("falls back to the default when the value is not a positive number", async () => {
      mocks.getSetting.mockResolvedValue("0");
      await expect(getFxRate()).resolves.toBe(DEFAULT_FX_RATE);
      mocks.getSetting.mockResolvedValue("abc");
      await expect(getFxRate()).resolves.toBe(DEFAULT_FX_RATE);
    });
  });

  describe("getMarkup", () => {
    it("returns a rounded integer >= 1", async () => {
      mocks.getSetting.mockResolvedValue("4.6");
      await expect(getMarkup()).resolves.toBe(5);
    });

    it("defaults when below the minimum", async () => {
      mocks.getSetting.mockResolvedValue("0");
      await expect(getMarkup()).resolves.toBe(DEFAULT_MARKUP);
    });
  });

  describe("snipeServicePrice", () => {
    it("computes serviceCents = eur × fx × markup × 100, min 1", async () => {
      mocks.getSetting.mockImplementation((key: string, def: string) =>
        key === "snipe_eur_fx_rate" ? "8" : key === "snipe_markup" ? "4" : def,
      );
      mocks.netimQueryDomainPrice.mockResolvedValue({ price: 10.5, isPremium: false });
      const quote = await snipeServicePrice("example.com");
      expect(quote).toEqual({
        domain: "example.com",
        eurCost: 10.5,
        cnyCost: 84,
        serviceCents: Math.round(84 * 4 * 100),
        fxRate: 8,
        markup: 4,
        isPremium: false,
      });
    });

    it("returns null serviceCents when the price query fails", async () => {
      mocks.netimQueryDomainPrice.mockResolvedValue(null);
      const quote = await snipeServicePrice("example.com");
      expect(quote).not.toBeNull();
      expect(quote?.serviceCents).toBeNull();
      expect(quote?.error).toBeTruthy();
    });

    it("keeps serviceCents null when Netim reports a non-positive price", async () => {
      mocks.netimQueryDomainPrice.mockResolvedValue({ price: -1, isPremium: null });
      const quote = await snipeServicePrice("example.com");
      expect(quote?.serviceCents).toBeNull();
    });
  });
});