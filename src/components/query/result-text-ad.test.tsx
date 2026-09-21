import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { SiteSettings } from "@/lib/site-settings";

const mockSettings: { result_ads: string } = { result_ads: "" };

vi.mock("@/lib/site-settings", async (orig) => {
  const actual = await (orig as () => Promise<object>)();
  return {
    ...actual,
    useSiteSettings: () => mockSettings,
  };
});

import { ResultTextAd } from "./result-text-ad";

function json(map: { slot1?: unknown[]; slot2?: unknown[] }) {
  return JSON.stringify({ slot1: [], slot2: [], ...map });
}

beforeEach(() => {
  mockSettings.result_ads = "";
});

describe("ResultTextAd", () => {
  it("renders nothing when the slot has no ads", () => {
    mockSettings.result_ads = json({ slot1: [] });
    expect(renderToStaticMarkup(<ResultTextAd slot="slot1" />)).toBe("");
  });

  it("renders nothing when every ad in the slot is disabled", () => {
    mockSettings.result_ads = json({
      slot2: [{ id: "a1", enabled: "", text: "hidden ad" }],
    });
    expect(renderToStaticMarkup(<ResultTextAd slot="slot2" />)).toBe("");
  });

  it("renders an image ad for slot1", () => {
    mockSettings.result_ads = json({
      slot1: [{
        id: "a1", enabled: "1", text: "",
        image_url: "https://example.com/banner.png", image_alt: "广告图", url: "", label: "广告", html: "",
      }],
    });
    const html = renderToStaticMarkup(<ResultTextAd slot="slot1" />);
    expect(html).toContain("https://example.com/banner.png");
    expect(html).toContain("广告图");
  });

  it("renders text ad and cycles the first item when multiple", () => {
    mockSettings.result_ads = json({
      slot2: [{
        id: "a2", enabled: "1", text: "A公司 | B公司", image_url: "", url: "", label: "推广", html: "",
      }],
    });
    const html = renderToStaticMarkup(<ResultTextAd slot="slot2" />);
    expect(html).toContain("A公司");
    expect(html).toContain("推广");
  });

  it("renders html ad with precedence over image/text", () => {
    mockSettings.result_ads = json({
      slot2: [{
        id: "a3", enabled: "1", text: "should-not-show", image_url: "https://example.com/x.png",
        url: "", label: "广告", html: '<a href="https://sponsor.example">赞助商</a>',
      }],
    });
    const html = renderToStaticMarkup(<ResultTextAd slot="slot2" />);
    expect(html).toContain("sponsor.example");
    expect(html).not.toContain("should-not-show");
    expect(html).not.toContain("x.png");
  });

  it("renders multiple enabled ads stacked in order", () => {
    mockSettings.result_ads = json({
      slot2: [
        { id: "a1", enabled: "1", text: "第一条", image_url: "", url: "", label: "广告", html: "" },
        { id: "a2", enabled: "1", text: "第二条", image_url: "", url: "", label: "广告", html: "" },
      ],
    });
    const html = renderToStaticMarkup(<ResultTextAd slot="slot2" />);
    const first = html.indexOf("第一条");
    const second = html.indexOf("第二条");
    expect(first).toBeGreaterThan(-1);
    expect(second).toBeGreaterThan(first);
  });

  it("returns nothing while results are still loading", () => {
    mockSettings.result_ads = json({
      slot2: [{ id: "a1", enabled: "1", text: "loading ad" }],
    });
    expect(renderToStaticMarkup(<ResultTextAd slot="slot2" loading />)).toBe("");
  });
});
