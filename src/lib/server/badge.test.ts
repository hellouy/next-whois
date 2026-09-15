import { describe, it, expect } from "vitest";
import { escapeHtml, textBadgeHtml, iconBadgeHtml, buildBadges } from "./badge";

const IDENTITY = { url: "https://whois.example", label: "DomainPulse" };

describe("escapeHtml", () => {
  it("escapes angle brackets, quotes and ampersands", () => {
    expect(escapeHtml(`<img src="x" onerror="alert(1)"> & '`)).toBe(
      "&lt;img src=&quot;x&quot; onerror=&quot;alert(1)&quot;&gt; &amp; &#39;",
    );
  });
});

describe("textBadgeHtml", () => {
  it("links to the site URL and escapes the label", () => {
    const html = textBadgeHtml({ url: "https://whois.example", label: "<Script>" });
    expect(html).toContain('href="https://whois.example"');
    expect(html).toContain("&lt;Script&gt;");
    expect(html).not.toContain("<Script>");
  });
});

describe("iconBadgeHtml", () => {
  it("embeds the monogram initial and href", () => {
    const html = iconBadgeHtml(IDENTITY);
    expect(html).toContain('href="https://whois.example"');
    expect(html).toContain("DomainPulse");
    expect(html).toContain("D");
  });
});

describe("buildBadges", () => {
  it("returns both snippets plus identity", () => {
    const b = buildBadges(IDENTITY);
    expect(b.textHtml).toBe(textBadgeHtml(IDENTITY));
    expect(b.iconHtml).toBe(iconBadgeHtml(IDENTITY));
    expect(b.siteUrl).toBe("https://whois.example");
    expect(b.siteName).toBe("DomainPulse");
  });
});