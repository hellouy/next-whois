import { describe, it, expect } from "vitest";
import { parseWhoisdsText, stageFromUrl } from "./whoisds";
import { parsePendingDelete } from "./expireddomains";
import { parseMetric, parseListedDate, parsePublicListing } from "./expireddomains-public";
import { runDropSources } from "./registry";
import type { DropSourceAdapter } from "./types";

const TODAY = "2026-09-22";

describe("stageFromUrl", () => {
  it("infers the stage from the list path", () => {
    expect(stageFromUrl("https://x.com/pending-delete-list.txt")).toBe("pending_delete");
    expect(stageFromUrl("https://x.com/expiring-domains.txt")).toBe("expiring");
    expect(stageFromUrl("https://x.com/deleted-domains.txt")).toBe("deleted");
  });
});

describe("parseWhoisdsText", () => {
  it("parses domains, skips noise, and de-duplicates", () => {
    const text = [
      "# daily list",
      "",
      "Example.COM",
      "foo.net",
      "foo.net",
      "not a domain",
      "bad_underscore.com",
      "bar.co.uk",
    ].join("\n");

    const { rows, skipped } = parseWhoisdsText(text, "deleted", TODAY);
    expect(rows.map((r) => r.domain)).toEqual(["example.com", "foo.net", "bar.co.uk"]);
    expect(skipped).toBe(2);
    expect(rows.every((r) => r.stage === "deleted")).toBe(true);
    expect(rows.every((r) => r.dropDate === TODAY)).toBe(true);
    expect(rows.every((r) => r.sourceDateType === "source")).toBe(true);
  });

  it("leaves the drop date empty for pre-release stages", () => {
    const { rows } = parseWhoisdsText("future.com", "pending_delete", TODAY);
    expect(rows[0].dropDate).toBeNull();
    expect(rows[0].sourceDateType).toBe("derived");
  });
});

describe("parsePendingDelete", () => {
  const html = `
    <table id="listing">
      <thead>
        <tr><th>Domain</th><th>Len</th><th>BL</th><th>DP</th><th>Drop</th></tr>
      </thead>
      <tbody>
        <tr>
          <td class="field_domain"><a href="#">Example.COM</a></td>
          <td>7</td><td>1,234</td><td>56</td><td>2026-10-01</td>
        </tr>
        <tr>
          <td class="field_domain"><a href="#">foo.net</a></td>
          <td>3</td><td>-</td><td>-</td><td>01-Oct-2026</td>
        </tr>
        <tr>
          <td>not a domain</td>
          <td>1</td><td>0</td><td>0</td><td>2026-10-02</td>
        </tr>
      </tbody>
    </table>`;

  it("parses rows with header-resolved columns", () => {
    const { rows, skipped } = parsePendingDelete(html);
    expect(rows).toHaveLength(2);
    expect(skipped).toBe(1);

    const [first, second] = rows;
    expect(first.domain).toBe("example.com");
    expect(first.stage).toBe("pending_delete");
    expect(first.bl).toBe(1234);
    expect(first.dp).toBe(56);
    expect(first.dropDate).toBe("2026-10-01");
    expect(first.sourceDateType).toBe("source");

    expect(second.domain).toBe("foo.net");
    expect(second.bl).toBeNull();
    expect(second.dp).toBeNull();
    expect(second.dropDate).toBe("2026-10-01");
  });

  it("returns nothing when the listing table is absent", () => {
    expect(parsePendingDelete("<html><body>login</body></html>")).toEqual({ rows: [], skipped: 0 });
  });
});

describe("parseMetric", () => {
  it("parses compact and comma-grouped metrics", () => {
    expect(parseMetric("354")).toBe(354);
    expect(parseMetric("1,234")).toBe(1234);
    expect(parseMetric("3.7 K")).toBe(3700);
    expect(parseMetric("1.2M")).toBe(1200000);
    expect(parseMetric("-")).toBeNull();
    expect(parseMetric("")).toBeNull();
  });
});

describe("parseListedDate", () => {
  it("resolves relative and absolute listing dates", () => {
    expect(parseListedDate("Today 01:31", TODAY)).toBe(TODAY);
    expect(parseListedDate("Yesterday 23:00", TODAY)).toBe("2026-09-21");
    expect(parseListedDate("2026-09-20", TODAY)).toBe("2026-09-20");
    expect(parseListedDate("", TODAY)).toBeNull();
  });
});

describe("parsePublicListing", () => {
  const deletedHtml = `
    <table id="listing">
      <thead><tr><th>Domain</th><th>BL</th><th>DP</th><th>Dropped</th><th>Status</th></tr></thead>
      <tbody>
        <tr>
          <td class="field_domain"><a title="AnchorApp.dev" href="#">AnchorApp.dev</a></td>
          <td>18</td><td>0</td><td>Today 01:31</td><td>available</td>
        </tr>
        <tr>
          <td class="field_domain"><a title="Noise.com" href="#">Noise.com</a></td>
          <td>3.7 K</td><td>-</td><td>Yesterday 12:00</td><td>available</td>
        </tr>
        <tr><td>not a domain</td><td>0</td><td>0</td><td>Today</td><td>available</td></tr>
      </tbody>
    </table>`;

  const expiredHtml = `
    <table id="listing">
      <thead><tr><th>Domain</th><th>BL</th><th>DP</th><th>End Date</th></tr></thead>
      <tbody>
        <tr>
          <td class="field_domain"><a title="118114.tv" href="#">118114.tv</a></td>
          <td>354</td><td>50</td><td>2026-09-24</td>
        </tr>
      </tbody>
    </table>`;

  it("maps the deleted listing to source drop dates", () => {
    const { rows, skipped } = parsePublicListing(deletedHtml, "deleted", TODAY);
    expect(rows).toHaveLength(2);
    expect(skipped).toBe(1);
    expect(rows[0]).toMatchObject({
      domain: "anchorapp.dev", stage: "deleted", dropDate: TODAY, expiryDate: null,
      bl: 18, dp: 0, sourceDateType: "source",
    });
    expect(rows[1].bl).toBe(3700);
    expect(rows[1].dropDate).toBe("2026-09-21");
  });

  it("maps the expired listing to expiry dates for derivation", () => {
    const { rows } = parsePublicListing(expiredHtml, "expiring", TODAY);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      domain: "118114.tv", stage: "expiring", dropDate: null,
      expiryDate: "2026-09-24", bl: 354, dp: 50, sourceDateType: "derived",
    });
  });

  it("returns nothing when the listing table is absent", () => {
    expect(parsePublicListing("<html><body>nope</body></html>", "deleted", TODAY)).toEqual({ rows: [], skipped: 0 });
  });
});

describe("runDropSources", () => {
  it("isolates a failing source and keeps the others", async () => {
    const ok: DropSourceAdapter = {
      id: "ok",
      stages: ["deleted"],
      fetch: async () => ({ rows: [{ domain: "a.com", stage: "deleted", sourceDateType: "source" }], skipped: 2 }),
    };
    const bad: DropSourceAdapter = {
      id: "bad",
      stages: ["expiring"],
      fetch: async () => { throw new Error("boom"); },
    };

    const outcomes = await runDropSources([ok, bad]);
    expect(outcomes).toEqual([
      { source: "ok", ok: true, items: 1, skipped: 2, error: null },
      { source: "bad", ok: false, items: 0, skipped: 0, error: "boom" },
    ]);
  });
});
