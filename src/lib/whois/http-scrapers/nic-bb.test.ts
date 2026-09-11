import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { lookupNicBb } from "./nic-bb";

const REGISTERED_HTML = `<!DOCTYPE html><html><body><table class="header"></table>
<pre>
Domain Name: BB.BB
Registry Domain ID: BBDN-00000407
Updated Date: 2025-11-01 01:07:10
Creation Date: 2008-08-12
Registrar Registration Expiration Date: 2026-08-11
Registrar: Barbados Telecommunications Unit
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: lynn.ns.cloudflare.com
Name Server: miki.ns.cloudflare.com
DNSSEC: unsigned
</pre>
<pre>--
The Data in the Barbados BB ccTLD Registrar WHOIS database ...
</pre></body></html>`;

const AVAILABLE_HTML = `<!DOCTYPE html><html><body><table class="header"></table>
<pre>--
The Data in the Barbados BB ccTLD Registrar WHOIS database is provided to 
you by the Telecommunications Unit ...
</pre></body></html>`;

describe("lookupNicBb", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function mockFetch(html: string, status = 200) {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(html, { status })));
  }

  it("extracts the WHOIS <pre> block for a registered domain", async () => {
    mockFetch(REGISTERED_HTML);

    const r = await lookupNicBb("bb.bb");

    expect(r.success).toBe(true);
    if (!r.success) return;
    expect(r.rawWhoisContent).toContain("Domain Name: BB.BB");
    expect(r.rawWhoisContent).toContain("Creation Date: 2008-08-12");
    expect(r.rawWhoisContent).toContain("lynn.ns.cloudflare.com");
  });

  it("reports a domain with only the disclaimer as not registered", async () => {
    mockFetch(AVAILABLE_HTML);

    const r = await lookupNicBb("zz9qq7x3nope.bb");

    expect(r.success).toBe(false);
    if (r.success) return;
    expect(r.blocked).toBe(false);
    expect(r.reason).toContain("not found");
  });

  it("hits the /status/<domain> path with a cleaned lower-case domain", async () => {
    mockFetch(REGISTERED_HTML);

    await lookupNicBb("https://EXAMPLE.BB/");

    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toBe("https://www.whois.telecoms.gov.bb/status/example.bb");
  });

  it("treats non-2xx responses as blocked", async () => {
    mockFetch("", 429);

    const r = await lookupNicBb("bb.bb");

    expect(r.success).toBe(false);
    if (r.success) return;
    expect(r.blocked).toBe(true);
  });
});
