import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { lookupNicTt } from "./nic-tt";

const REGISTERED_HTML = `<div class="main"><form method="post" action="/cgi-bin/search.pl" enctype="multipart/form-data"><h1> Domain Search Form </h1><br><p>Enter Domain Name:&nbsp&nbsp&nbsp<input type="text" name="name" value="nic.tt" />&nbsp&nbsp&nbsp&nbsp&nbsp<input type="submit" name="Search" value="Search" /><br><br></form><table class=data>
<tr><td>Domain Name</td> <td>nic.tt</td></tr> <tr><td>Registrant Name</td> <td>Trinidad and Tobago Network Information Centre</td></tr> <tr><td>Registrant Address</td> <td>Redacted (owner can view under <a href='https://www.nic.tt/cgi-bin/status.pl'>Retrieve->Domain Details</a>)</td></tr> <tr><td>DNS Hostnames</td> <td>dns.nic.tt, ns1.pch.net</td></tr> <tr><td>DNS IP Addresses</td> <td>66.27.54.138, 204.61.210.70</td></tr> <tr><td>Registration Date</td> <td>Oct 15, 2006</td></tr> <tr><td>Expiration Date</td> <td>Oct 15, 2026 &nbsp&nbsp&nbsp <font color=green> ACTIVE </font></td></tr> <tr><td>Administrative Contact</td> <td>Redacted (owner can view under <a href='https://www.nic.tt/cgi-bin/status.pl'>Retrieve->Domain Details</a>)</td></tr> <tr><td>Technical Contact</td> <td>Redacted (owner can view under <a href='https://www.nic.tt/cgi-bin/status.pl'>Retrieve->Domain Details</a>)</td></tr> <tr><td>Billing Contact</td> <td>Redacted (owner can view under <a href='https://www.nic.tt/cgi-bin/status.pl'>Retrieve->Domain Details</a>)</td></tr></table></div>`;

const AVAILABLE_HTML = `<div class="main"><form method="post" action="/cgi-bin/search.pl" enctype="multipart/form-data"><h1> Domain Search Form </h1><br><p>Enter Domain Name:&nbsp&nbsp&nbsp<input type="text" name="name" value="zzzqqqxxvbnm12345.tt" />&nbsp&nbsp&nbsp&nbsp&nbsp<input type="submit" name="Search" value="Search" /><br><br></form>This Domain Name is available.</div>`;

describe("lookupNicTt", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function mockFetch(html: string, status = 200) {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(html, { status })));
  }

  it("parses a registered domain's key/value table", async () => {
    mockFetch(REGISTERED_HTML);

    const r = await lookupNicTt("nic.tt");

    expect(r.success).toBe(true);
    if (!r.success) return;

    expect(r.domain).toBe("nic.tt");
    expect(r.registrant).toBe("Trinidad and Tobago Network Information Centre");
    expect(r.nameservers).toEqual(["dns.nic.tt", "ns1.pch.net"]);
    expect(r.createdDate).toBe("2006-10-15");
    expect(r.expiresDate).toBe("2026-10-15");
    expect(r.status).toEqual(["Active"]);
    expect(r.rawWhoisContent).toContain("Domain Name: nic.tt");
    expect(r.rawWhoisContent).toContain("Creation Date: 2006-10-15");
  });

  it("reports available domains as not registered", async () => {
    mockFetch(AVAILABLE_HTML);

    const r = await lookupNicTt("zzzqqqxxvbnm12345.tt");

    expect(r.success).toBe(false);
    if (r.success) return;
    expect(r.blocked).toBe(false);
    expect(r.reason).toContain("not found");
  });

  it("posts the domain name in the form body", async () => {
    mockFetch(REGISTERED_HTML);

    await lookupNicTt("https://EXAMPLE.tt/");

    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe("POST");
    expect(init.body).toContain("name=example.tt");
    expect(init.body).toContain("Search=Search");
  });

  it("treats unexpected HTML without a data table as an error", async () => {
    mockFetch("<html><body>Unexpected page</body></html>");

    const r = await lookupNicTt("nic.tt");

    expect(r.success).toBe(false);
    if (r.success) return;
    expect(r.blocked).toBe(false);
    expect(r.reason).toContain("Unexpected response");
  });
});
