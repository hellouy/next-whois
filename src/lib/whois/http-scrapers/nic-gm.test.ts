import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { lookupNicGm } from "./nic-gm";

const DETAILS_HTML = `<!DOCTYPE html><html><body><main class="split-container">
<h2>DOMAIN REGISTERED</h2>
<ul>
  <li>Registrar managing this domain: <b id="registrar-name">GM-NIC</b></li><br>
  <li>Registrant using domain online: <b id="registrant-name"></b></li><br>
  <li>Registration Date: <b id="registration-date">2020-01-15</b></li><br>
  <li>Name Server #1: <b id="name-server-1">ns1.nic.gm</b></li><br>
  <li>Name Server #2: <b id="name-server-2">ns2.nic.gm</b></li><br>
</ul>
</main></body></html>`;

function redirectTo(location: string) {
  return new Response(null, { status: 302, headers: { location } });
}

function mockCheckdom(location: string, detailsHtml?: string) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockImplementation(async (url: string) => {
      if (String(url).includes("checkdom.aspx")) {
        return redirectTo(location);
      }
      if (String(url).includes("whois-details")) {
        return new Response(detailsHtml ?? DETAILS_HTML, { status: 200 });
      }
      return new Response("", { status: 404 });
    }),
  );
}

describe("lookupNicGm", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("reports a registered domain (details redirect) as registered", async () => {
    mockCheckdom("https://www.nic.gm/NIC2/whois-details.html?dname=nic");

    const r = await lookupNicGm("nic.gm");

    expect(r.success).toBe(true);
    if (!r.success) return;
    expect(r.reserved).toBe(false);
    expect(r.domain).toBe("nic.gm");
    expect(r.status).toEqual(["Active"]);
    expect(r.registrar).toBe("GM-NIC");
    expect(r.registrationDate).toBe("2020-01-15");
    expect(r.nameservers).toEqual(["ns1.nic.gm", "ns2.nic.gm"]);
    expect(r.rawWhoisContent).toContain("Domain Name: nic.gm");
  });

  it("reports an available domain as not registered", async () => {
    mockCheckdom("https://www.nic.gm/NIC2/whois-available.html?dname=zz9q7x");

    const r = await lookupNicGm("zz9q7x.gm");

    expect(r.success).toBe(false);
    if (r.success) return;
    expect(r.blocked).toBe(false);
    expect(r.reason).toContain("not found");
  });

  it("reports a reserved domain with registry-reserved status", async () => {
    mockCheckdom("https://www.nic.gm/NIC2/whois-reserved.html?dname=china");

    const r = await lookupNicGm("china.gm");

    expect(r.success).toBe(true);
    if (!r.success) return;
    expect(r.reserved).toBe(true);
    expect(r.status).toEqual(["registry-reserved"]);
    expect(r.rawWhoisContent).toContain("registry-reserved");
  });

  it("strips protocol, .gm suffix and invalid characters from the query", async () => {
    mockCheckdom("https://www.nic.gm/NIC2/whois-details.html?dname=example");

    await lookupNicGm("https://EXAMPLE.GM/");

    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    const firstUrl = String(fetchMock.mock.calls[0][0]);
    expect(firstUrl).toContain("dname=example");
  });

  it("treats a missing redirect location as an unexpected response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("", { status: 200 })),
    );

    const r = await lookupNicGm("foo.gm");

    expect(r.success).toBe(false);
    if (r.success) return;
    expect(r.reason).toContain("Unexpected response");
  });
});
