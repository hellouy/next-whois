import { describe, it, expect } from "vitest";
import { analyzeWhois } from "./common_parser";
import { findRegistrarInfo } from "@/data/query-page/registrar-library";

describe("WHOIS text parsing — registrar URL cleanup", () => {
  it("strips trailing punctuation from Registrar URL", async () => {
    const r = await analyzeWhois("Domain Name: example.com\nRegistrar URL: https://www.tucows.com.\n");
    expect(r.registrarURL).toBe("https://www.tucows.com");
  });

  it("drops parenthetical annotations and trailing prose", async () => {
    const r = await analyzeWhois(
      "Domain Name: example.com\nRegistrar URL: http://www.nicheregistrar.de (Registrar's website) see more\n",
    );
    expect(r.registrarURL).toBe("http://www.nicheregistrar.de");
  });

  it("keeps legitimate query strings and paths intact", async () => {
    const r = await analyzeWhois(
      "Domain Name: example.com\nRegistrar URL: https://www.101domain.com/transfer-domain.asp?lang=en\n",
    );
    expect(r.registrarURL).toBe("https://www.101domain.com/transfer-domain.asp?lang=en");
  });
});

describe("registrar library — short alias matching", () => {
  it("matches 3-char substring aliases that the old >3 filter dropped", () => {
    expect(findRegistrarInfo("OVH SAS")?.ianaId).toBe("1319");
    expect(findRegistrarInfo("1&1 IONOS SE")?.ianaId).toBe("83");
  });

  it("matches 2-char Chinese aliases only as the whole name", () => {
    expect(findRegistrarInfo("万网")?.ianaId).toBe("1938");
    expect(findRegistrarInfo("新网")?.ianaId).toBe("120");
    expect(findRegistrarInfo("亿网")?.ianaId).toBe("1556");
  });

  it("does not let the short alias 新网 falsely hit a longer different name", () => {
    const hit = findRegistrarInfo("厦门新网数码科技有限公司");
    expect(hit?.ianaId).not.toBe("120");
  });

  it("keeps long-alias substring behavior unchanged", () => {
    expect(findRegistrarInfo("Alibaba Cloud Computing (Beijing) Co., Ltd.")?.ianaId).toBe("1938");
    expect(findRegistrarInfo("GoDaddy.com, LLC")?.ianaId).toBe("146");
  });
});
