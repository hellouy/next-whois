import { describe, it, expect } from "vitest";
import { analyzeWhois } from "./common_parser";
import { calculateDomainAge, calculateRemainingDays } from "./parsers/date";

/**
 * TWNIC (.台灣 / .台湾) writes its timestamps as free text with a clock colon
 * and no key:
 *
 *   Record created on 2022-07-30 07:57:05 (UTC+8)
 *   Record expires on 2027-07-30 07:57:05 (UTC+8)
 *
 * The shared line tokenizer used to split at the first colon — the one inside
 * "07:57:05" — yielding the value "57:05 (UTC+8)", which moment leniently read
 * as year 2057. Both dates collapsed to 2057-05-01 (creation "30 years" in the
 * future, ~11180 days remaining).
 */
const TWNIC_RESPONSE = `註冊原型域名: 收复.台灣 (xn--yrsv6z.xn--kpry57d)
保留字域名(由下列相關字組合之域名):
 収 收
 复 復 複 覆
   Domain Status: ok
   Registrant:
      (Redacted for privacy)
   Administrative Contact:
      (Redacted for privacy)
   Technical Contact:
      (Redacted for privacy)
   Record expires on 2027-07-30 07:57:05 (UTC+8)
   Record created on 2022-07-30 07:57:05 (UTC+8)
   Domain servers in listed order:
      ada.ns.cloudflare.com
      chuck.ns.cloudflare.com
Registration Service Provider: HINET
Registration Service URL: https://domain.hinet.net
Registrar Abuse Contact Email: service@domain.hinet.net`;

describe("analyzeWhois — TWNIC free-text timestamps", () => {
  it("parses the real creation and expiry dates instead of 2057-05-01", async () => {
    const r = await analyzeWhois(TWNIC_RESPONSE);
    expect(r.creationDate).toBe("2022-07-30T00:00:00.000Z");
    expect(r.expirationDate).toBe("2027-07-30T00:00:00.000Z");
  });

  it("computes a non-negative domain age and a sane remaining-days count", async () => {
    const r = await analyzeWhois(TWNIC_RESPONSE);
    expect(calculateDomainAge(r.creationDate)).toBeGreaterThan(0);
    expect(calculateRemainingDays(r.expirationDate)).toBeLessThan(3660);
  });

  it("maps the Registration Service Provider/URL to registrar and registrarURL", async () => {
    const r = await analyzeWhois(TWNIC_RESPONSE);
    expect(r.registrar).toBe("HINET");
    expect(r.registrarURL).toBe("https://domain.hinet.net");
  });
});
