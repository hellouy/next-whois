import { describe, it, expect } from "vitest";
import { detectParkingProvider } from "./dns-check";
import { parsePorkbunResponse, parseNetimResponse } from "../server/premium-check";

describe("detectParkingProvider", () => {
  it("returns null for empty or non-parking nameservers", () => {
    expect(detectParkingProvider([])).toBeNull();
    expect(detectParkingProvider(["ns1.google.com", "ns2.google.com"])).toBeNull();
  });

  it("detects Sedo parking via sedoparking.com", () => {
    expect(detectParkingProvider(["ns1.sedoparking.com"])).toBe("Sedo");
    expect(detectParkingProvider(["NS2.SEDOPARKING.COM"])).toBe("Sedo");
  });

  it("detects Afternic and Bodis", () => {
    expect(detectParkingProvider(["ns1.afternic.com", "ns2.afternic.com"])).toBe("Afternic");
    expect(detectParkingProvider(["ns1.bodis.com"])).toBe("Bodis");
  });

  it("detects HugeDomains and Dan", () => {
    expect(detectParkingProvider(["ns1.hugedomains.com"])).toBe("HugeDomains");
    expect(detectParkingProvider(["ns1.dan.com"])).toBe("Dan.com");
  });

  it("does not flag GoDaddy's generic DNS hosting as parking", () => {
    expect(detectParkingProvider(["ns1.domaincontrol.com"])).toBeNull();
  });

  it("matches parking NS even when mixed with normal NS", () => {
    expect(detectParkingProvider(["ns1.example.com", "ns2.sedoparking.com"])).toBe("Sedo");
  });
});

describe("parsePorkbunResponse", () => {
  it("parses a premium domain with the string flag and thousands-separated price", () => {
    const r = parsePorkbunResponse({
      status: "SUCCESS",
      response: {
        avail: "yes",
        price: "1,092.18",
        regularPrice: "1,092.18",
        premium: "yes",
        additional: { renewal: { type: "renewal", price: "1,092.18", regularPrice: "1,092.18" } },
      },
    });

    expect(r).not.toBeNull();
    expect(r?.isPremium).toBe(true);
    expect(r?.price).toBe(1092.18);
    expect(r?.renewalPrice).toBe(1092.18);
    expect(r?.currency).toBe("USD");
    expect(r?.source).toBe("porkbun");
  });

  it("prefers regularPrice over the promo first-year price", () => {
    const r = parsePorkbunResponse({
      status: "SUCCESS",
      response: {
        avail: "yes",
        price: "2.04",
        firstYearPromo: "yes",
        regularPrice: "14.21",
        premium: "no",
        additional: { renewal: { price: "14.21", regularPrice: "14.21" } },
      },
    });

    expect(r?.isPremium).toBe(false);
    expect(r?.price).toBe(14.21);
    expect(r?.renewalPrice).toBe(14.21);
  });

  it("returns null for an already-registered domain (avail=no)", () => {
    const r = parsePorkbunResponse({
      status: "SUCCESS",
      response: { avail: "no", premium: "yes", price: "1,092.18", regularPrice: "1,092.18" },
    });

    expect(r).toBeNull();
  });

  it("returns null for a non-SUCCESS response", () => {
    expect(parsePorkbunResponse({ status: "ERROR", message: "invalid" })).toBeNull();
    expect(parsePorkbunResponse(null)).toBeNull();
    expect(parsePorkbunResponse(undefined)).toBeNull();
  });

  it("accepts boolean true premium flag", () => {
    const r = parsePorkbunResponse({
      status: "SUCCESS",
      response: { avail: "yes", premium: true, price: "500.00", regularPrice: "500.00" },
    });

    expect(r?.isPremium).toBe(true);
    expect(r?.price).toBe(500);
  });
});

describe("parseNetimResponse", () => {
  const soap = (body: string) =>
    `<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:DRS" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><SOAP-ENV:Body>${body}</SOAP-ENV:Body></SOAP-ENV:Envelope>`;

  const priceReply = (premium: number, reg: string, renew: string) =>
    soap(
      `<ns1:queryDomainPriceResponse><queryDomainPriceReturn xsi:type="ns1:StructQueryDomainPrice">` +
        `<FeeCurrency xsi:type="xsd:string">EUR</FeeCurrency>` +
        `<Fee4Registration xsi:type="xsd:string">${reg}</Fee4Registration>` +
        `<Fee4Renewal xsi:type="xsd:string">${renew}</Fee4Renewal>` +
        `<IsPremium xsi:type="xsd:int">${premium}</IsPremium>` +
        `</queryDomainPriceReturn></ns1:queryDomainPriceResponse>`,
    );

  it("parses a premium domain (IsPremium=1, EUR price)", () => {
    const r = parseNetimResponse(priceReply(1, "1093.00", "1093.00"));

    expect(r).not.toBeNull();
    expect(r?.isPremium).toBe(true);
    expect(r?.price).toBe(1093);
    expect(r?.renewalPrice).toBe(1093);
    expect(r?.currency).toBe("EUR");
    expect(r?.source).toBe("netim");
  });

  it("parses a non-premium domain (IsPremium=0)", () => {
    const r = parseNetimResponse(priceReply(0, "10.00", "10.00"));

    expect(r?.isPremium).toBe(false);
    expect(r?.price).toBe(10);
    expect(r?.renewalPrice).toBe(10);
  });

  it("keeps promo registration and regular renewal prices separate", () => {
    const r = parseNetimResponse(priceReply(0, "3.00", "13.60"));

    expect(r?.isPremium).toBe(false);
    expect(r?.price).toBe(3);
    expect(r?.renewalPrice).toBe(13.6);
  });

  it("returns null on a SOAP fault", () => {
    const xml = soap(
      `<SOAP-ENV:Fault><faultcode>SOAP-ENV:Server</faultcode><faultstring>E02 - invalid session</faultstring></SOAP-ENV:Fault>`,
    );
    expect(parseNetimResponse(xml)).toBeNull();
  });

  it("returns null for empty input or missing IsPremium", () => {
    expect(parseNetimResponse("")).toBeNull();
    expect(parseNetimResponse(soap(`<ns1:helloResponse></ns1:helloResponse>`))).toBeNull();
  });
});
