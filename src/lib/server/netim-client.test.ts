import { describe, it, expect } from "vitest";
import {
  parseNetimPriceResponse,
  parseDomainCheckResponse,
  escapeXml,
  xmlValue,
  mapOpeStatus,
} from "../server/netim-client";

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

describe("parseNetimPriceResponse", () => {
  it("parses a premium domain (IsPremium=1, EUR price)", () => {
    const r = parseNetimPriceResponse(priceReply(1, "1093.00", "1093.00"));
    expect(r).not.toBeNull();
    expect(r?.isPremium).toBe(true);
    expect(r?.price).toBe(1093);
    expect(r?.renewalPrice).toBe(1093);
    expect(r?.currency).toBe("EUR");
  });

  it("parses a non-premium domain (IsPremium=0)", () => {
    const r = parseNetimPriceResponse(priceReply(0, "10.00", "10.00"));
    expect(r?.isPremium).toBe(false);
    expect(r?.price).toBe(10);
  });

  it("keeps promo registration and regular renewal prices separate", () => {
    const r = parseNetimPriceResponse(priceReply(0, "3.00", "13.60"));
    expect(r?.price).toBe(3);
    expect(r?.renewalPrice).toBe(13.6);
  });

  it("returns null on a SOAP fault and on empty input", () => {
    const xml = soap(
      `<SOAP-ENV:Fault><faultcode>SOAP-ENV:Server</faultcode><faultstring>E02 - invalid session</faultstring></SOAP-ENV:Fault>`,
    );
    expect(parseNetimPriceResponse(xml)).toBeNull();
    expect(parseNetimPriceResponse("")).toBeNull();
  });
});

describe("parseDomainCheckResponse (real captured replies)", () => {
  // Captured live 2026-09-12 from api.netim.com for f.sb and a random .sb name.
  const checkReply = (domain: string, result: string, reason: string) =>
    soap(
      `<ns1:domainCheckResponse><domainCheckResponseReturn SOAP-ENC:arrayType="ns1:StructDomainCheckResponse[1]" xsi:type="ns1:ArrayStructDomainCheckResponse"><item xsi:type="ns1:StructDomainCheckResponse">` +
        `<domain xsi:type="xsd:string">${domain}</domain>` +
        `<result xsi:type="xsd:string">${result}</result>` +
        `<reason xsi:type="xsd:string">${reason}</reason>` +
        `</item></domainCheckResponseReturn></ns1:domainCheckResponse>`,
    );

  it("parses an AVAILABLE verdict with empty reason", () => {
    const r = parseDomainCheckResponse(checkReply("zzqsnipetest-3827.sb", "AVAILABLE", ""));
    expect(r).not.toBeNull();
    expect(r?.available).toBe(true);
    expect(r?.reason).toBe("");
  });

  it("parses a NOT AVAILABLE premium verdict", () => {
    const r = parseDomainCheckResponse(checkReply("f.sb", "NOT AVAILABLE", "PREMIUM"));
    expect(r?.available).toBe(false);
    expect(r?.reason).toBe("PREMIUM");
  });

  it("returns null on a fault or empty reply", () => {
    expect(parseDomainCheckResponse("")).toBeNull();
    expect(parseDomainCheckResponse(soap(`<SOAP-ENV:Fault><faultstring>boom</faultstring></SOAP-ENV:Fault>`))).toBeNull();
  });
});

describe("XML primitives", () => {
  it("escapeXml escapes the five XML entities", () => {
    expect(escapeXml(`a&b<c>d"e'f`)).toBe("a&amp;b&lt;c&gt;d&quot;e&apos;f");
  });

  it("xmlValue extracts the first matching tag", () => {
    const xml = `<x><IDSession>abc123</IDSession><IDSession>def</IDSession></x>`;
    expect(xmlValue(xml, "IDSession")).toBe("abc123");
    expect(xmlValue(xml, "missing")).toBeNull();
    expect(xmlValue(null, "IDSession")).toBeNull();
  });
});

describe("mapOpeStatus (operation status classification)", () => {
  it("maps terminal and error keywords", () => {
    expect(mapOpeStatus("DONE")).toBe("done");
    expect(mapOpeStatus("Terminee")).toBe("done");
    expect(mapOpeStatus("ERROR")).toBe("error");
    expect(mapOpeStatus("Annulee")).toBe("error");
  });

  it("treats anything else as pending", () => {
    expect(mapOpeStatus("RUN")).toBe("pending");
    expect(mapOpeStatus("WAITING")).toBe("pending");
    expect(mapOpeStatus(null)).toBe("pending");
  });
});
