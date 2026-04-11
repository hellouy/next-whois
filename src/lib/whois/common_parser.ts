/**
 * WHOIS text analysis — main entry point.
 *
 * The heavy-lifting helpers have been extracted into focused sub-modules:
 *   parsers/utils.ts          — string / field helpers
 *   parsers/date.ts           — date-format parsing and domain-age computation
 *   parsers/preprocessors.ts  — per-TLD raw-text normalisation
 *   parsers/status-injection.ts — synthetic status detection from free-form text
 *
 * This file re-exports the public API and wires the sub-modules together
 * inside the main analyzeWhois() dispatcher.
 */

import {
  DomainStatusProps,
  initialWhoisAnalyzeResult,
  WhoisAnalyzeResult,
} from "@/lib/whois/types";
import { includeArgs } from "@/lib/utils";
import {
  isDomainLike,
  convertIdnToUnicode,
  cleanFieldValue,
  isRedactedValue,
  analyzeDomainStatus,
} from "@/lib/whois/parsers/utils";
import {
  analyzeTime,
  extractDateNearKeyword,
  applyParams,
} from "@/lib/whois/parsers/date";
import { preprocessSmWhois, preprocessIslandNetworks } from "@/lib/whois/parsers/preprocessors";
import { injectSyntheticStatuses } from "@/lib/whois/parsers/status-injection";

// Re-export for backward compatibility (rdap_client.ts and others import this).
export { applyParams };

export async function analyzeWhois(data: string): Promise<WhoisAnalyzeResult> {
  data = preprocessSmWhois(data);
  data = preprocessIslandNetworks(data);

  const lines = data
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  const result: WhoisAnalyzeResult = {
    ...initialWhoisAnalyzeResult,
    status: [],
    nameServers: [],
    rawWhoisContent: data,
  };

  let explicitUnicodeDomain = "";
  let explicitAsciiDomain = "";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    let key: string;
    let value: string;

    const bracketMatch = line.match(/^(?:[a-z]\.\s*)?\[(.+?)\]\s+(.+)/);
    if (bracketMatch) {
      key = bracketMatch[1].trim().toLowerCase();
      value = cleanFieldValue(bracketMatch[2].trim());
    } else {
      let segments = line.split(":");
      if (segments.length < 2) continue;
      if (segments.length >= 3 && segments[0].toLowerCase() === "network") {
        segments = segments.slice(1);
      }
      key = segments[0].trim().toLowerCase();
      value = cleanFieldValue(segments.slice(1).join(":").trim());
    }

    if (!value) continue;

    switch (key) {
      case "domain name (unicode)":
        if (!explicitUnicodeDomain) explicitUnicodeDomain = value;
        break;
      case "domain name (ascii)":
        if (!explicitAsciiDomain) explicitAsciiDomain = value;
        if (isDomainLike(value)) result.domain = result.domain || value;
        break;
      case "domain name":
      case "domain":
      case "nom de domaine":
      case "domaine":
        if (isDomainLike(value)) result.domain = result.domain || value;
        break;
      case "registrar":
      case "authorized agency":
      case "sponsoring registrar":
      case "registrar name":
      case "registrant registrar":
      case "registration service provider":
      case "enregistreur":
      case "bureau d'enregistrement":
        result.registrar = result.registrar === "Unknown" ? value : result.registrar;
        break;
      case "iana id":
        result.ianaId = value;
        break;
      case "registrar iana id":
        result.ianaId = value;
        break;
      case "whois server":
        result.whoisServer = value;
        break;
      case "whois":
        result.whoisServer = value;
        break;
      case "registrar whois server":
        result.whoisServer = value;
        break;
      case "updated date":
      case "last updated date":
      case "last modified":
      case "last-modified":
      case "modification date":
      case "modified":
      case "last update":
      case "last updated":
      case "update date":
      case "date updated":
      case "updated on":
      case "modified on":
      case "date de mise a jour":
      case "date de mise à jour":
      case "zuletzt geaendert am":
      case "updated (utc)":
      case "last-update":
      case "updated":
      case "last changed":
      case "changed on":
      case "modifié le":
      case "fecha de modificacion":
      case "actualizado":
      case "changed":
      case "last modification":
      case "modified date":
      case "last modified date":
      case "record last updated":
      case "record modified":
      case "last update date":
      case "domain updated":
      case "last-modified-date":
      case "senast ändrad":
      case "viimeksi muokattu":
      case "sist endret":
      case "sidst ændret":
      case "senest opdateret":
      case "letzte änderung":
      case "última modificación":
      case "última atualização":
        if (result.updatedDate === "Unknown") result.updatedDate = analyzeTime(value);
        break;
      case "creation date":
      case "registered date":
      case "activation":
      case "activation date":
      case "registered on":
      case "date registered":
      case "domain registered":
      case "created":
      case "created on":
      case "created date":
      case "registration date":
      case "registration time":
      case "date de creation":
      case "date de création":
      case "registriert am":
      case "datum registracije":
      case "created (utc)":
      case "created date (utc)":
      case "reg date":
      case "create date":
      case "entry created":
      case "domain registration date":
      case "first registered":
      case "first registration date":
      case "registered":
      case "register date":
      case "start date":
      case "date d'enregistrement":
      case "enregistré le":
      case "fecha de registro":
      case "fecha de creacion":
      case "fecha creacion":
      case "criado em":
      case "data de registro":
      case "anniversary":
      case "inception date":
      case "domain inception date":
      case "record created":
      case "created at":
      case "activation time":
      case "delegated on":
      case "delegated":
      case "fecha de alta":
      case "registreringsdatum":
      case "rekisteröintipäivä":
      case "registreringsdato":
      case "domainregistrierung":
        if (result.creationDate === "Unknown") result.creationDate = analyzeTime(value);
        break;
      case "domain name commencement date":
      case "domain commencement date":
        if (result.creationDate === "Unknown") result.creationDate = analyzeTime(value);
        break;
      case "expiration date":
      case "expiration":
      case "valid until":
      case "paid-till":
      case "paid till":
      case "expires on":
      case "expire date":
      case "expire":
      case "expires":
      case "expiry date":
      case "expiry":
      case "registry expiration date":
      case "date expiration":
      case "date d'expiration":
      case "ablaufdatum":
      case "expires (utc)":
      case "expiration date (utc)":
      case "expiration time":
      case "renewal date":
      case "due date":
      case "valid-date":
      case "expire-date":
      case "expiration-date":
      case "end date":
      case "domain expiration date":
      case "fecha de vencimiento":
      case "fecha expiracion":
      case "fecha de expiracion":
      case "validade":
      case "vence em":
      case "ablauf":
      case "laufzeit bis":
      case "registry expiry date":
      case "registrar registration expiration date":
      case "registration expiry date":
      case "expiration-date (registrar)":
      case "domain renewal date":
      case "renewal deadline":
      case "validity":
      case "validity date":
      case "valid through":
      case "valid to":
      case "valid-till":
      case "gyldig til":
      case "keston loppupäivä":
      case "giltig till":
      case "verfallsdatum":
        if (result.expirationDate === "Unknown") result.expirationDate = analyzeTime(value);
        break;
      case "state": {
        const expiryMatch = value.match(/\((\d{4}\/\d{2}\/\d{2})\)/);
        if (expiryMatch && result.expirationDate === "Unknown") {
          result.expirationDate = analyzeTime(expiryMatch[1]);
        }
        result.status.push(analyzeDomainStatus(value));
        break;
      }
      case "status":
      case "registration status":
        result.status.push(analyzeDomainStatus(value));
        break;
      case "domain status":
        result.status.push(analyzeDomainStatus(value));
        break;
      case "name server":
      case "name server (db)":
      case "host name":
      case "hostname":
      case "nameserver":
      case "ns":
      case "ns1":
      case "ns2":
      case "ns3":
      case "ns4":
      case "ns5":
      case "ns6":
      case "dns":
      case "dns1":
      case "dns2":
      case "dns3":
      case "dns4":
      case "primary nameserver":
      case "secondary nameserver":
      case "serveur dns":
      case "nameservers":
      case "name servers":
      case "nserver":
      case "p":
      // Split on commas (e.g. "ns1.foo.com, ns2.foo.com") then strip IPs
        for (const nsEntry of value.split(",")) {
          const ns = nsEntry.trim().split(/\s+/)[0];
          if (ns && ns.includes(".")) result.nameServers.push(ns);
        }
        break;
      // ── Registry domain ID ────────────────────────────────────────────────
      case "registry domain id":
      case "domain id":
      case "domain-id":
      case "roid":
        if (result.registryDomainId === "Unknown") result.registryDomainId = value;
        break;

      // ── Registrant name ────────────────────────────────────────────────────
      case "registrant name":
      case "registrant contact name":
      case "holder":
      case "owner":
        if (!isRedactedValue(value) && result.registrantName === "Unknown")
          result.registrantName = value;
        break;

      // ── Registrant organization ────────────────────────────────────────────
      case "registrant organization":
      case "registrant organisation":
      case "registrant org":
        if (!isRedactedValue(value)) result.registrantOrganization = value;
        break;
      case "organization":
      case "organisation":
      case "org-name":
        if (!isRedactedValue(value) && result.registrantOrganization === "Unknown")
          result.registrantOrganization = value;
        break;
      case "registrant":
        if (!isRedactedValue(value)) result.registrantOrganization = value;
        break;
      case "descr":
        if (
          !isRedactedValue(value) &&
          result.registrantOrganization === "Unknown"
        )
          result.registrantOrganization = value;
        break;

      // ── Registrant state/province ─────────────────────────────────────────
      case "registrant state/province":
      case "registrant state":
      case "registrant province":
      case "province":
        if (!isRedactedValue(value) && result.registrantProvince === "Unknown")
          result.registrantProvince = value;
        break;

      // ── Registrant city ────────────────────────────────────────────────────
      case "registrant city":
      case "registrant locality":
      case "city":
      case "locality":
        if (!isRedactedValue(value) && result.registrantCity === "Unknown")
          result.registrantCity = value;
        break;

      // ── Registrant street address ──────────────────────────────────────────
      case "registrant street":
      case "registrant address":
      case "registrant street1":
      case "registrant street2":
      case "registrant street3":
      case "street":
      case "address":
      case "addr":
        if (!isRedactedValue(value) && result.registrantAddress === "Unknown")
          result.registrantAddress = value;
        break;

      // ── Registrant postal code ─────────────────────────────────────────────
      case "registrant postal code":
      case "registrant zip":
      case "registrant zip code":
      case "postal code":
      case "zip code":
      case "zip":
      case "postcode":
      case "postalcode":
      case "postal-code":
        if (!isRedactedValue(value) && result.registrantPostalCode === "Unknown")
          result.registrantPostalCode = value;
        break;

      // ── Registrant country ────────────────────────────────────────────────
      case "registrant country":
      case "registrant country code":
      case "registrant country/economy":
        if (!isRedactedValue(value)) result.registrantCountry = value;
        break;
      case "country":
      case "country-code":
        if (!isRedactedValue(value) && result.registrantCountry === "Unknown")
          result.registrantCountry = value;
        break;

      // ── Registrant phone ──────────────────────────────────────────────────
      case "registrant phone":
      case "registrant phone number":
      case "registrant telephone":
      case "phone":
      case "telephone":
        if (!isRedactedValue(value) && result.registrantPhone === "Unknown")
          result.registrantPhone = value.replace(/^tel:/i, "").trim();
        break;

      // ── Registrant fax ────────────────────────────────────────────────────
      case "registrant fax":
      case "registrant fax ext":
      case "fax":
      case "fax-no":
      case "fax no":
      case "telefax":
        if (!isRedactedValue(value) && result.registrantFax === "Unknown")
          result.registrantFax = value.replace(/^tel:/i, "").trim();
        break;

      // ── Administrative contact ────────────────────────────────────────────
      case "admin name":
      case "administrative name":
      case "admin contact name":
      case "admin contact":
      case "administrative contact":
      case "administrative contact name":
      case "ac":
      case "admin id":
        if (!isRedactedValue(value) && result.adminName === "Unknown")
          result.adminName = value;
        break;
      case "admin organization":
      case "admin organisation":
      case "admin org":
      case "administrative organization":
      case "administrative organisation":
        if (!isRedactedValue(value) && result.adminOrganization === "Unknown")
          result.adminOrganization = value;
        break;
      case "admin email":
      case "admin e-mail":
      case "administrative email":
      case "administrative e-mail":
      case "admin contact email":
      case "ac e-mail":
        if (!isRedactedValue(value) && result.adminEmail === "Unknown")
          result.adminEmail = value;
        break;
      case "admin phone":
      case "admin telephone":
      case "administrative phone":
      case "administrative telephone":
      case "admin contact phone":
        if (!isRedactedValue(value) && result.adminPhone === "Unknown")
          result.adminPhone = value.replace(/^tel:/i, "").trim();
        break;
      case "admin country":
      case "administrative country":
        if (!isRedactedValue(value) && result.adminCountry === "Unknown")
          result.adminCountry = value;
        break;

      // ── Technical contact ─────────────────────────────────────────────────
      case "tech name":
      case "technical name":
      case "technical contact name":
      case "tech contact name":
      case "tech contact":
      case "technical contact":
        if (!isRedactedValue(value) && result.techName === "Unknown")
          result.techName = value;
        break;
      case "tech organization":
      case "tech organisation":
      case "tech org":
      case "technical organization":
      case "technical organisation":
        if (!isRedactedValue(value) && result.techOrganization === "Unknown")
          result.techOrganization = value;
        break;
      case "tech email":
      case "tech e-mail":
      case "technical email":
      case "technical e-mail":
      case "tech contact email":
        if (!isRedactedValue(value) && result.techEmail === "Unknown")
          result.techEmail = value;
        break;
      case "tech phone":
      case "tech telephone":
      case "technical phone":
      case "technical telephone":
      case "tech contact phone":
        if (!isRedactedValue(value) && result.techPhone === "Unknown")
          result.techPhone = value.replace(/^tel:/i, "").trim();
        break;

      // ── Abuse contact ─────────────────────────────────────────────────────
      case "registrar abuse contact phone":
      case "abuse phone":
      case "abuse contact phone":
        if (!isRedactedValue(value))
          result.abusePhone = value.replace(/^tel:/i, "").trim();
        break;
      case "registrar abuse contact email":
      case "abuse-mailbox":
        if (!isRedactedValue(value)) result.abuseEmail = value;
        break;
      case "orgtechphone":
        if (!isRedactedValue(value) && result.techPhone === "Unknown")
          result.techPhone = value.replace(/^tel:/i, "").trim();
        break;
      case "registrant email":
      case "registrant contact email":
        if (!isRedactedValue(value))
          result.registrantEmail = value.replace(
            "Select Request Email Form at ",
            "",
          );
        break;
      case "dnssec":
      case "dnssec status":
      case "signed":
        result.dnssec = value;
        break;
      case "email":
        if (!isRedactedValue(value) && result.registrantEmail === "Unknown")
          result.registrantEmail = value;
        break;
      case "e-mail":
        if (!isRedactedValue(value) && result.registrantEmail === "Unknown")
          result.registrantEmail = value;
        break;
      case "registrar url":
      case "referral url":
      case "registrar website":
        if (result.registrarURL === "Unknown") result.registrarURL = value;
        break;
      case "cidr":
        result.cidr = value;
        break;
      case "inetnum":
        result.inetNum = value;
        break;
      case "inet6num":
        result.inet6Num = value;
        break;
      case "netrange":
        result.netRange = value;
        break;
      case "netname":
        result.netName = value;
        break;
      case "network-name":
        result.netName = value;
        break;
      case "nettype":
        result.netType = value;
        break;
      case "originas":
        result.originAS = value;
        break;
      case "origin":
        result.originAS = value;
        break;
    }

    if (includeArgs(key, "domain name") && !result.domain && isDomainLike(value)) {
      result.domain = value;
    } else if (
      includeArgs(key, "registrar") &&
      !includeArgs(key, "expir", "date", "phone", "email", "url", "whois", "iana", "server", "abuse", "registration") &&
      result.registrar === "Unknown"
    ) {
      result.registrar = value;
    } else if (
      includeArgs(key, "admin", "administrative") &&
      includeArgs(key, "email", "e-mail", "mail") &&
      result.adminEmail === "Unknown" &&
      !isRedactedValue(value)
    ) {
      result.adminEmail = value;
    } else if (
      includeArgs(key, "admin", "administrative") &&
      includeArgs(key, "phone", "tel") &&
      result.adminPhone === "Unknown" &&
      !isRedactedValue(value)
    ) {
      result.adminPhone = value.replace(/^tel:/i, "").trim();
    } else if (
      includeArgs(key, "tech", "technical") &&
      includeArgs(key, "email", "e-mail", "mail") &&
      result.techEmail === "Unknown" &&
      !isRedactedValue(value)
    ) {
      result.techEmail = value;
    } else if (
      includeArgs(key, "tech", "technical") &&
      includeArgs(key, "phone", "tel") &&
      result.techPhone === "Unknown" &&
      !isRedactedValue(value)
    ) {
      result.techPhone = value.replace(/^tel:/i, "").trim();
    } else if (
      includeArgs(key, "contact email") &&
      result.registrantEmail === "Unknown" &&
      !isRedactedValue(value)
    ) {
      result.registrantEmail = value;
    } else if (
      includeArgs(key, "contact phone") &&
      result.registrantPhone === "Unknown" &&
      !isRedactedValue(value)
    ) {
      result.registrantPhone = value;
    } else if (
      includeArgs(
        key,
        "creation",
        "created",
        "created date",
        "registration time",
        "registered",
        "commencement",
      ) &&
      result.creationDate === "Unknown"
    ) {
      result.creationDate = analyzeTime(value);
    } else if (
      includeArgs(key, "expiration", "expiry", "expire", "expire date") &&
      result.expirationDate === "Unknown"
    ) {
      result.expirationDate = analyzeTime(value);
    } else if (
      includeArgs(
        key,
        "updated",
        "update",
        "last update",
        "last updated",
        "last-modified",
      ) &&
      result.updatedDate === "Unknown"
    ) {
      result.updatedDate = analyzeTime(value);
    } else if (
      includeArgs(key, "account name", "registrant org") &&
      result.registrantOrganization === "Unknown" &&
      !isRedactedValue(value)
    ) {
      result.registrantOrganization = value;
    }
  }

  // Deduplicate status codes
  let newStatus: DomainStatusProps[] = [];
  for (let i = 0; i < result.status.length; i++) {
    const status = result.status[i];
    if (newStatus.find((item) => item.status === status.status)) continue;
    newStatus.push(status);
  }
  result.status = newStatus;

  // Detect synthetic statuses from free-form WHOIS text (reserved, premium,
  // prohibited, suspended) — see parsers/status-injection.ts for full details.
  injectSyntheticStatuses(data, result);

  // Deduplicate nameservers
  const seenNS = new Set<string>();
  result.nameServers = result.nameServers.filter((ns) => {
    const nsKey = ns.toLowerCase().trim();
    if (!nsKey || seenNS.has(nsKey)) return false;
    seenNS.add(nsKey);
    return true;
  });

  // Date fallback: scan raw text for dates near known date keywords when the
  // structured fields were not populated by the switch above.
  if (result.creationDate === "Unknown") {
    const fallback = extractDateNearKeyword(data, [
      "creat", "registered", "activation", "anniversary", "inception",
      "enregistr", "registro", "criado",
    ]);
    if (fallback) result.creationDate = fallback;
  }

  if (result.expirationDate === "Unknown") {
    const fallback = extractDateNearKeyword(data, [
      "expir", "valid until", "paid-till", "paid till", "renewal",
      "due date", "venc", "ablauf", "validade",
    ]);
    if (fallback) result.expirationDate = fallback;
  }

  if (result.updatedDate === "Unknown") {
    const fallback = extractDateNearKeyword(data, [
      "updated", "modified", "last change", "last update", "mise à jour",
      "mise a jour", "modificat", "actualiz",
    ]);
    if (fallback) result.updatedDate = fallback;
  }

  // IDN conversion: if the WHOIS body explicitly declared a Unicode domain
  // name, use that; otherwise try to detect ACE labels in result.domain and
  // convert to Unicode for display.
  if (explicitUnicodeDomain) {
    result.domain = explicitUnicodeDomain;
    if (explicitAsciiDomain) {
      result.domainPunycode = explicitAsciiDomain.toUpperCase();
    } else if (result.domain) {
      const punycheck = convertIdnToUnicode(result.domain);
      if (punycheck.punycode) result.domainPunycode = punycheck.punycode;
    }
  } else if (result.domain) {
    const converted = convertIdnToUnicode(result.domain);
    if (converted.punycode) {
      result.domainPunycode = converted.punycode;
      result.domain = converted.unicode;
    }
  }

  return await applyParams(result);
}
