import { DomainPricing } from "../pricing/client";
import { DnsProbeResult } from "./dns-check";

/** Raw output from any WHOIS/scraper transport layer. */
export interface WhoisRawResult {
  raw: string;
  structured: Record<string, unknown>;
  server?: string;
  registryUrl?: string;
}

export type WhoisResult = {
  status: boolean;
  time: number;
  cached?: boolean;
  cachedAt?: number;
  cacheTtl?: number;
  source?: "rdap" | "whois" | "tian.hu" | "YISI.YUN";
  result?: WhoisAnalyzeResult;
  error?: string;
  dnsProbe?: DnsProbeResult;
  registryUrl?: string;
};

export type WhoisAnalyzeResult = {
  domain: string;
  domainPunycode?: string;
  registrar: string;
  registrarURL: string;
  ianaId: string;
  whoisServer: string;
  registryDomainId: string;
  updatedDate: string;
  creationDate: string;
  expirationDate: string;
  status: DomainStatusProps[];
  nameServers: string[];

  // Registrant contact
  registrantName: string;
  registrantOrganization: string;
  registrantCountry: string;
  registrantProvince: string;
  registrantCity: string;
  registrantAddress: string;
  registrantPostalCode: string;
  registrantPhone: string;
  registrantFax: string;
  registrantEmail: string;

  // Administrative contact
  adminName: string;
  adminOrganization: string;
  adminCountry: string;
  adminEmail: string;
  adminPhone: string;

  // Technical contact
  techName: string;
  techOrganization: string;
  techEmail: string;
  techPhone: string;

  abuseEmail: string;
  abusePhone: string;
  dnssec: string;
  rawWhoisContent: string;
  rawRdapContent?: string;

  // Domain age and expiration
  domainAge: number | null;
  remainingDays: number | null;

  // Domain pricing
  registerPrice: DomainPricing | null;
  renewPrice: DomainPricing | null;
  negotiable: boolean | null;

  cidr: string;
  inetNum: string;
  inet6Num: string;
  netRange: string;
  netName: string;
  netType: string;
  originAS: string;
};

export type DomainStatusProps = {
  status: string;
  url: string;
};

export const initialWhoisAnalyzeResult: WhoisAnalyzeResult = {
  domain: "",
  registrar: "Unknown",
  registrarURL: "Unknown",
  ianaId: "N/A",
  whoisServer: "Unknown",
  registryDomainId: "Unknown",
  updatedDate: "Unknown",
  creationDate: "Unknown",
  expirationDate: "Unknown",
  status: [],
  nameServers: [],

  // Registrant contact
  registrantName: "Unknown",
  registrantOrganization: "Unknown",
  registrantCountry: "Unknown",
  registrantProvince: "Unknown",
  registrantCity: "Unknown",
  registrantAddress: "Unknown",
  registrantPostalCode: "Unknown",
  registrantPhone: "Unknown",
  registrantFax: "Unknown",
  registrantEmail: "Unknown",

  // Administrative contact
  adminName: "Unknown",
  adminOrganization: "Unknown",
  adminCountry: "Unknown",
  adminEmail: "Unknown",
  adminPhone: "Unknown",

  // Technical contact
  techName: "Unknown",
  techOrganization: "Unknown",
  techEmail: "Unknown",
  techPhone: "Unknown",

  abuseEmail: "Unknown",
  abusePhone: "Unknown",
  dnssec: "",
  rawWhoisContent: "",

  // Domain age and expiration
  domainAge: null,
  remainingDays: null,

  // Domain pricing
  registerPrice: null,
  renewPrice: null,
  negotiable: null,

  cidr: "Unknown",
  inetNum: "Unknown",
  inet6Num: "Unknown",
  netRange: "Unknown",
  netName: "Unknown",
  netType: "Unknown",
  originAS: "Unknown",
};
