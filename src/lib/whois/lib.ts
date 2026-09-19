// Special-case domain normalisation for the URL parser.
//
// The legacy per-TLD regexp table (DomainRegex / getDomainRegex) that used to
// live here was superseded by src/lib/whois/common_parser.ts and had no
// remaining callers; only getSpecialDomain is still used (src/lib/utils.ts).

const specialDomains: Record<string, string> = {
  "ac.cn": "www.ac.cn",
  "gov.cn": "www.gov.cn",
  "com.cn": "www.com.cn",
  "org.cn": "www.org.cn",
  "net.cn": "www.net.cn",
  "edu.cn": "www.edu.cn",
  "mil.cn": "www.mil.cn",
};

export function getSpecialDomain(domain: string): string {
  return specialDomains[domain.toLowerCase()] ?? domain;
}
