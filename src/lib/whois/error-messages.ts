/**
 * Human-friendly error messages for WHOIS/RDAP lookup failures.
 *
 * The server keeps low-level error strings in English because the failure
 * classifier (classify-failure.ts, whois-patterns.ts) matches on those exact
 * patterns. This module maps them to user-facing copy at the presentation
 * layer — a lookup that fails for a technical reason should read like a
 * person wrote it, not like a stack trace. Order matters: more specific
 * patterns run first.
 */

const HUMANIZED: { re: RegExp; zh: string; en: string }[] = [
  {
    re: /rate.?limit|too many requests|too many queries|\b429\b|please slow down|temporarily rate-limited/i,
    zh: "注册局服务器临时限流，请稍等片刻再试。",
    en: "The registry server is temporarily rate-limiting requests — please try again shortly.",
  },
  {
    re: /timed out|timeout|aborted due to|etimedout/i,
    zh: "查询超时，注册局服务器响应较慢，请稍后重试。",
    en: "The lookup timed out — the registry server is responding slowly, please try again.",
  },
  {
    re: /no public whois\/rdap server|not available for this tld|no whois\/rdap server available|not supported/i,
    zh: "该后缀暂不支持自动查询，可前往注册局官网查看。",
    en: "Automated lookup is not supported for this TLD — try the registry's official website.",
  },
  {
    re: /no rdap server found/i,
    zh: "该后缀没有配置可用的 RDAP 服务。",
    en: "No RDAP service is configured for this TLD.",
  },
  {
    re: /empty whois response|empty response|returned no data|returned only its usage banner|policy|restricts queries from cloud networks/i,
    zh: "注册局返回了空响应，可能限制了数据中心 IP 的查询，可前往注册局官网查看。",
    en: "The registry returned an empty response — it may restrict queries from data-center IPs, try its official website.",
  },
  {
    re: /scraper error|requires captcha|requires verification|could not parse whois data/i,
    zh: "该注册局暂不支持自动查询，可前往注册局官网查看。",
    en: "The registry does not support automated lookups — try its official website.",
  },
  {
    re: /cannot read properties|invalid json|unparseable|unrecognized|unexpected response|parse failed/i,
    zh: "无法解析注册局返回的数据，可能是其页面结构发生了变化。",
    en: "Could not parse the registry's response — its page structure may have changed.",
  },
  {
    re: /not found|no match|not registered|no data found|no entries found|no object found/i,
    zh: "该域名未被注册，可以立即注册。",
    en: "This domain is not registered — it is available to register.",
  },
  {
    re: /econnrefused|econnreset|econnaborted|broken pipe|epipe|enotfound|eai_again|getaddrinfo|nxdomain|dns request timed out/i,
    zh: "无法连接注册局服务器（网络或 DNS 问题），请稍后重试。",
    en: "Could not reach the registry server (network or DNS issue) — please try again.",
  },
];

/**
 * Map a low-level lookup error to a human-friendly message for the requested
 * locale. Returns null when the error does not match any known pattern — the
 * caller should fall back to the original string.
 */
export function humanizeLookupError(
  error: string | null | undefined,
  isZh: boolean,
): string | null {
  if (!error) return null;
  if (error === "INVALID_DOMAIN_TLD") {
    return isZh ? "域名格式不正确，请检查后缀后重试。" : "Invalid domain — please check the TLD.";
  }
  for (const m of HUMANIZED) {
    if (m.re.test(error)) return isZh ? m.zh : m.en;
  }
  return null;
}
