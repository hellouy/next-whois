export async function lookupWhois(domain: string): Promise<WhoisResult> {
  const startTime = performance.now();

  const tld = getTld(domain);
  const server = customServers[tld];

  if (!server) {
    const errorMsg = `[WHOIS] 未配置 ${tld} 的 whois 服务器，请维护 custom_servers.json`;
    console.error(errorMsg);
    return {
      time: (performance.now() - startTime) / 1000,
      status: false,
      cached: false,
      source: "whois",
      error: errorMsg,
    };
  }

  console.log(`[WHOIS] 查询域名: ${domain}; 使用服务器: ${server}`);

  try {
    const whoisData = await getLookupRawWhois(domain, server);
    const result = await analyzeWhois(whoisData);

    return {
      time: (performance.now() - startTime) / 1000,
      status: true,
      cached: false,
      source: "whois",
      result,
    };
  } catch (whoisError: unknown) {
    const errorMessage =
      whoisError instanceof Error
        ? whoisError.message
        : "Unknown error occurred";
    console.error(`[WHOIS] 查询失败: ${domain} @ ${server} - ${errorMessage}`);
    return {
      time: (performance.now() - startTime) / 1000,
      status: false,
      cached: false,
      source: "whois",
      error: errorMessage,
    };
  }
}
