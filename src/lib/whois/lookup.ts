import { MAX_WHOIS_FOLLOW } from "@/lib/env";
import { WhoisResult } from "@/lib/whois/types";
import { getJsonRedisValue, setJsonRedisValue } from "@/lib/server/redis";
import { analyzeWhois } from "@/lib/whois/common_parser";
import { extractDomain } from "@/lib/utils";
import whois from "whois-raw";
import fs from "fs";
import path from "path";

// 加载自定义服务器映射
let customServers: Record<string, string> = {};
const customServersPath = path.resolve(process.cwd(), "src/lib/whois/custom_servers.json");
if (fs.existsSync(customServersPath)) {
  customServers = JSON.parse(fs.readFileSync(customServersPath, "utf-8"));
  console.log("[WHOIS] Loaded custom servers:", customServers);
} else {
  console.warn("[WHOIS] custom_servers.json not found at", customServersPath);
}

function getTld(domain: string) {
  const parts = domain.toLowerCase().split(".");
  if (parts.length < 2) return "";
  return "." + parts[parts.length - 1];
}

// 只用 custom_servers.json 指定的服务器
async function getLookupRawWhois(domain: string, server: string): Promise<string> {
  return new Promise((resolve, reject) => {
    whois.lookup(domain, { server }, (err: Error, data: string) => {
      if (err) {
        console.error(`[WHOIS] 查询失败: ${domain} @ ${server} - ${err.message}`);
        reject(err);
      } else {
        console.log(`[WHOIS] 查询成功: ${domain} @ ${server}`);
        resolve(data);
      }
    });
  });
}

export async function lookupWhoisWithCache(
  domain: string,
): Promise<WhoisResult> {
  const key = `whois:${domain}`;
  const cached = await getJsonRedisValue<WhoisResult>(key);
  if (cached) {
    return {
      ...cached,
      time: 0,
      cached: true,
    };
  }

  const result = await lookupWhois(domain);
  if (result.status) {
    await setJsonRedisValue<WhoisResult>(key, result);
  }

  return {
    ...result,
    cached: false,
  };
}

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
