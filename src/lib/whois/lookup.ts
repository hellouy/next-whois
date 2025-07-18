import { WhoisResult } from "@/lib/whois/types";
import { getJsonRedisValue, setJsonRedisValue } from "@/lib/server/redis";
import { analyzeWhois } from "@/lib/whois/common_parser";
import { extractDomain } from "@/lib/utils";
import whois from "whois-raw";
import fs from "fs";
import path from "path";

// 加载自定义服务器映射
const customServersPath = path.resolve(process.cwd(), "src/lib/whois/custom_servers.json");
let customServers: Record<string, string> = {};
if (fs.existsSync(customServersPath)) {
  customServers = JSON.parse(fs.readFileSync(customServersPath, "utf-8"));
}

function getTld(domain: string) {
  const parts = domain.toLowerCase().split(".");
  if (parts.length < 2) return "";
  return "." + parts[parts.length - 1];
}

async function getLookupRawWhois(domain: string, server: string): Promise<string> {
  return new Promise((resolve, reject) => {
    whois.lookup(domain, { server }, (err: Error, data: string) => {
      if (err) {
        reject(err);
      } else {
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

  // 只查 custom_servers.json
  const tld = getTld(domain);
  const server = customServers[tld];

  if (!server) {
    return {
      time: (performance.now() - startTime) / 1000,
      status: false,
      cached: false,
      source: "whois",
      error: `未配置 ${tld} 的 whois 服务器，请联系开发者维护 custom_servers.json`,
    };
  }

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
    return {
      time: (performance.now() - startTime) / 1000,
      status: false,
      cached: false,
      source: "whois",
      error: errorMessage,
    };
  }
}
