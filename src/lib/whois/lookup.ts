import { MAX_WHOIS_FOLLOW } from "@/lib/env";
import { WhoisResult } from "@/lib/whois/types";
import { getJsonRedisValue, setJsonRedisValue } from "@/lib/server/redis";
import { analyzeWhois } from "@/lib/whois/common_parser";
import { extractDomain } from "@/lib/utils";
import { lookupRdap, convertRdapToWhoisResult } from "@/lib/whois/rdap_client";
import whois from "whois-raw";
import fs from "fs";
import path from "path";

// 加载自定义服务器映射
let customServers: Record<string, string> = {};
const customServersPath = path.resolve(process.cwd(), "src/lib/whois/custom_servers.json");
if (fs.existsSync(customServersPath)) {
  customServers = JSON.parse(fs.readFileSync(customServersPath, "utf-8"));
}

function getTld(domain: string) {
  const parts = domain.toLowerCase().split(".");
  if (parts.length < 2) return "";
  return "." + parts[parts.length - 1];
}

function getLookupOptions(domain: string) {
  const isDomain = !!extractDomain(domain);
  const tld = getTld(domain);
  // 如果有自定义服务器，指定给 whois-raw
  if (customServers[tld]) {
    return {
      follow: isDomain ? MAX_WHOIS_FOLLOW : 0,
      server: customServers[tld],
    };
  }
  return {
    follow: isDomain ? MAX_WHOIS_FOLLOW : 0,
  };
}

function getLookupRawWhois(domain: string, options?: any): Promise<string> {
  return new Promise((resolve, reject) => {
    try {
      whois.lookup(domain, options, (err: Error, data: string) => {
        if (err) {
          reject(err);
        } else {
          resolve(data);
        }
      });
    } catch (e) {
      reject(e);
    }
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

  try {
    const rdapData = await lookupRdap(domain);
    const result = await convertRdapToWhoisResult(rdapData, domain);

    return {
      time: (performance.now() - startTime) / 1000,
      status: true,
      cached: false,
      source: "rdap",
      result,
    };
  } catch (rdapError: unknown) {
    console.log("RDAP lookup failed, fallback to WHOIS:", rdapError);

    try {
      const whoisData = await getLookupRawWhois(
        domain,
        getLookupOptions(domain),
      );
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
}
