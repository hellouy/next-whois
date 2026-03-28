/**
 * Audit script: test connectivity for all ccTLD RDAP and WHOIS endpoints.
 *
 * RDAP: for each entry in CCTLD_RDAP_OVERRIDES, fetch /domain/<tld>.{tld}
 *       (a non-existent domain is fine — 404 from a working RDAP = pass)
 * WHOIS TCP: for ccTLDs not in RDAP list (and not in STATIC_ALWAYS_FALLBACK),
 *             open a TCP socket to port 43 and send a simple query
 */

import https from "https";
import http from "http";
import net from "net";
import fs from "fs";
import { createRequire } from "module";
import { fileURLToPath } from "url";
import path from "path";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, "..");

// ── Extract CCTLD_RDAP_OVERRIDES from rdap_client.ts ──────────────────────────
const rdapSrc = fs.readFileSync(path.join(ROOT, "src/lib/whois/rdap_client.ts"), "utf8");
const rdapOverrides = {};
for (const m of rdapSrc.matchAll(/^\s{2}(\w{2,4}):\s*"(https?:\/\/[^"]+)"/gm)) {
  rdapOverrides[m[1]] = m[2];
}

// ── Extract STATIC_ALWAYS_FALLBACK from tld-fallback-gate.ts ────────────────
const gateSrc = fs.readFileSync(path.join(ROOT, "src/lib/whois/tld-fallback-gate.ts"), "utf8");
const staticFallback = new Set();
const sfBlock = gateSrc.match(/STATIC_ALWAYS_FALLBACK\s*=\s*new Set\<string\>\(\[([\s\S]+?)\]\)/);
if (sfBlock) {
  for (const m of sfBlock[1].matchAll(/"(\w+)"/g)) staticFallback.add(m[1]);
}

// ── Load cctld WHOIS servers ──────────────────────────────────────────────────
const cctldWhois = require(path.join(ROOT, "src/data/cctld-whois-servers.json"));

const RDAP_TIMEOUT  = 6000;
const WHOIS_TIMEOUT = 4000;
const CONCURRENCY   = 25;

// ── Helper: fetch a URL with timeout ──────────────────────────────────────────
function fetchWithTimeout(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const proto = url.startsWith("https") ? https : http;
    const req = proto.get(url, {
      headers: { Accept: "application/rdap+json, */*" },
      timeout: timeoutMs,
      rejectUnauthorized: false,
    }, res => {
      res.resume();
      resolve({ status: res.statusCode });
    });
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    req.on("error", reject);
  });
}

// ── Helper: test TCP port 43 with quick query ─────────────────────────────────
function testWhoisTcp(host, tld, timeoutMs) {
  return new Promise((resolve, reject) => {
    let data = "";
    const socket = net.connect({ host, port: 43 }, () => {
      socket.write(`${tld}.${tld}\r\n`);
    });
    socket.setTimeout(timeoutMs);
    socket.on("data", d => { data += d.toString(); });
    socket.on("close", () => resolve(data));
    socket.on("timeout", () => { socket.destroy(); reject(new Error("timeout")); });
    socket.on("error", reject);
  });
}

// ── Batch runner ──────────────────────────────────────────────────────────────
async function runBatch(tasks) {
  const results = [];
  for (let i = 0; i < tasks.length; i += CONCURRENCY) {
    const batch = tasks.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(batch.map(t => t()));
    results.push(...batchResults);
    process.stdout.write(`  [${Math.min(i + CONCURRENCY, tasks.length)}/${tasks.length}]\r`);
  }
  process.stdout.write("\n");
  return results;
}

// ── RDAP audit ────────────────────────────────────────────────────────────────
console.log(`\n${"═".repeat(70)}`);
console.log(` RDAP audit — ${Object.keys(rdapOverrides).length} ccTLD endpoints`);
console.log(`${"═".repeat(70)}`);

const rdapTasks = Object.entries(rdapOverrides).map(([tld, base]) => async () => {
  const url = `${base.replace(/\/$/, "")}/domain/test.${tld}`;
  try {
    const { status } = await fetchWithTimeout(url, RDAP_TIMEOUT);
    // 404 = domain not found (RDAP working), 200 = found, 422 = validation error
    // All of the above mean the server is UP and responding correctly
    const ok = [200, 404, 422, 400].includes(status);
    return { tld, url: base, status, ok, error: null };
  } catch (e) {
    return { tld, url: base, status: null, ok: false, error: e.message };
  }
});

const rdapResults = await runBatch(rdapTasks);
const rdapFail = rdapResults.filter(r => !r.ok);
const rdapPass = rdapResults.filter(r => r.ok);

console.log(`\n✅ RDAP passing (${rdapPass.length}):`);
for (const r of rdapPass) {
  console.log(`   .${r.tld.padEnd(6)} HTTP ${r.status}  ${r.url}`);
}
console.log(`\n❌ RDAP failing (${rdapFail.length}):`);
for (const r of rdapFail) {
  const reason = r.error ?? `HTTP ${r.status}`;
  console.log(`   .${r.tld.padEnd(6)} ${reason.padEnd(30)}  ${r.url}`);
}

// ── WHOIS TCP audit ───────────────────────────────────────────────────────────
// Test ccTLDs that are NOT in RDAP overrides and NOT in STATIC_ALWAYS_FALLBACK
const whoisOnlyTlds = Object.keys(cctldWhois).filter(
  tld => !rdapOverrides[tld] && !staticFallback.has(tld) && cctldWhois[tld]
);

console.log(`\n${"═".repeat(70)}`);
console.log(` WHOIS-only audit — ${whoisOnlyTlds.length} ccTLD TCP endpoints`);
console.log(`${"═".repeat(70)}`);

const whoisTasks = whoisOnlyTlds.map(tld => async () => {
  const server = cctldWhois[tld];
  try {
    const raw = await testWhoisTcp(server, tld, WHOIS_TIMEOUT);
    const ok = raw.trim().length > 0;
    const snippet = raw.replace(/\s+/g, " ").trim().substring(0, 60);
    return { tld, server, ok, error: null, snippet };
  } catch (e) {
    return { tld, server, ok: false, error: e.message, snippet: "" };
  }
});

const whoisResults = await runBatch(whoisTasks);
const whoisFail = whoisResults.filter(r => !r.ok);
const whoisPass = whoisResults.filter(r => r.ok);

console.log(`\n✅ WHOIS passing (${whoisPass.length}):`);
for (const r of whoisPass) {
  console.log(`   .${r.tld.padEnd(6)} ${r.server.padEnd(40)} "${r.snippet}"`);
}
console.log(`\n❌ WHOIS failing (${whoisFail.length}):`);
for (const r of whoisFail) {
  console.log(`   .${r.tld.padEnd(6)} ${(r.error || "empty").padEnd(30)} server=${r.server}`);
}

// ── RDAP 5xx / bad status ────────────────────────────────────────────────────
const rdapBadStatus = rdapResults.filter(r => r.status && ![200,404,422,400].includes(r.status));
if (rdapBadStatus.length > 0) {
  console.log(`\n⚠️  RDAP unexpected status codes:`);
  for (const r of rdapBadStatus) {
    console.log(`   .${r.tld.padEnd(6)} HTTP ${r.status}  ${r.url}`);
  }
}

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`\n${"═".repeat(70)}`);
console.log(` Summary`);
console.log(`${"═".repeat(70)}`);
console.log(` RDAP:  ${rdapPass.length} pass / ${rdapFail.length} fail  (of ${rdapResults.length} total)`);
console.log(` WHOIS: ${whoisPass.length} pass / ${whoisFail.length} fail  (of ${whoisResults.length} total)`);
console.log(` Static-always-fallback (skipped): ${staticFallback.size} TLDs`);
console.log();

// ── Suggestions ───────────────────────────────────────────────────────────────
if (rdapFail.length > 0) {
  console.log("Suggested fixes for failing RDAP TLDs:");
  console.log("  - If consistently returning timeout/ECONNREFUSED: remove from CCTLD_RDAP_OVERRIDES");
  console.log("  - If returning HTTP 5xx: add longer timeout in RDAP_TLD_TIMEOUT_MS");
  console.log("  - If returning non-standard response: investigate RDAP URL format");
}
if (whoisFail.length > 0) {
  console.log("Suggested fixes for failing WHOIS TLDs:");
  console.log("  - If timeout/ECONNREFUSED consistently: add to STATIC_ALWAYS_FALLBACK");
  console.log("  - If empty response: server may require specific query format");
}
