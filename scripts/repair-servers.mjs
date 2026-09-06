/**
 * TLD Server Repair Script
 *
 * Reads tld_server_failures from the DB and attempts to discover the correct
 * WHOIS/RDAP server for each failing TLD via:
 *   1. IANA RDAP bootstrap JSON (data.iana.org/rdap/dns.json)
 *   2. Direct TCP query to whois.iana.org for WHOIS referral
 *   3. AI analysis (Groq/Gemini) as fallback for ccTLDs with no bootstrap entry
 *
 * Found servers are saved to custom_whois_servers and the failure record is
 * updated.  TLDs with no server after exhaustive search are marked 'not_found'
 * so they aren't retried on every run.
 *
 * Usage:
 *   node scripts/repair-servers.mjs [options]
 *
 * Options:
 *   --min-failures 3   Only repair TLDs with at least N failures (default: 2)
 *   --limit 50         Max TLDs to process per run (default: 50)
 *   --dry-run          Print what would be saved, don't actually save
 *   --reset-not-found  Re-queue TLDs previously marked not_found
 *   --tld example      Process a single TLD (debug mode)
 *   --debug            Verbose output
 */

import net from "net";
import pg from "pg";

// ── CLI ───────────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const getArg  = n => { const i = args.indexOf(n); return i >= 0 ? args[i+1] : null; };
const hasFlag = n => args.includes(n);
const MIN_FAILURES    = parseInt(getArg("--min-failures") ?? "2");
const LIMIT           = parseInt(getArg("--limit") ?? "50");
const DRY_RUN         = hasFlag("--dry-run");
const RESET_NOT_FOUND = hasFlag("--reset-not-found");
const SINGLE_TLD      = getArg("--tld");
const DEBUG           = hasFlag("--debug");

const log  = (...a) => console.log("[repair]", ...a);
const dbg  = (...a) => { if (DEBUG) console.log("[debug]", ...a); };
const warn = (...a) => console.warn("[repair:warn]", ...a);

// ── Database ──────────────────────────────────────────────────────────────────
const DB_URL = process.env.POSTGRES_URL || process.env.POSTGRES_URL_NON_POOLING ||
               process.env.SUPABASE_DATABASE_URL || process.env.DATABASE_URL;
if (!DB_URL) { console.error("No database URL found."); process.exit(1); }

const pool = new pg.Pool({ connectionString: DB_URL, ssl: { rejectUnauthorized: false }, max: 4 });

async function q(sql, params = []) {
  const { rows } = await pool.query(sql, params);
  return rows;
}
async function run(sql, params = []) {
  await pool.query(sql, params);
}

// ── IANA RDAP bootstrap ────────────────────────────────────────────────────────
let _rdapBootstrap = null;

async function getRdapBootstrap() {
  if (_rdapBootstrap) return _rdapBootstrap;
  try {
    const res = await fetch("https://data.iana.org/rdap/dns.json", {
      headers: { "User-Agent": "domain-repair-bot/1.0 (contact: admin@example.com)" },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json();
    // Build tld → url map from the services array
    const map = {};
    for (const [tlds, urls] of json.services ?? []) {
      const url = urls[0];
      if (!url) continue;
      for (const tld of tlds) {
        map[tld.toLowerCase()] = url;
      }
    }
    _rdapBootstrap = map;
    log(`RDAP bootstrap loaded: ${Object.keys(map).length} TLDs`);
    return map;
  } catch (e) {
    warn("RDAP bootstrap fetch failed:", e.message);
    return {};
  }
}

// ── IANA WHOIS TCP referral ────────────────────────────────────────────────────
function queryWhoisTcp(host, port, query, timeoutMs = 8_000) {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection({ host, port });
    let data = "";
    const timer = setTimeout(() => { sock.destroy(); reject(new Error("TCP timeout")); }, timeoutMs);
    sock.once("connect", () => sock.write(query + "\r\n"));
    sock.on("data", chunk => { data += chunk.toString("utf8"); });
    sock.once("end", () => { clearTimeout(timer); resolve(data); });
    sock.once("error", e => { clearTimeout(timer); reject(e); });
  });
}

async function getIanaWhoisReferral(tld) {
  try {
    const raw = await queryWhoisTcp("whois.iana.org", 43, tld, 8_000);
    dbg(`IANA response for .${tld}:\n${raw.slice(0, 500)}`);
    const m = raw.match(/^refer:\s*(\S+)/im);
    return m ? m[1].trim().toLowerCase() : null;
  } catch (e) {
    dbg(`IANA TCP query failed for .${tld}:`, e.message);
    return null;
  }
}

// ── AI provider ────────────────────────────────────────────────────────────────
let _aiProvider = null;

async function loadAiProvider() {
  if (_aiProvider !== null) return _aiProvider;
  // Read from site_settings DB
  try {
    const rows = await q(`SELECT key, value FROM site_settings WHERE key IN
      ('api_ai_groq_key','api_ai_gemini_key','api_ai_deepseek_key')`);
    const db = Object.fromEntries(rows.map(r => [r.key, r.value]));
    const groq    = process.env.GROQ_API_KEY    || db.api_ai_groq_key;
    const gemini  = process.env.GEMINI_API_KEY  || db.api_ai_gemini_key;
    const deepseek= process.env.DEEPSEEK_API_KEY|| db.api_ai_deepseek_key;

    const providers = [
      groq    && { key: groq,     url: "https://api.groq.com/openai/v1/chat/completions", model: "llama-3.3-70b-versatile", name: "Groq/Llama-3.3-70B" },
      groq    && { key: groq,     url: "https://api.groq.com/openai/v1/chat/completions", model: "qwen-qwq-32b", name: "Groq/QwQ-32B" },
      gemini  && { key: gemini,   url: "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", model: "gemini-2.0-flash", name: "Gemini-2.0-Flash" },
      deepseek && { key: deepseek, url: "https://api.deepseek.com/chat/completions", model: "deepseek-chat", name: "DeepSeek-Chat" },
    ].filter(Boolean);

    _aiProvider = providers[0] ?? null;
    if (_aiProvider) log(`AI provider: ${_aiProvider.name}`);
    else log("No AI provider configured — AI lookups disabled");
  } catch (e) {
    warn("AI provider load error:", e.message);
    _aiProvider = null;
  }
  return _aiProvider;
}

async function askAi(messages) {
  const p = await loadAiProvider();
  if (!p) return null;
  try {
    const res = await fetch(p.url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${p.key}` },
      body: JSON.stringify({ model: p.model, messages, temperature: 0, max_tokens: 512 }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) throw new Error(`AI HTTP ${res.status}`);
    const json = await res.json();
    return json.choices?.[0]?.message?.content?.trim() ?? null;
  } catch (e) {
    dbg("AI call failed:", e.message);
    return null;
  }
}

/**
 * Ask AI to find the WHOIS or RDAP server for a TLD.
 * Returns { type: 'rdap'|'whois', server: string } or null.
 */
async function aiLookupServer(tld) {
  const answer = await askAi([
    {
      role: "system",
      content: `You are a DNS/WHOIS expert.  Given a ccTLD or gTLD, output ONLY a JSON object with these fields:
  - "type": "rdap" | "whois" | "none"
  - "server": the hostname (for whois) or base URL (for rdap), or null if none
  - "notes": brief explanation

Example output:
{"type":"rdap","server":"https://rdap.nic.example/rdap/","notes":"Found in IANA bootstrap"}
{"type":"whois","server":"whois.nic.example","notes":"Registry NIC server"}
{"type":"none","server":null,"notes":"No public WHOIS/RDAP for this TLD"}

Output ONLY the JSON, nothing else.`,
    },
    {
      role: "user",
      content: `What is the public WHOIS server (TCP port 43) or RDAP server for the .${tld} TLD? Check IANA, the ccTLD registry, and any known NIC. Return the official server.`,
    },
  ]);

  if (!answer) return null;
  try {
    const json = JSON.parse(answer.replace(/```[a-z]*\n?/g, "").trim());
    if (json.type === "none") return { type: "none", notes: json.notes };
    if ((json.type === "rdap" || json.type === "whois") && json.server) {
      return { type: json.type, server: json.server.trim(), notes: json.notes };
    }
  } catch (e) {
    dbg("AI JSON parse error:", e.message, "raw:", answer.slice(0, 200));
  }
  return null;
}

// ── Validate that an RDAP server actually responds ─────────────────────────────
async function validateRdap(baseUrl, tld) {
  const url = `${baseUrl.replace(/\/$/, "")}/domain/example.${tld}`;
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/rdap+json,application/json" },
      signal: AbortSignal.timeout(6_000),
    });
    // 200 (found) or 404 (not found but server works) are both valid
    return res.status === 200 || res.status === 404;
  } catch {
    return false;
  }
}

// ── Validate that a WHOIS TCP server responds for the TLD ─────────────────────
async function validateWhois(host, tld) {
  try {
    const raw = await queryWhoisTcp(host, 43, `example.${tld}`, 7_000);
    // Any response with content (not just a timeout) means the server works
    return raw.trim().length > 20;
  } catch {
    return false;
  }
}

// ── Save discovered server ─────────────────────────────────────────────────────
async function saveServer(tld, entry, foundServer, notes) {
  if (DRY_RUN) {
    log(`[DRY-RUN] Would save .${tld}:`, JSON.stringify(entry));
    return;
  }
  await run(
    `INSERT INTO custom_whois_servers (tld, entry, created_at, updated_at)
     VALUES ($1, $2::jsonb, NOW(), NOW())
     ON CONFLICT (tld) DO UPDATE SET entry = $2::jsonb, updated_at = NOW()`,
    [tld, JSON.stringify(entry)],
  );
  await run(
    `UPDATE tld_server_failures
     SET repair_status = 'found', found_server = $2, ai_notes = $3, repaired_at = NOW()
     WHERE tld = $1`,
    [tld, foundServer, notes ?? null],
  );
  log(`✅ .${tld} → ${foundServer} (${notes ?? ""})`);
}

async function markNotFound(tld, notes) {
  if (DRY_RUN) { log(`[DRY-RUN] Would mark .${tld} not_found`); return; }
  await run(
    `UPDATE tld_server_failures
     SET repair_status = 'not_found', ai_notes = $2, repaired_at = NOW()
     WHERE tld = $1`,
    [tld, notes ?? null],
  );
  log(`❌ .${tld} — no server found (${notes ?? "no details"})`);
}

// ── Process a single TLD ───────────────────────────────────────────────────────
async function processTld(tld, rdapBootstrap) {
  log(`\n── .${tld} ──`);

  // 1. RDAP bootstrap (fastest, most reliable)
  const rdapUrl = rdapBootstrap[tld];
  if (rdapUrl) {
    dbg(`RDAP bootstrap hit: ${rdapUrl}`);
    const valid = await validateRdap(rdapUrl, tld);
    if (valid) {
      await saveServer(tld, { type: "http", url: `${rdapUrl.replace(/\/$/, "")}/domain/`, method: "GET" }, rdapUrl, "IANA RDAP bootstrap");
      return;
    }
    log(`  RDAP bootstrap URL did not validate: ${rdapUrl}`);
  }

  // 2. IANA WHOIS TCP referral
  const ianaWhois = await getIanaWhoisReferral(tld);
  if (ianaWhois) {
    dbg(`IANA WHOIS referral: ${ianaWhois}`);
    const valid = await validateWhois(ianaWhois, tld);
    if (valid) {
      await saveServer(tld, ianaWhois, ianaWhois, "IANA WHOIS referral");
      return;
    }
    log(`  IANA referral server did not validate: ${ianaWhois}`);
  }

  // 3. AI lookup (Groq/Gemini)
  log(`  Trying AI lookup for .${tld}…`);
  const ai = await aiLookupServer(tld);
  if (ai) {
    dbg(`AI result:`, ai);
    if (ai.type === "none") {
      await markNotFound(tld, `AI: ${ai.notes}`);
      return;
    }
    if (ai.type === "rdap" && ai.server) {
      const valid = await validateRdap(ai.server, tld);
      if (valid) {
        await saveServer(tld, { type: "http", url: `${ai.server.replace(/\/$/, "")}/domain/`, method: "GET" }, ai.server, `AI: ${ai.notes}`);
        return;
      }
    }
    if (ai.type === "whois" && ai.server) {
      const valid = await validateWhois(ai.server, tld);
      if (valid) {
        await saveServer(tld, ai.server, ai.server, `AI: ${ai.notes}`);
        return;
      }
    }
    log(`  AI suggestion did not validate: ${JSON.stringify(ai)}`);
  }

  await markNotFound(tld, ianaWhois ? `IANA referral ${ianaWhois} invalid; AI also failed` : "No RDAP bootstrap, no IANA referral, AI failed");
}

// ── Main ───────────────────────────────────────────────────────────────────────
async function main() {
  log("TLD Server Repair — starting");
  if (DRY_RUN) log("DRY-RUN mode — no changes will be saved");

  if (RESET_NOT_FOUND && !DRY_RUN) {
    await run(`UPDATE tld_server_failures SET repair_status = 'pending' WHERE repair_status = 'not_found'`);
    log("Reset all not_found entries to pending");
  }

  let rows;
  if (SINGLE_TLD) {
    rows = [{ tld: SINGLE_TLD.toLowerCase().replace(/^\./, "") }];
  } else {
    rows = await q(
      `SELECT tld FROM tld_server_failures
       WHERE repair_status = 'pending'
         AND fail_count >= $1
       ORDER BY fail_count DESC, last_failed_at DESC
       LIMIT $2`,
      [MIN_FAILURES, LIMIT],
    );
  }

  if (rows.length === 0) {
    log("No TLDs to repair.");
    await pool.end();
    return;
  }

  log(`Processing ${rows.length} TLD(s) (min-failures=${MIN_FAILURES}, limit=${LIMIT})`);

  const rdapBootstrap = await getRdapBootstrap();

  for (const { tld } of rows) {
    try {
      await processTld(tld, rdapBootstrap);
    } catch (e) {
      warn(`.${tld} unexpected error:`, e.message);
    }
    // Brief delay between TLDs to avoid hammering IANA
    await new Promise(r => setTimeout(r, 600));
  }

  log("\nRepair run complete.");
  await pool.end();
}

main().catch(e => { console.error(e); process.exit(1); });
