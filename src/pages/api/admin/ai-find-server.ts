/**
 * /api/admin/ai-find-server
 *
 * AI-powered WHOIS server discovery for a single TLD.
 * Uses a layered strategy:
 *   1. Probe known shared-registry WHOIS clusters (TCP, free, fast)
 *   2. IANA RDAP bootstrap
 *   3. IANA WHOIS TCP referral (whois.iana.org)
 *   4. AI model lookup
 *
 * POST /api/admin/ai-find-server   { tld, mode:"full"|"clusters-only" }
 *   → SSE stream with events: start | probe | found | done | error
 *
 * GET  /api/admin/ai-find-server   → list of known clusters (for display)
 */

import type { NextApiRequest, NextApiResponse } from "next";
import net from "net";
import { requireAdmin } from "@/lib/admin";
import { setRepairedServer } from "@/lib/whois/custom-servers";
import { markTldRepaired, markTldNotFound } from "@/lib/whois/server-failure-tracker";
import { callProviderWithFallback } from "@/lib/server/ai-providers";
import { getDbReady } from "@/lib/db";

export const config = { maxDuration: 60 };

// ── Shared-registry WHOIS clusters ───────────────────────────────────────────
// These organizations run shared WHOIS infrastructure serving many TLDs.
export interface WhoisCluster {
  name: string;
  host: string;
  desc: string;
  knownTlds?: string[];   // non-exhaustive hint list
}

export const WHOIS_CLUSTERS: WhoisCluster[] = [
  {
    name: "Identity Digital / Afilias",
    host: "whois.identitydigital.com",
    desc: "Afilias 后继者，管理数百个 gTLD（.io, .mobi, .info, .ag, .bz, .in 等）",
    knownTlds: ["io","mobi","info","ag","bz","in","mn","pro","me","tel","gy","lc","vc","ms","tc","vg","dm","sc","ki","mu","ai","bm","aw","gd","pm","re","mq","gp","yt","wf","tf","nc","pf"],
  },
  {
    name: "Afilias (legacy)",
    host: "whois.afilias.net",
    desc: "Afilias 旧端点，与 identitydigital.com 互为备份",
  },
  {
    name: "CentralNic",
    host: "whois.centralnic.com",
    desc: "管理 uk.com, us.com, eu.com, cn.com 等二级域及部分 ccTLD/gTLD",
    knownTlds: ["uk.com","us.com","eu.com","cn.com","de.com","br.com","ru.com","sa.com","se.com","qc.com","gr.com","hu.com","ar.com","kr.com","no.com","za.com","jpn.com","ae","fo","im","ky","ms","nu","pm","re","tf","wf","yt","fm","gs"],
  },
  {
    name: "Donuts",
    host: "whois.donuts.co",
    desc: "Donuts 管理数百个新 gTLD（.wiki, .ninja, .diet, .accountant 等）",
    knownTlds: ["wiki","ninja","diet","accountant","actor","agency","apartments","attorney","auction","band","bargains","bike","bingo","boutique","builders","business","cab","camera","camp","cards","care","careers","cash","catering","center","chat","cheap","church","city","claims","cleaning","clinic","clothing","coach","codes","coffee","community","company","computer","condos","construction","consulting","contractors","cool","coupons","credit","cruises","dance","dating","deals","delivery","democrat","diamonds","digital","direct","directory","discount","domains","education","email","energy","engineering","enterprises","equipment","estate","events","exchange","expert","exposed","fail","farm","finance","fish","fitness","flights","florist","foundation","fun","fund","games","gifts","glass","guide","guru","healthcare","holdings","holiday","house","info","insure","investments","kitchen","legal","limo","loan","management","marketing","media","memorial","money","movies","network","partners","parts","photography","photos","pizza","place","plumbing","productions","properties","recipes","repairs","report","reviews","run","sale","school","services","shoes","show","singles","soccer","social","studio","style","supplies","supply","support","surgery","systems","tattoo","technology","tips","today","tools","trades","training","vacations","ventures","viajes","villas","vision","watch","works","world","zone"],
  },
  {
    name: "Google Registry",
    host: "whois.nic.google",
    desc: "Google 旗下 gTLD（.app, .dev, .page, .how, .soy, .みんな 等）",
    knownTlds: ["app","dev","page","how","soy","fly","esq","prof","phd","new","rsvp","eat"],
  },
  {
    name: "Verisign",
    host: "whois.verisign-grs.com",
    desc: "Verisign 管理 .com, .net 及多个 ccTLD",
    knownTlds: ["com","net","name","edu","gov","mil","cc","tv"],
  },
  {
    name: "PIR – Public Interest Registry",
    host: "whois.pir.org",
    desc: "PIR 管理 .org, .ngo, .ong, .给我 等",
    knownTlds: ["org","ngo","ong","bio","int"],
  },
  {
    name: "MMRegistry / Minds+Machines",
    host: "whois.mmregistry.com",
    desc: "Minds+Machines 旗下 gTLD（.law, .fit, .fashion, .surf 等）",
    knownTlds: ["law","fit","fashion","surf","surf","navy","energy","green","kiwi","luxury","ooo","property","sexy","voting","webcam","wedding"],
  },
  {
    name: "Nominet",
    host: "whois.nominet.uk",
    desc: "英国 ccTLD 注册局（.uk, .co.uk, .org.uk, .me.uk 等）",
    knownTlds: ["uk","co.uk","org.uk","me.uk","net.uk","sch.uk","ltd.uk","plc.uk","police.uk","nhs.uk"],
  },
  {
    name: "Radix / PDR",
    host: "whois.publicdomainregistry.com",
    desc: "Radix / Public Domain Registry（.online, .site, .tech, .store 等）",
    knownTlds: ["online","site","tech","store","fun","press","website","space","host","host","pw","in","de","eu","co","tv","rest","art"],
  },
  {
    name: "Neustar / TransUnion",
    host: "whois.neustar.biz",
    desc: "Neustar 旗下 gTLD（.biz, .us, .jobs 等）",
    knownTlds: ["biz","us","jobs","tel","co"],
  },
  {
    name: "EURid",
    host: "whois.eurid.eu",
    desc: ".eu 欧盟顶级域注册局",
    knownTlds: ["eu"],
  },
  {
    name: "ISOC / ARIN (whois.arin.net)",
    host: "whois.arin.net",
    desc: "ARIN IP/ASN 数据库，也包含部分 TLD 信息",
    knownTlds: [],
  },
];

// ── TCP helpers ───────────────────────────────────────────────────────────────
function queryWhoisTcp(host: string, query: string, port = 43, timeoutMs = 6000): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    const sock = net.createConnection({ host, port });
    const timer = setTimeout(() => { sock.destroy(); reject(new Error(`TCP timeout (${timeoutMs}ms)`)); }, timeoutMs);
    sock.once("connect", () => sock.write(query + "\r\n"));
    sock.on("data", chunk => { data += chunk.toString("utf8"); if (data.length > 8000) sock.destroy(); });
    sock.once("close", () => { clearTimeout(timer); resolve(data); });
    sock.once("error", e => { clearTimeout(timer); reject(e); });
  });
}

// ── Cluster probe ─────────────────────────────────────────────────────────────
/**
 * Returns true when the cluster's response indicates it manages this TLD.
 * Heuristic: the server responds (no timeout), and the response body
 * references the domain or contains recognizable WHOIS fields, not a hard
 * "domain invalid" or "TLD not supported" rejection.
 */
function analyseClusterResponse(raw: string, tld: string, domain: string): {
  handles: boolean;
  score: number;
  snippet: string;
} {
  const lower = raw.toLowerCase().trim();
  const snippet = raw.slice(0, 500).trim();

  if (!lower || lower.length < 5) return { handles: false, score: 0, snippet };

  // Hard rejection patterns → definitely does NOT handle this TLD
  const rejections = [
    "invalid tld", "unknown tld", "tld not supported", "invalid domain", "unknown domain",
    "no data found for tld", "not a valid tld", "domain syntax error",
    "this server does not", "we do not serve", "does not handle",
    "no information available", "error: tld",
  ];
  for (const r of rejections) {
    if (lower.includes(r)) return { handles: false, score: 0, snippet };
  }

  let score = 0;

  // Strong positive signals
  if (lower.includes(domain.toLowerCase())) score += 60;  // domain name in response
  if (lower.includes(`.${tld}`)) score += 40;              // TLD mentioned
  if (lower.includes("no match")) score += 30;             // classic "no match" = knows the TLD
  if (lower.includes("not found")) score += 30;
  if (lower.includes("domain name:")) score += 50;         // actual WHOIS record
  if (lower.includes("registrar:")) score += 40;
  if (lower.includes("registry expiry")) score += 40;
  if (lower.includes("creation date")) score += 40;
  if (lower.includes("name server")) score += 20;
  if (lower.includes("status:")) score += 20;

  // Medium signals — response is substantive (not a 1-line error)
  if (raw.length > 100) score += 10;
  if (raw.length > 300) score += 10;

  return { handles: score >= 30, score, snippet };
}

async function probeCluster(cluster: WhoisCluster, tld: string): Promise<{
  cluster: WhoisCluster;
  handles: boolean;
  score: number;
  snippet: string;
  error?: string;
  elapsedMs: number;
}> {
  const domain = `example.${tld}`;
  const start = Date.now();
  try {
    const raw = await queryWhoisTcp(cluster.host, domain, 43, 5000);
    const { handles, score, snippet } = analyseClusterResponse(raw, tld, domain);
    return { cluster, handles, score, snippet, elapsedMs: Date.now() - start };
  } catch (e: any) {
    return { cluster, handles: false, score: 0, snippet: "", error: e.message, elapsedMs: Date.now() - start };
  }
}

// ── IANA helpers ──────────────────────────────────────────────────────────────
async function getIanaWhoisReferral(tld: string): Promise<string | null> {
  try {
    const raw = await queryWhoisTcp("whois.iana.org", tld, 43, 8000);
    const m = raw.match(/^refer:\s*(\S+)/im);
    return m ? m[1].trim().toLowerCase() : null;
  } catch { return null; }
}

async function getRdapBootstrapUrl(tld: string): Promise<string | null> {
  try {
    const res = await fetch("https://data.iana.org/rdap/dns.json", {
      headers: { "User-Agent": "xrw-admin/1.0" },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const json = await res.json() as { services: [string[], string[]][] };
    for (const [tlds, urls] of json.services ?? []) {
      if (tlds.map(t => t.toLowerCase()).includes(tld.toLowerCase())) {
        return urls[0] ?? null;
      }
    }
    return null;
  } catch { return null; }
}

async function validateRdap(baseUrl: string, tld: string): Promise<boolean> {
  try {
    const url = `${baseUrl.replace(/\/$/, "")}/domain/example.${tld}`;
    const res = await fetch(url, {
      headers: { Accept: "application/rdap+json,application/json" },
      signal: AbortSignal.timeout(6000),
    });
    return res.status === 200 || res.status === 404;
  } catch { return false; }
}

// ── AI lookup ─────────────────────────────────────────────────────────────────
async function aiLookupServer(tld: string): Promise<{
  type: "rdap" | "whois" | "cluster" | "none";
  server: string | null;
  clusterHost?: string;
  notes: string;
} | null> {
  const clusterList = WHOIS_CLUSTERS.map(c => `  • ${c.name}: ${c.host}  (${c.desc})`).join("\n");
  try {
    const { content } = await callProviderWithFallback([
      {
        role: "system",
        content: `You are a WHOIS/RDAP expert. Respond ONLY with valid JSON (no markdown):
{"type":"rdap"|"whois"|"cluster"|"none","server":"hostname_or_url_or_null","clusterHost":"optional_cluster_hostname","notes":"brief reason"}
- type "rdap": server is base RDAP URL (e.g. https://rdap.nic.example/)
- type "whois": server is TCP hostname (e.g. whois.nic.example, port 43)
- type "cluster": server is a shared-registry cluster; clusterHost is one of the known clusters below
- type "none": no public server is known for this TLD

Known shared-registry clusters (prefer these when applicable):
${clusterList}`,
      },
      {
        role: "user",
        content: `Find the best WHOIS (port 43) or RDAP server for the .${tld} TLD.
Check: official IANA page, NIC.${tld}, known shared registry clusters (Identity Digital/Afilias often handles small ccTLDs like .vc .gy .lc .ms .tc; CentralNic handles .uk.com .eu.com etc.).
Return the cluster type if a known shared registry serves this TLD.`,
      },
    ]);
    const cleaned = content.replace(/```[a-z]*\n?/g, "").trim();
    return JSON.parse(cleaned);
  } catch { return null; }
}

// ── SSE helper ────────────────────────────────────────────────────────────────
type SendFn = (event: string, data: object) => void;

function makeSse(res: NextApiResponse): SendFn {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();
  return (event, data) => {
    try {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      (res as any).flush?.();
    } catch {}
  };
}

// ── Main find logic ───────────────────────────────────────────────────────────
async function findServer(
  tld: string,
  mode: "full" | "clusters-only",
  send: SendFn,
  save: boolean,
): Promise<{ ok: boolean; method: string; server: string | null; entry?: unknown }> {
  const normalized = tld.toLowerCase().replace(/^\./, "");

  // ── Step 1: Probe shared clusters concurrently ─────────────────────────────
  send("phase", { phase: "clusters", total: WHOIS_CLUSTERS.length });

  const probeResults = await Promise.all(
    WHOIS_CLUSTERS.map(c => probeCluster(c, normalized))
  );

  // Report all probe results
  for (const r of probeResults) {
    send("probe", {
      cluster: r.cluster.name,
      host: r.cluster.host,
      handles: r.handles,
      score: r.score,
      snippet: r.handles ? r.snippet.slice(0, 200) : (r.error ?? "(无响应)"),
      elapsedMs: r.elapsedMs,
    });
  }

  // Sort by score — pick the best matching cluster
  const winners = probeResults
    .filter(r => r.handles)
    .sort((a, b) => b.score - a.score);

  if (winners.length > 0) {
    const best = winners[0];
    const entry: string = best.cluster.host;
    if (save) {
      await setRepairedServer(normalized, entry);
      await markTldRepaired(normalized, entry, `Shared cluster: ${best.cluster.name}`);
    }
    send("found", {
      method: "cluster",
      server: entry,
      clusterName: best.cluster.name,
      score: best.score,
      snippet: best.snippet.slice(0, 300),
    });
    return { ok: true, method: `cluster:${best.cluster.name}`, server: entry, entry };
  }

  if (mode === "clusters-only") {
    send("done", { ok: false, method: "clusters-only", server: null });
    return { ok: false, method: "clusters-only", server: null };
  }

  // ── Step 2: IANA RDAP bootstrap ───────────────────────────────────────────
  send("phase", { phase: "rdap" });
  const rdapUrl = await getRdapBootstrapUrl(normalized);
  if (rdapUrl) {
    const valid = await validateRdap(rdapUrl, normalized);
    if (valid) {
      const entry = { type: "http" as const, url: `${rdapUrl.replace(/\/$/, "")}/domain/`, method: "GET" as const };
      if (save) {
        await setRepairedServer(normalized, entry);
        await markTldRepaired(normalized, rdapUrl, "IANA RDAP bootstrap");
      }
      send("found", { method: "rdap-bootstrap", server: rdapUrl });
      return { ok: true, method: "rdap-bootstrap", server: rdapUrl, entry };
    }
    send("probe", { cluster: "IANA RDAP", host: rdapUrl, handles: false, score: 0, snippet: "RDAP validation failed", elapsedMs: 0 });
  }

  // ── Step 3: IANA WHOIS TCP referral ──────────────────────────────────────
  send("phase", { phase: "iana-tcp" });
  const ianaWhois = await getIanaWhoisReferral(normalized);
  if (ianaWhois) {
    try {
      const resp = await queryWhoisTcp(ianaWhois, `example.${normalized}`, 43, 5000);
      if (resp && resp.length > 10) {
        if (save) {
          await setRepairedServer(normalized, ianaWhois);
          await markTldRepaired(normalized, ianaWhois, "IANA WHOIS TCP referral");
        }
        send("found", { method: "iana-tcp", server: ianaWhois });
        return { ok: true, method: "iana-tcp", server: ianaWhois, entry: ianaWhois };
      }
    } catch {}
    send("probe", { cluster: "IANA TCP", host: ianaWhois, handles: false, score: 0, snippet: "服务器无响应", elapsedMs: 0 });
  }

  // ── Step 4: AI lookup ────────────────────────────────────────────────────
  send("phase", { phase: "ai" });
  const ai = await aiLookupServer(normalized);
  if (ai) {
    send("ai_result", { type: ai.type, server: ai.server, clusterHost: ai.clusterHost, notes: ai.notes });

    if (ai.type === "none") {
      if (save) await markTldNotFound(normalized, `AI: ${ai.notes}`);
      send("done", { ok: false, method: "ai-none", server: null, notes: ai.notes });
      return { ok: false, method: "ai-none", server: null };
    }

    if (ai.type === "cluster" && ai.clusterHost) {
      // Verify the AI-suggested cluster
      const r = await probeCluster({ name: "AI建议", host: ai.clusterHost, desc: ai.notes }, normalized);
      if (r.handles) {
        if (save) {
          await setRepairedServer(normalized, ai.clusterHost);
          await markTldRepaired(normalized, ai.clusterHost, `AI cluster: ${ai.notes}`);
        }
        send("found", { method: "ai-cluster", server: ai.clusterHost, notes: ai.notes, score: r.score });
        return { ok: true, method: "ai-cluster", server: ai.clusterHost, entry: ai.clusterHost };
      }
    }

    if (ai.type === "rdap" && ai.server) {
      const valid = await validateRdap(ai.server, normalized);
      if (valid) {
        const entry = { type: "http" as const, url: `${ai.server.replace(/\/$/, "")}/domain/`, method: "GET" as const };
        if (save) {
          await setRepairedServer(normalized, entry);
          await markTldRepaired(normalized, ai.server, `AI RDAP: ${ai.notes}`);
        }
        send("found", { method: "ai-rdap", server: ai.server, notes: ai.notes });
        return { ok: true, method: "ai-rdap", server: ai.server, entry };
      }
    }

    if (ai.type === "whois" && ai.server) {
      try {
        const resp = await queryWhoisTcp(ai.server, `example.${normalized}`, 43, 5000);
        if (resp && resp.length > 10) {
          if (save) {
            await setRepairedServer(normalized, ai.server);
            await markTldRepaired(normalized, ai.server, `AI WHOIS: ${ai.notes}`);
          }
          send("found", { method: "ai-whois", server: ai.server, notes: ai.notes });
          return { ok: true, method: "ai-whois", server: ai.server, entry: ai.server };
        }
      } catch {}
    }
  }

  if (save) await markTldNotFound(normalized, "All strategies exhausted");
  send("done", { ok: false, method: "exhausted", server: null });
  return { ok: false, method: "exhausted", server: null };
}

// ── Handler ───────────────────────────────────────────────────────────────────
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  // GET — return cluster list
  if (req.method === "GET") {
    return res.json({ clusters: WHOIS_CLUSTERS });
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { tld, mode = "full", save = true } = req.body as {
    tld?: string;
    mode?: "full" | "clusters-only";
    save?: boolean;
  };

  if (!tld) return res.status(400).json({ error: "tld is required" });
  const normalized = tld.toLowerCase().replace(/^\./, "");

  const send = makeSse(res);
  send("start", { tld: normalized, mode });

  const hb = setInterval(() => {
    try { res.write(": heartbeat\n\n"); (res as any).flush?.(); } catch {}
  }, 5000);

  try {
    const result = await findServer(normalized, mode, send, !!save);
    send("done", { ...result });
  } catch (e: any) {
    send("error", { message: e.message });
  }

  clearInterval(hb);
  res.end();
}
