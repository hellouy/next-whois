import https from "https";
import http from "http";
import net from "net";

function testRdap(url, timeoutMs = 10000) {
  return new Promise((res, rej) => {
    const proto = url.startsWith("https") ? https : http;
    const req = proto.get(url, {
      headers: { Accept: "application/rdap+json" },
      timeout: timeoutMs,
      rejectUnauthorized: false,
    }, r => { r.resume(); res(r.statusCode); });
    req.on("timeout", () => { req.destroy(); rej(new Error("timeout")); });
    req.on("error", rej);
  });
}

function testWhoisTcp(host, tld, timeoutMs = 5000) {
  return new Promise((res, rej) => {
    let data = "";
    const s = net.connect({ host, port: 43 }, () => s.write(`${tld}.${tld}\r\n`));
    s.setTimeout(timeoutMs);
    s.on("data", d => { data += d.toString(); });
    s.on("close", () => res(data.trim()));
    s.on("timeout", () => { s.destroy(); rej(new Error("timeout")); });
    s.on("error", rej);
  });
}

const rdapToTest = [
  [".ar",       "https://rdap.nic.ar/domain/test.ar"],
  [".br",       "https://rdap.registro.br/domain/test.br"],
  [".as",       "https://rdap.nic.as/domain/test.as"],
  [".co",       "https://rdap.cctld.co/domain/test.co"],
  [".jp alt1",  "https://rdap.jprs.jp/domain/test.jp"],
  [".jp alt2",  "https://jprs.jp/rdap/domain/test.jp"],
  [".kr",       "https://rdap.kr/domain/test.kr"],
  [".hk",       "https://rdap.hkirc.hk/rdap/domain/test.hk"],
  [".nz",       "https://api.nzrs.net.nz/domain/test.nz"],
  [".nz alt",   "https://rdap.srs.net.nz/rdap/domain/test.nz"],
  [".ph",       "https://rdap.ph/domain/test.ph"],
  [".mx",       "https://rdap.mx/domain/test.mx"],
  [".pe",       "https://rdap.nic.pe/domain/test.pe"],
];

const whoisToTest = [
  ["jp","whois.jprs.jp"], ["hk","whois.hkirc.hk"], ["kr","whois.kr"],
  ["nz","whois.irs.net.nz"], ["ph","whois.dot.ph"], ["mx","whois.mx"],
  ["pe","whois.nic.pe"], ["ag","whois.nic.ag"], ["bb","whois.nic.bb"],
  ["ws","whois.website.ws"], ["co","whois.nic.co"],
  ["ar","whois.nic.ar"], ["mn","whois.nic.mn"], ["bt","whois.nic.bt"],
  ["kh","whois.nic.kh"], ["bh","whois.nic.bh"], ["jo","whois.nic.jo"],
  ["om","whois.registry.om"], ["np","whois.nic.np"], ["pk","whois.pknic.net.pk"],
  ["gl","whois.nic.gl"], ["xk","whois.nic.xk"], ["tj","whois.nic.tj"],
  ["ao","whois.nic.ao"], ["gh","whois.nic.gh"], ["ug","whois.nic.ug"],
  ["sc","whois.nic.sc"], ["zw","whois.zispa.co.zw"], ["su","whois.ripn.net"],
  ["dm","whois.nic.dm"], ["jm","whois.nic.jm"], ["lc","whois.nic.lc"],
  ["kn","whois.nic.kn"], ["tt","whois.nic.tt"], ["vc","whois.nic.vc"],
  ["bw","whois.nic.bw"], ["cd","whois.nic.cd"], ["dj","whois.nic.dj"],
  ["et","whois.nic.et"], ["mw","whois.nic.mw"], ["sc","whois.nic.sc"],
  ["ug","whois.nic.ug"], ["bh","whois.nic.bh"], ["ps","whois.pnina.ps"],
  ["sy","whois.tld.sy"], ["mm","whois.nic.mm"], ["vu","whois.nic.vu"],
];

console.log("=== RDAP alternative URL tests ===");
const rdapRes = await Promise.all(rdapToTest.map(async ([label, url]) => {
  try { return `${label.padEnd(12)}: HTTP ${await testRdap(url)}`; }
  catch (e) { return `${label.padEnd(12)}: ${e.message}`; }
}));
rdapRes.forEach(r => console.log(r));

console.log("\n=== WHOIS TCP tests (TLDs being removed from RDAP overrides) ===");
const seen = new Set();
const whoisRes = await Promise.all(whoisToTest.filter(([t]) => {
  if (seen.has(t)) return false; seen.add(t); return true;
}).map(async ([tld, server]) => {
  try {
    const raw = await testWhoisTcp(server, tld, 5000);
    const snip = raw.substring(0, 50).replace(/\s+/g, " ").trim();
    return `.${tld.padEnd(5)} OK  ${server.padEnd(35)} "${snip}"`;
  } catch (e) {
    return `.${tld.padEnd(5)} FAIL ${e.message.substring(0, 25).padEnd(26)} ${server}`;
  }
}));
whoisRes.forEach(r => console.log(r));
