#!/usr/bin/env node
/**
 * Regenerate src/data/rdap-bootstrap.json from the latest IANA RDAP bootstrap
 * files (ipv4.json / ipv6.json / asn.json).  The dns.json bootstrap lives in
 * src/lib/whois/rdap_gtld_bootstrap.ts (see update-rdap-bootstrap.js).
 *
 * Usage:
 *   node scripts/update-rdap-ip-asn-bootstrap.js
 *
 * Run this periodically (e.g. monthly) or when a new RIR RDAP endpoint appears.
 * The JSON is loaded by src/lib/whois/rdap-bootstrap.ts at build time, so after
 * regenerating you must rebuild for the change to take effect.
 */

const https = require("https");
const fs = require("fs");
const path = require("path");

const IANA_FILES = ["ipv4", "ipv6", "asn"];
const OUT_FILE = path.join(__dirname, "../src/data/rdap-bootstrap.json");

function fetch(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = "";
      res.on("data", (d) => (data += d));
      res.on("end", () => resolve(JSON.parse(data)));
    }).on("error", reject);
  });
}

(async () => {
  const out = { publication: {}, services: {} };
  for (const name of IANA_FILES) {
    const j = await fetch(`https://data.iana.org/rdap/${name}.json`);
    out.publication[name] = j.publication;
    out.services[name] = j.services;
    console.log(`${name}: ${j.services.length} services (pub ${j.publication})`);
  }
  fs.writeFileSync(OUT_FILE, JSON.stringify(out, null, 2) + "\n");
  console.log(`Written ${OUT_FILE}`);
})().catch((e) => {
  console.error("Failed:", e.message);
  process.exit(1);
});
