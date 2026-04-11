/**
 * Per-TLD WHOIS raw-text preprocessors.
 *
 * Each function normalises a registry-specific WHOIS format into the standard
 * "key: value" line structure that analyzeWhois() expects.  Only called when
 * the raw WHOIS text matches the specific registry's fingerprint, so they are
 * no-ops for all other registries.
 */

// ── .sm (San Marino) ─────────────────────────────────────────────────────────

/**
 * Normalises .sm WHOIS output into standard key: value lines.
 *
 * .sm WHOIS uses block-style contact sections:
 *   Owner:
 *   Junpeng Niu          ← name on next line
 *   Chang'An Street 66th ← address (no key prefix)
 *   100000 Beijing
 *   CN                   ← 2-letter country code
 *   Phone: +86 ...       ← sub-fields with colon are passed through
 *   Email: ...
 *
 *   DNS Servers:
 *   ns1.example.com      ← nameservers, one per line
 */
export function preprocessSmWhois(data: string): string {
  if (!/^DNS Servers:\s*$/m.test(data) && !/^Owner:\s*$/m.test(data)) return data;

  const lines = data.split("\n");
  const out: string[] = [];
  let block: "owner" | "tech" | "dns" | null = null;
  let blockLine = 0;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const t = raw.trim();

    if (!t) {
      block = null;
      blockLine = 0;
      out.push("");
      continue;
    }

    if (/^Owner:\s*$/.test(t))                   { block = "owner"; blockLine = 0; continue; }
    if (/^Technical Contact:\s*$/.test(t))        { block = "tech";  blockLine = 0; continue; }
    if (/^Administrative Contact:\s*$/.test(t))   { block = "tech";  blockLine = 0; continue; }
    if (/^DNS Servers?:\s*$/.test(t))             { block = "dns";   blockLine = 0; continue; }

    if (block === "dns") {
      if (t.includes(".")) out.push(`Nameserver: ${t}`);
      continue;
    }

    if (block === "owner" || block === "tech") {
      const colonIdx = t.indexOf(":");
      if (colonIdx > 0 && colonIdx < t.length - 1) {
        out.push(raw);
        blockLine++;
        continue;
      }
      if (blockLine === 0) {
        out.push(block === "owner" ? `Registrant Name: ${t}` : `Tech Name: ${t}`);
        blockLine++;
        continue;
      }
      if (/^[A-Z]{2}$/.test(t) && block === "owner") {
        out.push(`Registrant Country: ${t}`);
        blockLine++;
        continue;
      }
      if (block === "owner" && blockLine === 1) {
        out.push(`Registrant Street: ${t}`);
      }
      blockLine++;
      continue;
    }

    out.push(raw);
  }

  return out.join("\n");
}

// ── .gg / .je (Island Networks) ──────────────────────────────────────────────

/**
 * Normalises Island Networks (.gg / .je) WHOIS output into standard key: value lines.
 *
 * Their format uses section headers (ending with ":") whose values appear on
 * the next indented line(s), and ordinal dates ("10th June 2018 at 05:02:34").
 */
export function preprocessIslandNetworks(data: string): string {
  if (!data.includes("Island Networks") && !data.includes("channelisles.net")) return data;

  const rawLines = data.split("\n");
  const out: string[] = [];
  let lastSectionKey: string | null = null;

  for (let i = 0; i < rawLines.length; i++) {
    const trimmed = rawLines[i].trim();

    if (!trimmed) {
      lastSectionKey = null;
      out.push("");
      continue;
    }

    const sectionMatch = trimmed.match(/^([A-Za-z][^:]*?):\s*$/);
    if (sectionMatch) {
      lastSectionKey = sectionMatch[1].trim();
      continue;
    }

    if (lastSectionKey) {
      const ordinalMatch = trimmed.match(
        /^Registered on\s+(\d{1,2})(?:st|nd|rd|th)\s+(\w+)\s+(\d{4})(?:\s+at\s+(\d{2}:\d{2}:\d{2})(?:\.\d+)?)?/i,
      );
      if (ordinalMatch) {
        const [, day, month, year, time] = ordinalMatch;
        out.push(`Registered on: ${day} ${month} ${year}${time ? " " + time : ""}`);
        continue;
      }
      out.push(`${lastSectionKey}: ${trimmed}`);
      continue;
    }

    out.push(rawLines[i]);
  }

  return out.join("\n");
}
