export type IcsEvent = {
  uid: string;
  summary: string;
  start: string; // ISO date (YYYY-MM-DD)
  end?: string;
  description?: string;
  url?: string;
};

function esc(v: string): string {
  return v
    .replace(/\\/g, "\\\\")
    .replace(/;/g, "\\;")
    .replace(/,/g, "\\,")
    .replace(/\n/g, "\\n");
}

function formatDate(iso: string): string {
  return iso.replace(/-/g, "");
}

function fold(line: string): string {
  if (line.length <= 73) return line + "\r\n";
  const out: string[] = [];
  let rest = line;
  while (rest.length > 0) {
    const chunk = rest.slice(0, 73);
    out.push(out.length === 0 ? chunk : " " + chunk);
    rest = rest.slice(73);
  }
  return out.join("\r\n") + "\r\n";
}

export function buildIcs(events: IcsEvent[], opts?: { prodId?: string; calendarName?: string }): string {
  const prodId = opts?.prodId || "-//WHOIS Reminder//EN";
  const now = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const lines: string[] = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    `PRODID:${esc(prodId)}`,
    `X-WR-CALNAME:${esc(opts?.calendarName || "Domain Expiry Reminders")}`,
    "X-WR-CALDESC:Domain expiration and lifecycle milestone reminders",
    "CALSCALE:GREGORIAN",
    "METHOD:PUBLISH",
  ];
  for (const e of events) {
    lines.push("BEGIN:VEVENT");
    lines.push(`UID:${esc(e.uid)}`);
    lines.push(`DTSTAMP:${now}`);
    // Whole-day event: DTSTART is a DATE value
    lines.push(`DTSTART;VALUE=DATE:${formatDate(e.start)}`);
    if (e.end) lines.push(`DTEND;VALUE=DATE:${formatDate(e.end)}`);
    lines.push(`SUMMARY:${esc(e.summary)}`);
    if (e.description) lines.push(`DESCRIPTION:${esc(e.description)}`);
    if (e.url) lines.push(`URL:${esc(e.url)}`);
    lines.push("END:VEVENT");
  }
  lines.push("END:VCALENDAR");
  return lines.map(fold).join("");
}
