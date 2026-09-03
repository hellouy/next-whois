/** Minimal shape of an HTTP custom-server entry (mirrors HttpServerEntry in custom-servers.ts). */
interface HttpEntry {
  url: string;
  method?: "GET" | "POST";
  body?: string;
}

export async function queryWhoisTcp(
  host: string,
  port: number,
  query: string,
  timeoutMs: number,
): Promise<string> {
  const { resolveWithDohFallback } = await import("./dns-resolver");
  let resolvedHost = host;
  try {
    resolvedHost = await resolveWithDohFallback(host);
  } catch {}

  return new Promise((resolve, reject) => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const net = require("node:net") as typeof import("net");
    let data = "";
    const socket = net.connect({ host: resolvedHost, port }, () => {
      // Do NOT half-close the socket with socket.end() after writing. Some
      // WHOIS servers (e.g. the JWhoisServer deployment behind whois.nic.tg)
      // discard the pending query when the FIN arrives and return zero bytes.
      // The standard WHOIS flow is: client sends the query, server responds
      // and closes the connection — matching whoiser's behaviour here.
      socket.write(query + "\r\n");
    });
    socket.setTimeout(timeoutMs);
    socket.on("data", (chunk: Buffer) => (data += chunk.toString()));
    socket.on("close", () => resolve(data));
    // A server that responds but never closes should still yield its data
    // once the timeout fires, rather than failing the whole query.
    socket.on("timeout", () => {
      if (data.trim().length > 0) resolve(data);
      socket.destroy(new Error("TCP WHOIS timeout"));
    });
    socket.on("error", reject);
  });
}

function decodeHtmlEntities(text: string): string {
  return text
    // Named entities
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&mdash;/g, "—")
    .replace(/&ndash;/g, "–")
    .replace(/&hellip;/g, "…")
    .replace(/&copy;/g, "©")
    .replace(/&reg;/g, "®")
    .replace(/&trade;/g, "™")
    // Decimal numeric entities: &#123;
    .replace(/&#(\d{1,6});/g, (_, n) => {
      const code = parseInt(n, 10);
      return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : "";
    })
    // Hex numeric entities: &#x1F600;
    .replace(/&#x([0-9a-fA-F]{1,6});/g, (_, h) => {
      const code = parseInt(h, 16);
      return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : "";
    });
}

function stripHtmlToWhoisText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(?:tr|p|div|li|h[1-6]|pre)>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .split("\n")
    .map((l) => decodeHtmlEntities(l).replace(/[ \t]+/g, " ").trim())
    .filter((l) => l.length > 0)
    .join("\n");
}

export async function queryWhoisHttp(
  entry: HttpEntry,
  domain: string,
  timeoutMs: number,
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const placeholder = (s: string) => s.replace(/\{\{domain\}\}/g, domain);
  const url = placeholder(entry.url);
  const method = entry.method || "GET";

  try {
    const init: RequestInit = {
      method,
      signal: controller.signal,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (compatible; next-whois-ui/1.0; +https://github.com/zmh-program/next-whois-ui)",
        Accept: "text/plain, text/html, */*",
      },
    };
    if (method === "POST") {
      init.body = entry.body ? placeholder(entry.body) : domain;
      (init.headers as Record<string, string>)["Content-Type"] =
        "application/x-www-form-urlencoded";
    }
    const res = await fetch(url, init);
    if (!res.ok) throw new Error(`HTTP WHOIS server returned ${res.status}`);
    const contentType = res.headers.get("content-type") || "";
    const text = await res.text();
    if (contentType.includes("text/html") || text.trimStart().startsWith("<!")) {
      return stripHtmlToWhoisText(text);
    }
    return text;
  } finally {
    clearTimeout(timer);
  }
}
