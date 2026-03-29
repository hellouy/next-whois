import type { NextApiRequest, NextApiResponse } from "next";
import net from "net";
import { requireAdmin } from "@/lib/admin";
import type { CustomServerEntry, TcpServerEntry, HttpServerEntry } from "@/lib/whois/custom-servers";

export const config = { maxDuration: 15 };

type TestResult = {
  ok: boolean;
  method: string;
  output?: string;
  statusCode?: number;
  error?: string;
  elapsedMs: number;
};

function tcpQuery(host: string, port: number, query: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    const socket = net.createConnection({ host, port }, () => {
      socket.write(query + "\r\n");
    });
    socket.setTimeout(timeoutMs);
    socket.on("data", (chunk: Buffer) => { data += chunk.toString(); });
    socket.on("close", () => resolve(data));
    socket.on("timeout", () => socket.destroy(new Error(`TCP timeout after ${timeoutMs}ms`)));
    socket.on("error", reject);
  });
}

async function httpQuery(url: string, method: string, timeoutMs: number): Promise<{ status: number; body: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method,
      signal: controller.signal,
      headers: { Accept: "application/rdap+json,application/json,text/plain" },
    });
    const body = await res.text();
    return { status: res.status, body };
  } finally {
    clearTimeout(timer);
  }
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<TestResult>,
) {
  const session = await requireAdmin(req, res);
  if (!session) return;
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, method: "none", error: "Method not allowed", elapsedMs: 0 });
  }

  const { tld, entry } = req.body as { tld?: string; entry?: CustomServerEntry };
  if (!tld || !entry) {
    return res.status(400).json({ ok: false, method: "none", error: "tld and entry are required", elapsedMs: 0 });
  }

  const domain = `example.${tld.toLowerCase().replace(/^\./, "")}`;
  const start = Date.now();

  try {
    // ── WHOIS TCP ────────────────────────────────────────────────────────────
    if (typeof entry === "string" || (typeof entry === "object" && entry.type === "tcp")) {
      const host = typeof entry === "string" ? entry : (entry as TcpServerEntry).host;
      const port = typeof entry === "object" && (entry as TcpServerEntry).port
        ? (entry as TcpServerEntry).port!
        : 43;

      const raw = await tcpQuery(host, port, domain, 8000);
      const elapsedMs = Date.now() - start;

      if (!raw || raw.trim().length === 0) {
        return res.status(200).json({
          ok: false,
          method: "WHOIS TCP",
          output: "(服务器返回了空响应)",
          error: "Empty response from server",
          elapsedMs,
        });
      }

      const preview = raw.slice(0, 800).trim();
      return res.status(200).json({ ok: true, method: "WHOIS TCP", output: preview, elapsedMs });
    }

    // ── RDAP / HTTP ──────────────────────────────────────────────────────────
    if (typeof entry === "object" && entry.type === "http") {
      const h = entry as HttpServerEntry;
      const url = h.url.replace("{domain}", domain).replace(/\{[^}]+\}/g, domain);
      const resolvedUrl = url.endsWith("/") ? `${url}${domain}` : `${url}/${domain}`;

      const { status, body } = await httpQuery(resolvedUrl, h.method || "GET", 8000);
      const elapsedMs = Date.now() - start;

      const preview = body.slice(0, 800).trim();

      if (status >= 200 && status < 400) {
        return res.status(200).json({ ok: true, method: "HTTP", statusCode: status, output: preview, elapsedMs });
      }
      return res.status(200).json({
        ok: false,
        method: "HTTP",
        statusCode: status,
        output: preview || "(无响应体)",
        error: `HTTP ${status}`,
        elapsedMs,
      });
    }

    // ── Scraper ──────────────────────────────────────────────────────────────
    if (typeof entry === "object" && entry.type === "scraper") {
      return res.status(200).json({
        ok: true,
        method: "Scraper",
        output: `Scraper «${entry.name}» 已配置，无法在此直接测试连通性。注册局页面: ${entry.registryUrl}`,
        elapsedMs: Date.now() - start,
      });
    }

    return res.status(400).json({ ok: false, method: "unknown", error: "未知服务器类型", elapsedMs: Date.now() - start });
  } catch (e: any) {
    return res.status(200).json({
      ok: false,
      method: "?",
      error: e?.message || String(e),
      elapsedMs: Date.now() - start,
    });
  }
}
