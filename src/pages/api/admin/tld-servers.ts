import type { NextApiRequest, NextApiResponse } from "next";
import {
  getAllCustomServers,
  getAllDbServersWithSource,
  getRegistryInfoServers,
  setCustomServer,
  deleteCustomServer,
  CustomServerEntry,
  ServerWithSource,
  BUILTIN_SERVER_TLDS,
} from "@/lib/whois/custom-servers";
import { invalidateLookupCacheForTld } from "@/lib/whois/lookup";
import { deleteRedisKeysByPattern } from "@/lib/server/redis";
import { requireAdmin } from "@/lib/admin";

async function purgeTldCache(tld: string): Promise<number> {
  const normalized = tld.toLowerCase().replace(/^\./, "");
  const l1Count = invalidateLookupCacheForTld(normalized);
  const l2Count = await deleteRedisKeysByPattern(`whois:*.${normalized}`);
  return l1Count + l2Count;
}

export const config = {
  maxDuration: 10,
};

type ResponseData = {
  success: boolean;
  message?: string;
  servers?: Record<string, CustomServerEntry>;
  dbServers?: Record<string, ServerWithSource>;
  registryServers?: Record<string, CustomServerEntry>;
  builtinTlds?: string[];
};

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<ResponseData>,
) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method === "GET") {
    const [servers, dbServers, registryServers] = await Promise.all([
      getAllCustomServers(),
      getAllDbServersWithSource(),
      getRegistryInfoServers(),
    ]);
    return res.status(200).json({
      success: true,
      servers,
      dbServers,
      registryServers,
      builtinTlds: [...BUILTIN_SERVER_TLDS],
    });
  }

  if (req.method === "POST") {
    const { tld, server, entry } = req.body as {
      tld?: string;
      server?: string;
      entry?: CustomServerEntry;
    };
    if (!tld) {
      return res.status(400).json({ success: false, message: "tld is required" });
    }
    const value: CustomServerEntry | undefined = entry ?? server;
    if (!value) {
      return res.status(400).json({ success: false, message: "server or entry is required" });
    }
    await setCustomServer(tld, value);
    const purged = await purgeTldCache(tld);
    const label = typeof value === "string" ? value : JSON.stringify(value);
    return res
      .status(200)
      .json({ success: true, message: `Added: .${tld.replace(/^\./, "")} → ${label}`, purged });
  }

  if (req.method === "DELETE") {
    const tld = (req.query.tld as string) || (req.body as any)?.tld;
    if (!tld) {
      return res
        .status(400)
        .json({ success: false, message: "tld is required" });
    }
    const removed = await deleteCustomServer(tld);
    if (!removed) {
      return res
        .status(404)
        .json({ success: false, message: `TLD .${tld.replace(/^\./, "")} not found in user-managed list` });
    }
    const purged = await purgeTldCache(tld);
    return res
      .status(200)
      .json({ success: true, message: `Removed: .${tld.replace(/^\./, "")}`, purged });
  }

  return res.status(405).json({ success: false, message: "Method not allowed" });
}
