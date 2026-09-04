import { createClient, SupabaseClient } from "@supabase/supabase-js";
import { createLogger } from "@/lib/logger";

const logger = createLogger("supabase");

let _client: SupabaseClient | null = null;

/**
 * Returns the Supabase admin client (service role).
 * Uses REST/HTTP under the hood — works from any environment including Replit,
 * where direct TCP connections to Supabase are blocked.
 *
 * Required secrets (any one of the key names is accepted):
 *   SUPABASE_URL              – e.g. https://xxxx.supabase.co
 *   SUPABASE_SERVICE_KEY      – service_role key (Replit naming)
 *   SUPABASE_SERVICE_ROLE_KEY – service_role key (Vercel/Supabase standard naming)
 */
export function getSupabase(): SupabaseClient | null {
  if (_client) return _client;

  const url = process.env.SUPABASE_URL;
  const key =
    process.env.SUPABASE_SERVICE_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) {
    logger.error(
      "[supabase] Missing SUPABASE_URL or SUPABASE_SERVICE_KEY / SUPABASE_SERVICE_ROLE_KEY. " +
        "Add them as secrets in your project settings.",
    );
    return null;
  }

  _client = createClient(url, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  return _client;
}
