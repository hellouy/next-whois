import { Pool } from "pg";

declare global {
  // eslint-disable-next-line no-var
  var __pgPool: Pool | undefined;
  // eslint-disable-next-line no-var
  var __pgMigrated: boolean | undefined;
}

declare global {
  // eslint-disable-next-line no-var
  var __pgMigrating: Promise<void> | undefined;
}

function getPool(): Pool | null { return global.__pgPool ?? null; }
function setPool(p: Pool | null) { global.__pgPool = p ?? undefined; }
function getMigrated(): boolean { return global.__pgMigrated ?? false; }
function setMigrated(v: boolean) { global.__pgMigrated = v; }

const CREATE_TABLES = [
  `CREATE TABLE IF NOT EXISTS users (
    id                    VARCHAR(16)  PRIMARY KEY,
    email                 TEXT         UNIQUE NOT NULL,
    password_hash         TEXT         NOT NULL,
    name                  TEXT,
    disabled              BOOLEAN      NOT NULL DEFAULT false,
    admin_notes           TEXT,
    avatar_color          TEXT,
    email_verified        BOOLEAN      NOT NULL DEFAULT false,
    email_verify_token    TEXT,
    email_verify_expires  TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id           VARCHAR(16)  PRIMARY KEY,
    user_id      VARCHAR(16)  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token        TEXT         UNIQUE NOT NULL,
    expires_at   TIMESTAMPTZ  NOT NULL,
    used         BOOLEAN      NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS stamps (
    id           VARCHAR(16)  PRIMARY KEY,
    domain       TEXT         NOT NULL,
    tag_name     TEXT         NOT NULL,
    tag_style    TEXT         NOT NULL DEFAULT 'personal',
    link         TEXT,
    description  TEXT,
    nickname     TEXT         NOT NULL,
    email        TEXT         NOT NULL,
    verify_token TEXT         NOT NULL,
    verified     BOOLEAN      NOT NULL DEFAULT false,
    verified_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS reminders (
    id              VARCHAR(16)  PRIMARY KEY,
    domain          TEXT         NOT NULL,
    email           TEXT         NOT NULL,
    expiration_date TEXT,
    active          BOOLEAN      NOT NULL DEFAULT true,
    cancel_token    TEXT,
    cancelled_at    TIMESTAMPTZ,
    cancel_reason   TEXT,
    days_before     INTEGER      DEFAULT 30,
    phase_flags     TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS reminder_logs (
    id          VARCHAR(16)  PRIMARY KEY,
    reminder_id TEXT         NOT NULL REFERENCES reminders(id) ON DELETE CASCADE,
    days_before INTEGER      NOT NULL,
    sent_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (reminder_id, days_before)
  )`,
  `CREATE TABLE IF NOT EXISTS tool_clicks (
    url          TEXT         PRIMARY KEY,
    total_clicks INTEGER      NOT NULL DEFAULT 0,
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS user_tool_clicks (
    user_id         VARCHAR(16)  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url             TEXT         NOT NULL,
    click_count     INTEGER      NOT NULL DEFAULT 0,
    last_clicked_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, url)
  )`,
  `CREATE TABLE IF NOT EXISTS search_history (
    id              VARCHAR(16)  PRIMARY KEY,
    user_id         VARCHAR(16)  REFERENCES users(id) ON DELETE CASCADE,
    query           TEXT         NOT NULL,
    query_type      TEXT         NOT NULL DEFAULT 'domain',
    reg_status      TEXT,
    expiration_date TEXT,
    remaining_days  INTEGER,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS feedback (
    id           VARCHAR(16)  PRIMARY KEY,
    query        TEXT         NOT NULL,
    query_type   TEXT,
    issue_types  TEXT         NOT NULL,
    description  TEXT,
    email        TEXT,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS site_settings (
    key        TEXT         PRIMARY KEY,
    value      TEXT         NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS tld_fallback_stats (
    tld           TEXT         PRIMARY KEY,
    fail_count    INTEGER      NOT NULL DEFAULT 0,
    use_fallback  BOOLEAN      NOT NULL DEFAULT false,
    rdap_skip     BOOLEAN      NOT NULL DEFAULT false,
    last_fail_at  TIMESTAMPTZ
  )`,
  `ALTER TABLE tld_fallback_stats ADD COLUMN IF NOT EXISTS rdap_skip    BOOLEAN NOT NULL DEFAULT false`,
  `ALTER TABLE tld_fallback_stats ADD COLUMN IF NOT EXISTS fail_reason  TEXT`,
  `ALTER TABLE tld_fallback_stats ADD COLUMN IF NOT EXISTS last_domain  TEXT`,
  `ALTER TABLE tld_fallback_stats ADD COLUMN IF NOT EXISTS sample_error TEXT`,
  `CREATE TABLE IF NOT EXISTS custom_whois_servers (
    tld        TEXT         PRIMARY KEY,
    entry      JSONB        NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  // source: 'manual' = admin-managed, 'iana' = auto-discovered from whois.iana.org,
  //         'repair' = promoted from repair queue AI result
  `ALTER TABLE custom_whois_servers ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'manual'`,
  `CREATE TABLE IF NOT EXISTS rate_limit_records (
    key        TEXT         PRIMARY KEY,
    count      INTEGER      NOT NULL DEFAULT 0,
    reset_at   TIMESTAMPTZ  NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS verify_codes (
    email      TEXT         NOT NULL,
    scope      TEXT         NOT NULL DEFAULT 'register',
    code       TEXT         NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (email, scope)
  )`,
  `CREATE TABLE IF NOT EXISTS tld_rules (
    tld                    TEXT         PRIMARY KEY,
    grace_period_days      INTEGER      NOT NULL DEFAULT 0,
    redemption_period_days INTEGER      NOT NULL DEFAULT 0,
    pending_delete_days    INTEGER      NOT NULL DEFAULT 0,
    source_url             TEXT,
    confidence             TEXT         NOT NULL DEFAULT 'ai',
    raw_excerpt            TEXT,
    ai_reasoning           TEXT,
    drop_hour              INTEGER,
    drop_minute            INTEGER,
    drop_second            INTEGER,
    drop_timezone          TEXT,
    pre_expiry_days        INTEGER,
    scraped_at             TIMESTAMPTZ,
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    manually_edited        BOOLEAN      NOT NULL DEFAULT false,
    model_used             TEXT,
    scrape_status          TEXT         NOT NULL DEFAULT 'pending',
    failure_reason         TEXT,
    fetch_strategy         TEXT,
    scrape_attempts        INTEGER      NOT NULL DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS tld_lifecycle_overrides (
    id             VARCHAR(16)  PRIMARY KEY,
    tld            TEXT         NOT NULL UNIQUE,
    grace          INTEGER      NOT NULL DEFAULT 0,
    redemption     INTEGER      NOT NULL DEFAULT 0,
    pending_delete INTEGER      NOT NULL DEFAULT 0,
    registry       TEXT,
    notes          TEXT,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS tld_lifecycle_feedback (
    id                       VARCHAR(16)   PRIMARY KEY,
    tld                      VARCHAR(20)   NOT NULL,
    current_grace            INTEGER,
    current_redemption       INTEGER,
    current_pending_delete   INTEGER,
    suggested_grace          INTEGER       NOT NULL,
    suggested_redemption     INTEGER       NOT NULL,
    suggested_pending_delete INTEGER       NOT NULL,
    source_url               TEXT,
    notes                    TEXT,
    submitter_email          VARCHAR(255),
    status                   VARCHAR(20)   NOT NULL DEFAULT 'pending',
    reviewed_at              TIMESTAMPTZ,
    reviewed_by              VARCHAR(255),
    created_at               TIMESTAMPTZ   NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS sponsors (
    id           VARCHAR(16)  PRIMARY KEY,
    name         TEXT         NOT NULL,
    avatar_url   TEXT,
    amount       NUMERIC(10,2),
    currency     TEXT         NOT NULL DEFAULT 'CNY',
    message      TEXT,
    sponsor_date DATE,
    is_anonymous BOOLEAN      NOT NULL DEFAULT false,
    is_visible   BOOLEAN      NOT NULL DEFAULT true,
    platform     TEXT,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS invite_codes (
    id           VARCHAR(16)  PRIMARY KEY,
    code         TEXT         UNIQUE NOT NULL,
    description  TEXT,
    is_active    BOOLEAN      NOT NULL DEFAULT true,
    max_uses     INTEGER      NOT NULL DEFAULT 1,
    use_count    INTEGER      NOT NULL DEFAULT 0,
    created_by   VARCHAR(16)  REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS friendly_links (
    id           SERIAL       PRIMARY KEY,
    name         TEXT         NOT NULL,
    url          TEXT         NOT NULL,
    description  TEXT,
    category     TEXT,
    sort_order   INTEGER      NOT NULL DEFAULT 0,
    active       BOOLEAN      NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS access_keys (
    id           VARCHAR(16)  PRIMARY KEY,
    key          TEXT         UNIQUE NOT NULL,
    label        TEXT,
    scope        TEXT         NOT NULL DEFAULT 'api',
    is_active    BOOLEAN      NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    use_count    INTEGER      NOT NULL DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS payment_plans (
    id           VARCHAR(16)  PRIMARY KEY,
    name         TEXT         NOT NULL,
    description  TEXT,
    price        NUMERIC(10,2) NOT NULL,
    currency     TEXT         NOT NULL DEFAULT 'CNY',
    duration_days INTEGER,
    is_recurring BOOLEAN      NOT NULL DEFAULT false,
    grants_subscription BOOLEAN NOT NULL DEFAULT true,
    is_active    BOOLEAN      NOT NULL DEFAULT true,
    sort_order   INTEGER      NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS payment_orders (
    id              VARCHAR(32)  PRIMARY KEY,
    user_id         VARCHAR(16)  REFERENCES users(id) ON DELETE SET NULL,
    user_email      TEXT         NOT NULL,
    plan_id         VARCHAR(16)  REFERENCES payment_plans(id) ON DELETE SET NULL,
    plan_name       TEXT         NOT NULL,
    amount          NUMERIC(10,2) NOT NULL,
    currency        TEXT         NOT NULL DEFAULT 'CNY',
    provider        TEXT         NOT NULL,
    provider_order_id TEXT,
    status          TEXT         NOT NULL DEFAULT 'pending',
    paid_at         TIMESTAMPTZ,
    expired_at      TIMESTAMPTZ,
    webhook_raw     TEXT,
    metadata        JSONB,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,

  `CREATE TABLE IF NOT EXISTS activation_codes (
    id              SERIAL       PRIMARY KEY,
    code            TEXT         NOT NULL UNIQUE,
    plan_id         VARCHAR(16)  REFERENCES payment_plans(id) ON DELETE SET NULL,
    plan_name       TEXT         NOT NULL,
    duration_days   INTEGER,
    grants_subscription BOOLEAN  NOT NULL DEFAULT true,
    balance_grant_cents INTEGER  NOT NULL DEFAULT 0,
    used            BOOLEAN      NOT NULL DEFAULT false,
    used_by         VARCHAR(16)  REFERENCES users(id) ON DELETE SET NULL,
    used_at         TIMESTAMPTZ,
    note            TEXT,
    created_by      VARCHAR(16)  REFERENCES users(id) ON DELETE SET NULL,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,

  `CREATE TABLE IF NOT EXISTS balance_transactions (
    id              SERIAL       PRIMARY KEY,
    user_id         VARCHAR(16)  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount_cents    INTEGER      NOT NULL,
    type            TEXT         NOT NULL,
    description     TEXT,
    order_id        VARCHAR(32)  REFERENCES payment_orders(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,

  `CREATE TABLE IF NOT EXISTS changelog_entries (
    id              TEXT         PRIMARY KEY,
    entry_date      DATE         NOT NULL,
    type            TEXT         NOT NULL DEFAULT 'new',
    zh              TEXT         NOT NULL DEFAULT '',
    en              TEXT         NOT NULL DEFAULT '',
    version         TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
];

const ALTER_COLUMNS = [
  `ALTER TABLE users         ADD COLUMN IF NOT EXISTS subscription_expires_at TIMESTAMPTZ`,
  `ALTER TABLE reminders    ADD COLUMN IF NOT EXISTS phase_flags          TEXT`,
  `ALTER TABLE search_history ADD COLUMN IF NOT EXISTS reg_status         TEXT`,
  `ALTER TABLE search_history ADD COLUMN IF NOT EXISTS expiration_date    TEXT`,
  `ALTER TABLE search_history ADD COLUMN IF NOT EXISTS remaining_days     INTEGER`,
  `ALTER TABLE search_history ADD COLUMN IF NOT EXISTS value_tier        TEXT NOT NULL DEFAULT 'normal'`,
  `ALTER TABLE search_history ALTER COLUMN user_id                        DROP NOT NULL`,
  `ALTER TABLE users         ADD COLUMN IF NOT EXISTS disabled            BOOLEAN NOT NULL DEFAULT false`,
  `ALTER TABLE users         ADD COLUMN IF NOT EXISTS admin_notes         TEXT`,
  `ALTER TABLE users         ADD COLUMN IF NOT EXISTS updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
  `ALTER TABLE users         ADD COLUMN IF NOT EXISTS avatar_color        TEXT`,
  `ALTER TABLE users         ADD COLUMN IF NOT EXISTS email_verified      BOOLEAN NOT NULL DEFAULT false`,
  `ALTER TABLE users         ADD COLUMN IF NOT EXISTS email_verify_token  TEXT`,
  `ALTER TABLE users         ADD COLUMN IF NOT EXISTS email_verify_expires TIMESTAMPTZ`,
  `ALTER TABLE users         ADD COLUMN IF NOT EXISTS subscription_access BOOLEAN NOT NULL DEFAULT false`,
  `ALTER TABLE users         ADD COLUMN IF NOT EXISTS invite_code_used    TEXT`,
  `ALTER TABLE stamps        ADD COLUMN IF NOT EXISTS card_theme          TEXT NOT NULL DEFAULT 'app'`,
  `ALTER TABLE invite_codes  ADD COLUMN IF NOT EXISTS expires_at          TIMESTAMPTZ`,
  `ALTER TABLE reminders     ADD COLUMN IF NOT EXISTS thresholds_json     TEXT`,
  `ALTER TABLE reminders     ADD COLUMN IF NOT EXISTS whois_synced_at     TIMESTAMPTZ`,
  `ALTER TABLE reminders     ADD COLUMN IF NOT EXISTS whois_expiry_date   TEXT`,
  `ALTER TABLE reminders     ADD COLUMN IF NOT EXISTS registrar           TEXT`,
  `ALTER TABLE reminders     ADD COLUMN IF NOT EXISTS creation_date       TEXT`,
  `ALTER TABLE reminders     ADD COLUMN IF NOT EXISTS nameservers_json    TEXT`,
  `ALTER TABLE users         ADD COLUMN IF NOT EXISTS balance_cents       INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE users         ADD COLUMN IF NOT EXISTS membership_plan     TEXT`,
  `ALTER TABLE tld_rules     ADD COLUMN IF NOT EXISTS model_used          TEXT`,
  `ALTER TABLE tld_rules     ADD COLUMN IF NOT EXISTS scrape_status       TEXT    NOT NULL DEFAULT 'pending'`,
  `ALTER TABLE tld_rules     ADD COLUMN IF NOT EXISTS failure_reason      TEXT`,
  `ALTER TABLE tld_rules     ADD COLUMN IF NOT EXISTS fetch_strategy      TEXT`,
  `ALTER TABLE tld_rules     ADD COLUMN IF NOT EXISTS scrape_attempts     INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE tld_rules     ADD COLUMN IF NOT EXISTS manually_edited      BOOLEAN NOT NULL DEFAULT false`,
  `ALTER TABLE tld_rules     ADD COLUMN IF NOT EXISTS needs_admin_review   BOOLEAN NOT NULL DEFAULT false`,
  `ALTER TABLE payment_plans ADD COLUMN IF NOT EXISTS balance_grant_cents INTEGER NOT NULL DEFAULT 0`,
  /* Drop overly-restrictive confidence check — scraper uses high/medium/low/ai */
  `ALTER TABLE tld_rules DROP CONSTRAINT IF EXISTS tld_rules_confidence_check`,
  /* Change search_history FK from ON DELETE CASCADE → ON DELETE SET NULL.
     Previously, deleting a user wiped ALL their search records — destroying admin stats.
     With SET NULL the rows survive (user_id becomes NULL) so aggregate data is preserved. */
  `ALTER TABLE search_history DROP CONSTRAINT IF EXISTS search_history_user_id_fkey`,
  `ALTER TABLE search_history ADD CONSTRAINT  search_history_user_id_fkey
     FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL`,
  `ALTER TABLE friendly_links ADD COLUMN IF NOT EXISTS logo_url TEXT`,
  `ALTER TABLE feedback        ADD COLUMN IF NOT EXISTS handled  BOOLEAN NOT NULL DEFAULT false`,
  `ALTER TABLE feedback        ADD COLUMN IF NOT EXISTS handled_at TIMESTAMPTZ`,
  `ALTER TABLE tld_fallback_stats ADD COLUMN IF NOT EXISTS repair_status  TEXT NOT NULL DEFAULT 'pending'`,
  `ALTER TABLE tld_fallback_stats ADD COLUMN IF NOT EXISTS found_server   TEXT`,
  `ALTER TABLE tld_fallback_stats ADD COLUMN IF NOT EXISTS admin_notes    TEXT`,
  `ALTER TABLE tld_fallback_stats ADD COLUMN IF NOT EXISTS repaired_at    TIMESTAMPTZ`,
  `ALTER TABLE tld_fallback_stats ADD COLUMN IF NOT EXISTS whoiser_bypass BOOLEAN NOT NULL DEFAULT false`,
  `ALTER TABLE tld_fallback_stats ADD COLUMN IF NOT EXISTS tld_api_source TEXT`,
  `ALTER TABLE search_history   ADD COLUMN IF NOT EXISTS source          TEXT`,
  `ALTER TABLE users             ADD COLUMN IF NOT EXISTS locale          TEXT NOT NULL DEFAULT 'zh'`,
];

const CREATE_INDEXES = [
  `CREATE INDEX IF NOT EXISTS idx_users_email              ON users (email)`,
  `CREATE INDEX IF NOT EXISTS idx_users_subscription       ON users (subscription_access)`,
  `CREATE INDEX IF NOT EXISTS idx_reminders_email          ON reminders (email)`,
  `CREATE INDEX IF NOT EXISTS idx_reminders_domain         ON reminders (domain)`,
  `CREATE INDEX IF NOT EXISTS idx_stamps_email             ON stamps (email)`,
  `CREATE INDEX IF NOT EXISTS idx_stamps_domain            ON stamps (domain)`,
  `CREATE INDEX IF NOT EXISTS idx_search_history_user_id   ON search_history (user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_search_history_created   ON search_history (created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_search_history_query     ON search_history (query)`,
  `CREATE INDEX IF NOT EXISTS idx_search_history_lower_q   ON search_history (LOWER(query))`,
  `CREATE INDEX IF NOT EXISTS idx_search_history_type      ON search_history (query_type)`,
  `CREATE INDEX IF NOT EXISTS idx_search_history_regstatus ON search_history (reg_status)`,
  `CREATE INDEX IF NOT EXISTS idx_search_history_uid_q     ON search_history (user_id, LOWER(query))`,
  `CREATE INDEX IF NOT EXISTS idx_payment_orders_email     ON payment_orders (user_email)`,
  `CREATE INDEX IF NOT EXISTS idx_payment_orders_status    ON payment_orders (status)`,
  `CREATE INDEX IF NOT EXISTS idx_payment_orders_created   ON payment_orders (created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_feedback_created         ON feedback (created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_feedback_issue_type      ON feedback (issue_types)`,
  `CREATE INDEX IF NOT EXISTS idx_rate_limit_key_exp       ON rate_limit_records (key, reset_at)`,
  `CREATE INDEX IF NOT EXISTS idx_tld_rules_updated        ON tld_rules (updated_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_tld_overrides_tld        ON tld_lifecycle_overrides (tld)`,
  `CREATE INDEX IF NOT EXISTS idx_password_reset_token     ON password_reset_tokens (token)`,
  `CREATE INDEX IF NOT EXISTS idx_password_reset_user      ON password_reset_tokens (user_id)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_activation_codes_code ON activation_codes (code)`,
  `CREATE INDEX IF NOT EXISTS idx_activation_codes_used    ON activation_codes (used)`,
  `CREATE INDEX IF NOT EXISTS idx_balance_tx_user_id       ON balance_transactions (user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_balance_tx_created       ON balance_transactions (created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_changelog_entry_date     ON changelog_entries (entry_date DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_changelog_created        ON changelog_entries (created_at DESC)`,
  `CREATE TABLE IF NOT EXISTS tld_registry_info (
    tld              TEXT        PRIMARY KEY,
    tld_type         TEXT,
    status           TEXT,
    manager          TEXT,
    registry_url     TEXT,
    whois_server     TEXT,
    country          TEXT,
    address          TEXT,
    nameservers      TEXT,
    created_date     TEXT,
    changed_date     TEXT,
    iana_url         TEXT,
    probe_result     TEXT,
    probe_method     TEXT,
    probe_latency_ms INTEGER,
    probed_at        TIMESTAMPTZ,
    scan_error       TEXT,
    scraped_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_tld_registry_type    ON tld_registry_info (tld_type)`,
  `CREATE INDEX IF NOT EXISTS idx_tld_registry_status  ON tld_registry_info (status)`,
  `CREATE INDEX IF NOT EXISTS idx_tld_registry_scraped ON tld_registry_info (scraped_at DESC)`,
  `CREATE TABLE IF NOT EXISTS hot_prefixes (
    id            SERIAL       PRIMARY KEY,
    prefix        VARCHAR(100) NOT NULL,
    category      VARCHAR(50)  NOT NULL DEFAULT 'general',
    weight        INT          NOT NULL DEFAULT 10,
    source        VARCHAR(100) NOT NULL DEFAULT 'manual',
    sale_examples TEXT,
    notes         TEXT,
    enabled       BOOLEAN      NOT NULL DEFAULT true,
    hit_count     INT          NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT hot_prefixes_prefix_uniq UNIQUE (prefix)
  )`,
  `CREATE TABLE IF NOT EXISTS tld_server_failures (
    tld            TEXT         PRIMARY KEY,
    fail_count     INTEGER      NOT NULL DEFAULT 1,
    error_type     TEXT         NOT NULL DEFAULT 'iana_fallback',
    last_failed_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    repair_status  TEXT         NOT NULL DEFAULT 'pending',
    found_server   TEXT,
    ai_notes       TEXT,
    repaired_at    TIMESTAMPTZ
  )`,
  `CREATE TABLE IF NOT EXISTS whois_cache (
    key        TEXT         PRIMARY KEY,
    value      TEXT         NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_whois_cache_expires ON whois_cache (expires_at)`,
  // cctld_rdap_servers was an orphaned table — probe results were stored here but
  // never read by the live query engine. Dropped in favour of tld_fallback_stats.rdap_skip.
  `DROP TABLE IF EXISTS cctld_rdap_servers`,
  `CREATE TABLE IF NOT EXISTS email_queue (
    id            SERIAL        PRIMARY KEY,
    to_email      TEXT          NOT NULL,
    subject       TEXT          NOT NULL,
    html          TEXT          NOT NULL,
    status        TEXT          NOT NULL DEFAULT 'pending',
    attempts      INTEGER       NOT NULL DEFAULT 0,
    max_attempts  INTEGER       NOT NULL DEFAULT 5,
    next_retry_at TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_error    TEXT,
    created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    sent_at       TIMESTAMPTZ
  )`,
  `CREATE INDEX IF NOT EXISTS idx_email_queue_pending ON email_queue (next_retry_at, created_at) WHERE status = 'pending'`,
  `CREATE TABLE IF NOT EXISTS query_logs (
    id          BIGSERIAL    PRIMARY KEY,
    domain      TEXT         NOT NULL,
    tld         TEXT         NOT NULL DEFAULT '',
    success     BOOLEAN      NOT NULL,
    cached      BOOLEAN      NOT NULL DEFAULT false,
    duration_ms INTEGER      NOT NULL DEFAULT 0,
    error_code  TEXT,
    source      TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_query_logs_created ON query_logs (created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_query_logs_tld     ON query_logs (tld)`,
  `CREATE INDEX IF NOT EXISTS idx_query_logs_success ON query_logs (success)`,
  `CREATE TABLE IF NOT EXISTS expired_domain_leads (
    id            SERIAL       PRIMARY KEY,
    domain        TEXT         NOT NULL UNIQUE,
    tld           TEXT         NOT NULL DEFAULT '',
    sld           TEXT         NOT NULL DEFAULT '',
    char_count    INT          NOT NULL DEFAULT 0,
    bl            INT,
    dp            INT,
    deleted_date  TEXT,
    available_date TEXT,
    status        TEXT         NOT NULL DEFAULT 'available',
    source        TEXT         NOT NULL DEFAULT 'expireddomains.net',
    seen          BOOLEAN      NOT NULL DEFAULT false,
    starred       BOOLEAN      NOT NULL DEFAULT false,
    notes         TEXT,
    crawled_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_expired_domain_leads_char    ON expired_domain_leads (char_count)`,
  `CREATE INDEX IF NOT EXISTS idx_expired_domain_leads_tld     ON expired_domain_leads (tld)`,
  `CREATE INDEX IF NOT EXISTS idx_expired_domain_leads_crawled ON expired_domain_leads (crawled_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_expired_domain_leads_bl      ON expired_domain_leads (bl DESC NULLS LAST)`,
  `CREATE INDEX IF NOT EXISTS idx_expired_domain_leads_sld     ON expired_domain_leads (sld text_pattern_ops)`,
  `CREATE INDEX IF NOT EXISTS idx_expired_domain_leads_starred ON expired_domain_leads (starred) WHERE starred = true`,
  `CREATE INDEX IF NOT EXISTS idx_expired_domain_leads_unseen  ON expired_domain_leads (seen) WHERE seen = false`,
];

/**
 * Auto-derive a Supabase Transaction Mode URL (port 6543) from a Session Mode URL (port 5432).
 * Transaction mode allows far more concurrent connections — critical on Vercel serverless.
 * Returns null if the URL is not a Supabase pooler URL or already uses a non-session port.
 */
function deriveTransactionModeUrl(sessionUrl: string): string | null {
  try {
    const u = new URL(sessionUrl);
    if (!u.hostname.includes(".pooler.supabase.com")) return null;
    if (u.port !== "5432") return null; // already not session mode
    u.port = "6543";
    return u.toString();
  } catch {
    return null;
  }
}

function getConnectionString(): { url: string; source: string } | null {
  // 1. Explicit POSTGRES_URL — only use if it's on the correct region/host.
  //    Check that it matches the NON_POOLING host (same Supabase project).
  const explicitUrl = process.env.POSTGRES_URL;
  const nonPoolingUrl = process.env.POSTGRES_URL_NON_POOLING;
  if (explicitUrl && nonPoolingUrl) {
    try {
      const eu = new URL(explicitUrl);
      const nu = new URL(nonPoolingUrl);
      if (eu.hostname === nu.hostname) {
        return { url: explicitUrl, source: "POSTGRES_URL" };
      }
      // Hosts differ — fall through to auto-derive from NON_POOLING
    } catch { /* fall through */ }
  } else if (explicitUrl && !nonPoolingUrl) {
    return { url: explicitUrl, source: "POSTGRES_URL" };
  }

  // 2. Auto-derive Transaction Mode URL from POSTGRES_URL_NON_POOLING (port 5432 → 6543).
  //    Same credentials, same host, just switches connection pooling mode.
  if (nonPoolingUrl) {
    const txUrl = deriveTransactionModeUrl(nonPoolingUrl);
    if (txUrl) {
      return { url: txUrl, source: "POSTGRES_URL_NON_POOLING→TX" };
    }
    return { url: nonPoolingUrl, source: "POSTGRES_URL_NON_POOLING" };
  }

  if (process.env.SUPABASE_DATABASE_URL) {
    const txUrl = deriveTransactionModeUrl(process.env.SUPABASE_DATABASE_URL);
    if (txUrl) return { url: txUrl, source: "SUPABASE_DATABASE_URL→TX" };
    return { url: process.env.SUPABASE_DATABASE_URL, source: "SUPABASE_DATABASE_URL" };
  }
  if (process.env.DATABASE_URL) {
    const txUrl = deriveTransactionModeUrl(process.env.DATABASE_URL);
    if (txUrl) return { url: txUrl, source: "DATABASE_URL→TX" };
    return { url: process.env.DATABASE_URL, source: "DATABASE_URL" };
  }
  return null;
}

export function getConnectionHost(): string {
  const cs = getConnectionString();
  if (!cs) return "none";
  try {
    const u = new URL(cs.url);
    return `${u.hostname}:${u.port || 5432}`;
  } catch {
    return "unknown";
  }
}

export function getConnectionSource(): string {
  return getConnectionString()?.source ?? "none";
}

function stripSslMode(url: string): string {
  try {
    const u = new URL(url);
    u.searchParams.delete("sslmode");
    return u.toString();
  } catch {
    return url;
  }
}

function makePool(connectionString: string): Pool {
  const cleanUrl = stripSslMode(connectionString);
  // Disable SSL for local/internal hosts (e.g. Replit's internal "helium" Postgres).
  // External cloud databases (Supabase, Neon, etc.) still get SSL with self-signed cert support.
  let sslConfig: boolean | { rejectUnauthorized: boolean };
  try {
    const u = new URL(cleanUrl);
    const h = u.hostname;
    const isInternal = h === "localhost" || h === "127.0.0.1" || h === "helium" || !h.includes(".");
    sslConfig = isInternal ? false : { rejectUnauthorized: false };
  } catch {
    sslConfig = { rejectUnauthorized: false };
  }
  // On Vercel/Lambda each function instance is short-lived and isolated — keep
  // the pool very small to avoid exhausting Supabase connection limits.
  // On long-running servers a slightly larger pool improves throughput.
  const isServerless = !!(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);
  const maxConns = isServerless ? 2 : parseInt(process.env.PG_MAX_CONNECTIONS || "5");
  const p = new Pool({
    connectionString: cleanUrl,
    ssl: sslConfig,
    application_name: "next-whois-ui",
    max: maxConns,
    min: 0,
    connectionTimeoutMillis: 8_000,
    idleTimeoutMillis: 10_000,
    allowExitOnIdle: true,
    keepAlive: !isServerless,
    keepAliveInitialDelayMillis: 20_000,
    query_timeout: 25_000,
    statement_timeout: 25_000,
  } as any);
  p.on("error", (err) => console.error("[db] pool error:", err.message));
  return p;
}

export function getDb(): Pool | null {
  const existing = getPool();
  if (existing) return existing;
  const cs = getConnectionString();
  if (!cs) {
    console.error("[db] No PostgreSQL connection URL found. Set POSTGRES_URL_NON_POOLING as a secret.");
    return null;
  }
  console.log(`[db] Connecting via ${cs.source} → ${getConnectionHost()}`);
  const p = makePool(cs.url);
  setPool(p);
  setMigrated(false);
  return p;
}

export async function runMigrations(db: Pool): Promise<void> {
  const client = await db.connect();
  try {
    // Batch 1: all CREATE TABLE statements in a single round-trip.
    // pg uses simple query protocol (no parameters) → multi-statement is supported.
    await client.query(CREATE_TABLES.join(";\n") + ";");

    // Batch 2: all ALTER COLUMN/TABLE statements wrapped in a single DO block.
    // Errors (e.g. column already exists) are silently swallowed per-statement.
    const alterBlock =
      `DO $$\nBEGIN\n` +
      ALTER_COLUMNS.map(
        (s) => `  BEGIN\n    ${s};\n  EXCEPTION WHEN OTHERS THEN NULL;\n  END;`,
      ).join("\n") +
      `\nEND $$`;
    await client.query(alterBlock);

    // Batch 3: all CREATE INDEX IF NOT EXISTS in a single DO block.
    // Each is individually exception-protected so a bad index definition
    // (e.g., referencing a non-existent column) won't abort the rest.
    const indexBlock =
      `DO $$\nBEGIN\n` +
      CREATE_INDEXES.map(
        (s) => `  BEGIN\n    ${s};\n  EXCEPTION WHEN OTHERS THEN NULL;\n  END;`,
      ).join("\n") +
      `\nEND $$`;
    await client.query(indexBlock);

    console.log("[db] Schema ready");
  } finally {
    client.release();
  }
}

export async function getDbReady(): Promise<Pool | null> {
  const db = getDb();
  if (!db) return null;
  if (getMigrated()) return db;

  // SKIP_AUTO_MIGRATE=1 lets production instances (where all tables already exist)
  // skip the 3-batch DDL migration queries on every cold start, saving ~200-400ms.
  // Safe to set on Vercel once the Supabase schema is fully provisioned.
  if (process.env.SKIP_AUTO_MIGRATE === "1" || process.env.SKIP_AUTO_MIGRATE === "true") {
    setMigrated(true);
    return db;
  }

  if (global.__pgMigrating) {
    try {
      await global.__pgMigrating;
    } catch {
      return null;
    }
    return getMigrated() ? db : null;
  }

  const migrationPromise = runMigrations(db)
    .then(() => { setMigrated(true); })
    .catch((err: unknown) => {
      console.error("[db] Migration failed:", err instanceof Error ? err.message : String(err));
    })
    .finally(() => { global.__pgMigrating = undefined; });

  global.__pgMigrating = migrationPromise;

  try {
    await migrationPromise;
  } catch {
    return null;
  }
  return getMigrated() ? db : null;
}

/**
 * Log an individual query event (success or failure) for the admin observability dashboard.
 * Fire-and-forget — never throws, never blocks the main query path.
 * Automatically prunes records older than 30 days to cap table growth.
 */
export async function logQuery(entry: {
  domain: string;
  tld: string;
  success: boolean;
  cached: boolean;
  durationMs: number;
  errorCode?: string | null;
  source?: string | null;
}): Promise<void> {
  const db = await getDbReady().catch(() => null);
  if (!db) return;
  const client = await db.connect().catch(() => null);
  if (!client) return;
  try {
    await client.query(
      `INSERT INTO query_logs (domain, tld, success, cached, duration_ms, error_code, source)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        entry.domain.slice(0, 253),
        entry.tld.slice(0, 63),
        entry.success,
        entry.cached,
        Math.round(entry.durationMs),
        entry.errorCode ?? null,
        entry.source ?? null,
      ],
    );
    // Prune old records: keep only the last 30 days (runs occasionally, non-blocking)
    await client.query(
      `DELETE FROM query_logs WHERE created_at < NOW() - INTERVAL '30 days'`,
    );
  } catch {
    // Silently ignore — never disrupt the query path
  } finally {
    client.release();
  }
}

// ── Per-TLD third-party API source ────────────────────────────────────────────

/**
 * In-process cache so every WHOIS lookup doesn't hit the DB.
 * Keys are normalised TLDs (no dot). Populated on first miss, cleared on write.
 */
const _tldApiSourceCache = new Map<string, { src: string | null; at: number }>();
const TLD_API_CACHE_TTL = 120_000; // 2 minutes

export async function getTldApiSource(tld: string): Promise<string | null> {
  const key = tld.toLowerCase().replace(/^\./, "");
  const cached = _tldApiSourceCache.get(key);
  if (cached && Date.now() - cached.at < TLD_API_CACHE_TTL) return cached.src;
  const db = await getDbReady().catch(() => null);
  if (!db) return null;
  const client = await db.connect().catch(() => null);
  if (!client) return null;
  try {
    const r = await client.query(
      "SELECT tld_api_source FROM tld_fallback_stats WHERE tld = $1",
      [key],
    );
    const src = (r.rows[0]?.tld_api_source as string | null) ?? null;
    _tldApiSourceCache.set(key, { src, at: Date.now() });
    return src;
  } catch {
    return null;
  } finally {
    client.release();
  }
}

export async function setTldApiSource(tld: string, source: string | null): Promise<void> {
  const key = tld.toLowerCase().replace(/^\./, "");
  _tldApiSourceCache.delete(key);
  const db = await getDbReady().catch(() => null);
  if (!db) return;
  const client = await db.connect().catch(() => null);
  if (!client) return;
  try {
    await client.query(
      `INSERT INTO tld_fallback_stats (tld, fail_count, last_fail_at, tld_api_source)
       VALUES ($1, 0, NOW(), $2)
       ON CONFLICT (tld) DO UPDATE SET tld_api_source = $2`,
      [key, source],
    );
  } finally {
    client.release();
  }
}

/**
 * Delete a TLD's failure stats row.  Called after a successful third-party
 * API lookup proves the TLD can be handled — the row no longer needs to appear
 * in the admin failures list.
 * Fire-and-forget — never throws.
 */
export async function clearTldFailureStats(tld: string): Promise<void> {
  const key = tld.toLowerCase().replace(/^\./, "");
  const db = await getDbReady().catch(() => null);
  if (!db) return;
  const client = await db.connect().catch(() => null);
  if (!client) return;
  try {
    // When a tld_api_source is configured, preserve the row (and the config)
    // but reset fail_count to 0 so the TLD disappears from the failures list.
    // Only hard-delete rows that have no third-party override — those are pure
    // failure records with nothing worth keeping.
    await client.query(
      `UPDATE tld_fallback_stats
         SET fail_count = 0, repair_status = 'fixed', repaired_at = NOW()
       WHERE tld = $1 AND tld_api_source IS NOT NULL`,
      [key],
    );
    await client.query(
      `DELETE FROM tld_fallback_stats
       WHERE tld = $1 AND tld_api_source IS NULL`,
      [key],
    );
    // Clear the in-memory cache so any subsequent getTldApiSource() call reads
    // fresh data instead of returning a stale value from a now-deleted row.
    _tldApiSourceCache.delete(key);
  } catch {
    // Silently ignore
  } finally {
    client.release();
  }
}

/**
 * Record a TLD lookup failure for admin review.
 * Fire-and-forget — never throws, never blocks the main query path.
 */
export async function recordTldLookupFailure(
  tld: string,
  reason: "no_server" | "timeout" | "parse_error" | "rate_limited" | "iana_fallback",
  domain: string,
  errorMsg?: string,
): Promise<void> {
  // Skip recording for obviously invalid TLDs:
  // - too short or too long (IANA TLDs are at most 24 chars)
  // - doesn't start with a letter
  // - purely numeric
  // - contains a dot (means it's a full domain label, not a TLD suffix)
  if (!tld || tld.length < 2 || tld.length > 24) return;
  if (!/^[a-zA-Z]/.test(tld) || /^\d+$/.test(tld) || tld.includes(".")) return;
  const db = await getDbReady().catch(() => null);
  if (!db) return;
  const client = await db.connect().catch(() => null);
  if (!client) return;
  try {
    await client.query(
      `INSERT INTO tld_fallback_stats (tld, fail_count, last_fail_at, fail_reason, last_domain, sample_error)
       VALUES ($1, 1, NOW(), $2, $3, $4)
       ON CONFLICT (tld) DO UPDATE SET
         fail_count   = tld_fallback_stats.fail_count + 1,
         last_fail_at = NOW(),
         fail_reason  = $2,
         last_domain  = $3,
         sample_error = COALESCE($4, tld_fallback_stats.sample_error)`,
      [tld, reason, domain, errorMsg ? errorMsg.slice(0, 200) : null],
    );
  } catch {
    // Silently ignore — never disrupt the query path
  } finally {
    client.release();
  }
}
