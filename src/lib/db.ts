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
  `ALTER TABLE tld_fallback_stats ADD COLUMN IF NOT EXISTS rdap_skip BOOLEAN NOT NULL DEFAULT false`,
  `CREATE TABLE IF NOT EXISTS custom_whois_servers (
    tld        TEXT         PRIMARY KEY,
    entry      JSONB        NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS rate_limit_records (
    key        TEXT         PRIMARY KEY,
    count      INTEGER      NOT NULL DEFAULT 0,
    reset_at   TIMESTAMPTZ  NOT NULL
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
  `ALTER TABLE users         ADD COLUMN IF NOT EXISTS balance_cents       INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE users         ADD COLUMN IF NOT EXISTS membership_plan     TEXT`,
  `ALTER TABLE tld_rules     ADD COLUMN IF NOT EXISTS model_used          TEXT`,
  `ALTER TABLE tld_rules     ADD COLUMN IF NOT EXISTS scrape_status       TEXT    NOT NULL DEFAULT 'pending'`,
  `ALTER TABLE tld_rules     ADD COLUMN IF NOT EXISTS failure_reason      TEXT`,
  `ALTER TABLE tld_rules     ADD COLUMN IF NOT EXISTS fetch_strategy      TEXT`,
  `ALTER TABLE tld_rules     ADD COLUMN IF NOT EXISTS scrape_attempts     INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE tld_rules     ADD COLUMN IF NOT EXISTS manually_edited     BOOLEAN NOT NULL DEFAULT false`,
  `ALTER TABLE payment_plans ADD COLUMN IF NOT EXISTS balance_grant_cents INTEGER NOT NULL DEFAULT 0`,
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
];

function getConnectionString(): { url: string; source: string } | null {
  if (process.env.POSTGRES_URL) {
    return { url: process.env.POSTGRES_URL, source: "POSTGRES_URL" };
  }
  if (process.env.POSTGRES_URL_NON_POOLING) {
    return { url: process.env.POSTGRES_URL_NON_POOLING, source: "POSTGRES_URL_NON_POOLING" };
  }
  if (process.env.SUPABASE_DATABASE_URL) {
    return { url: process.env.SUPABASE_DATABASE_URL, source: "SUPABASE_DATABASE_URL" };
  }
  if (process.env.DATABASE_URL) {
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
  const p = new Pool({
    connectionString: cleanUrl,
    ssl: { rejectUnauthorized: false },
    max: 10,
    connectionTimeoutMillis: 8000,
    idleTimeoutMillis: 30000,
    allowExitOnIdle: true,
  });
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

  if (global.__pgMigrating) {
    await global.__pgMigrating;
    return db;
  }

  global.__pgMigrating = runMigrations(db).then(() => {
    setMigrated(true);
    global.__pgMigrating = undefined;
  });

  await global.__pgMigrating;
  return db;
}
