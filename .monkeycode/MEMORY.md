# User Instruction Memory

This file records user instructions, preferences, and teachings for reference in future interactions.

## Format

### User Instruction Entry
User instruction entries should follow this format:

[User Instruction Summary]
- Date: [YYYY-MM-DD]
- Context: [Mentioned scenario or time]
- Instructions:
  - [Content of user teaching or instruction, described line by line]

### Project Knowledge Entry
Entries discovered by the Agent during task execution should follow this format:

[Project Knowledge Summary]
- Date: [YYYY-MM-DD]
- Context: Discovered by Agent while performing [specific task description]
- Category: [Operations & Deployment|Build Methods|Testing Methods|Troubleshooting & Debugging|Workflow & Collaboration|Environment Configuration]
- Instructions:
  - [Specific knowledge points, described line by line]

## Deduplication Strategy
- Before adding a new entry, check for similar or identical instructions.
- If a duplicate is found, skip the new entry or merge it with the existing one.
- When merging, update the context or date information.
- This helps avoid redundant entries and keeps the memory file tidy.

## Entries

[Project Knowledge Summary]
- Date: 2026-09-03
- Context: Discovered while connecting the project's Supabase database for the user
- Category: Operations & Deployment
- Instructions:
  - Database is Supabase, project ref rdhwkrlnlceibzjmjipj, located in aws-0-us-east-1
  - IPv4-only environments must connect via pooler: host aws-0-us-east-1.pooler.supabase.com port 6543, user postgres.rdhwkrlnlceibzjmjipj, sslmode=require
  - Direct host db.rdhwkrlnlceibzjmjipj.supabase.co resolves IPv6 only and is unreachable from this environment
  - All credentials live in /workspace/.env.local (gitignored, do not commit); secret key is mapped to SUPABASE_SERVICE_ROLE_KEY for supabase.ts compatibility
  - Verify DB connectivity: PGPASSWORD=... psql "host=aws-0-us-east-1.pooler.supabase.com port=6543 dbname=postgres user=postgres.rdhwkrlnlceibzjmjipj sslmode=require" -c "SELECT 1"
  - GitHub: token and repo in /workspace/.env.local as GITHUB_TOKEN / GITHUB_REPO; account hellouy, repo hellouy/next-whois (public, push verified); used by /api/admin/git-force-push
  - DB migration history: old live DB is zyhyufxaccjvmkbyivxz (aws-1-ap-southeast-2, password differs from new one); new DB rdhwkrlnlceibzjmjipj (aws-0-us-east-1) received full data via pg_dump 17 (apt pgdg repo) in FK topological batches (users/reminders/payment_plans -> payment_orders -> rest); old schema has 7 extra columns, added via ALTER before import
  - db.ts getConnectionString ignores POSTGRES_URL when POSTGRES_URL_NON_POOLING host differs; it derives pooler URL from NON_POOLING - so switching projects requires updating NON_POOLING on Vercel, not just POSTGRES_URL
  - On new-DB pooler connections, unqualified table names fail to resolve (search_path lacks public); always use public.xxx qualified names; pg_dump files import fine because they qualify everything

[Project Knowledge Summary]
- Date: 2026-09-03
- Context: Cutover of the WHOIS site from old Vercel account/old Supabase to new Vercel project + migrated Supabase
- Category: Operations & Deployment
- Instructions:
  - Two Vercel projects named next-whois: OLD prj_iUBe5v2wht9SYe1SuFKyj0vM (team_jwt3T9B3Dg8JLPoGEjauWPRr, token vcp_4IedJ...) hosting next-whois-zeta.vercel.app; NEW prj_mSlRPkhsU4hqYkJguqkciD79OOA4 (team_9YLetB6pJfH8UNY4rHVwN0cg, token in .env.local) hosting next-whois-c540usss4-teifan-8447s-projects.vercel.app, both linked to github hellouy/next-wohis main
  - vcp_ tokens are project tokens: /v2/user returns "User not found", but project-level env/deployment APIs work; teamId param not needed
  - Sandbox DNS poisons *.vercel.app (returns Meta/Twitter IPs); bypass via curl --resolve with anycast IPs 216.198.79.131 or 64.29.17.131
  - Supabase Vercel-integration default POSTGRES_URL_NON_POOLING points to db.xxx.supabase.co (IPv6-only) which silently kills DB in IPv4-only Vercel; fix is PATCHing it (and POSTGRES_URL) to aws-0-us-east-1.pooler.supabase.com host (5432 session / 6543 transaction)
  - New project env completed: pooler connection strings, NEXTAUTH_SECRET (fresh), NEXTAUTH_URL, ADMIN_EMAIL=9208522@qq.com, CRON_SECRET, NEXT_PUBLIC_BASE_URL, SKIP_AUTO_MIGRATE=1; Redis/KV vars not migrated yet (L2 cache absent on new site)
  - logQuery is fire-and-forget in Vercel Functions: logs are dropped when the lambda freezes right after response; some query_logs rows land probabilistically - this is expected behavior, not a config issue
  - New site ssoProtection had to be disabled via PATCH /v9/projects/{id} {"ssoProtection": null} before public access worked

[Project Knowledge Summary]
- Date: 2026-09-03
- Context: Security hotfix deployment (5 high-risk fixes) to the new Vercel project
- Category: Operations & Deployment
- Instructions:
  - Deploy flow verified: git push to github hellouy/next-whois main (token from .env.local) auto-triggers production build on the new Vercel project; poll GET /v6/deployments?projectId=...&limit=1&target=production until readyState=READY
  - Security fixes live in commit 5570d6b: NextAuth jwt email escalation, PayPal webhook 503-when-unconfigured, same-origin rate-limit exemption removed on all three lookup endpoints, admin login hardening, lookup-stream auth-before-lookup; access-key.ts same-origin key exemption intentionally KEPT (site UI never sends a key; rate limit + require_login are the abuse ceiling)
  - In-memory rate limiting is per-lambda-instance: a burst may get 6-7 successes before 429 even with limit=5; the 429 itself proves enforcement, exact boundary varies with instance routing
  - Live verification recipe: curl --resolve SITE:443:216.198.79.131 with spoofed Origin header; batch endpoint (anon limit 5/min) shows 429; /api/lookup without Origin returns 401 when require_api_key=1; paypal webhook POST {} returns 503 Webhook not configured

[Project Knowledge Summary]
- Date: 2026-09-03
- Context: Restructure /tlds public page into queryable / non-queryable suffix lists; fix inaccurate hasWhois/hasRdap
- Category: Troubleshooting & Debugging
- Instructions:
  - Product decision (user confirmed): "支持查询" = suffix has ANY known WHOIS and/or RDAP path (offline-deterministic); custom WHOIS server CRUD (previously in /tlds "WHOIS 服务器" tab) moved entirely to new admin page /admin/whois-servers
  - /tlds now shows: Tab1 支持查询后缀 (queryable, default) + Tab2 不支持查询后缀; top stat cards show supported/unsupported totals from /api/iana-tlds supportedCount/unsupportedCount
  - iana-tlds.ts hasWhois source union: runtime serverMap (tld_registry_info.whois_server + BUILTIN scrapers + custom DB) OR getStaticWhoisServer(tld) (whois-servers.json strings + GTLD_WHOIS_BOOTSTRAP, 1200 entries). hasRdap union: CCTLD_RDAP_OVERRIDES (rdap_client.ts) ∪ GTLD_RDAP_BOOTSTRAP ∪ live IANA dns.json. Cache key bumped to iana_tlds:v3
  - Prior inaccuracy: gTLD WHOIS badges were almost all false (gTLD bootstrap not merged) and hasRdap was live-IANA-only (fetch failure => all false)
  - Static IANA 1436 baseline with current data: ~1373 queryable / ~63 unsupported (mostly xn-- IDN ccTLDs without public WHOIS/RDAP + ccTLDs like al ao bv sj va etc. explicitly nulled in whois-servers.json). tld_registry_info currently has no whois_server values on the live DB; custom_whois_servers has 17
  - TldCard type label shows IDN for xn--* instead of mislabeled gTLD
  - Admin nav config group gained /admin/whois-servers ("WHOIS 服务器管理"); locale keys admin.nav_whois_servers added in en/zh/zh-tw; navbar /tlds label/desc renamed across all 8 locale files to "TLD 支持/queryable-not" semantics
  - Admin panel content pages (e.g. server-test, whois-servers) use Chinese-literal copy, not t() keys; only nav/layout strings use locale json

  - Root cause of undercounted stats: saveSearchRecord/logQuery were fire-and-forget after res.json()/res.end() — Vercel freezes the lambda right after the response and drops pending DB writes. Fix pattern: AWAIT every stats write BEFORE the response ends (done in lookup, lookup-stream, lookup-batch, commit c75c1fc)
  - /api/lookup-batch previously logged nothing at all; it now writes query_logs + search_history per item with caller identity
  - query_logs gained user_id/user_email/ip columns (schema in db.ts CREATE_TABLES+ALTER_COLUMNS+CREATE_INDEXES, plus manual ALTER on live DB because SKIP_AUTO_MIGRATE=1 on Vercel); legacy rows have NULL identity and count as anonymous
  - logQuery 30-day prune now runs on ~1% of inserts (was: full-table DELETE on every insert — too slow to await)
  - search_history only records SUCCESSFUL lookups (failures go to query_logs only) — empty search_history after a failed-domain test is expected behavior

[Project Knowledge Summary]
- Date: 2026-09-03
- Context: .gw web WHOIS integration fix (registar.nic.gw) after "Empty WHOIS response" on Vercel
- Category: Troubleshooting & Debugging
- Instructions:
  - "Empty WHOIS response" from lookup API with fast-fail (~1.6s) usually means the fetch SUCCEEDED but the generic parser found zero recognizable fields — debug with a temporary console.log of raw length in whois-generic.ts builtin step, NOT by blaming Vercel egress
  - To distinguish Vercel-egress vs code bug: run local dev server (npx next dev -p 3777, background terminal with timeout 0 — 10min timeout kills mid-test), curl /api/lookup with spoofed Origin header http://localhost:3777 (API key required otherwise, same-origin is exempt)
  - Non-standard registry pages (fieldset/label two-line layout, no "Key: value" lines) MUST use a dedicated scraper in src/lib/whois/http-scrapers/ (pattern: nic-ba/nic-ph/nic-gw) emitting normalized keys (Domain Name/Creation Date/Registry Expiry Date/Status/Registrar/Registrant ...) + ISO dates; generic http entries only work for "Key: value" text pages
  - Scraper integration recipe: ScraperEntry { type:"scraper", name, registryUrl } in BUILTIN_SERVERS + dispatch in executeServerEntry (custom-servers.ts) + iana-tlds.ts detects scrapers via .name property (NOT .scraper — that was a bug)
  - registar.nic.gw specifics: 404 = unregistered (WordPress), dates DD/MM/YYYY need toIsoDate, values are text nodes or <a> after <label>, Technical Contact is "Confidential"; Vercel egress is NOT blocked by this registry
  - Deploy: commit e4ed40c; live verified nic.gw full fields, unregistered .gw → DNS probe unregistered/medium; /tlds 1376/1438 supported

[Project Knowledge Summary]
- Date: 2026-09-03
- Context: .sn lookup misreported as error + infinite loading on same-domain re-search
- Category: Troubleshooting & Debugging
- Instructions:
  - detectWhoisError (whois-patterns.ts) MUST scan %/# comment lines for not-found markers as a fallback after content lines: some registries (whois.nic.sn = "%% NOT FOUND") report the empty state ONLY in RFC 3912 comments while the payload is a legal disclaimer
  - Symptom of that bug: "Empty WHOIS response" error + dnsProbe unregistered/medium instead of authoritative unregistered/high
  - Infinite loading skeleton root cause: [...query].tsx handleSearch shallow-pushes variant URLs (case/protocol/www) that cleanDomain-normalize to the SAME target; routeChangeStart sets loading but the [target, refreshKey] fetch effect never re-fires. Fixed by same-target re-query (refreshKey+1) + sync-effect loading safety net
  - Reproduce lookup-layer bugs locally via curl /api/lookup with Origin header; browser-only state bugs need code reading — SSE endpoint always res.end()s in finally
  - common_parser.ts switch already has partial French keys (date de création, date d'expiration, nom de domaine); added serveur de noms / statut / dernière modification for .sn registered output
  - RDAP and WHOIS run in parallel with grace windows (lookup.ts ~826-870): a dead/伪 RDAP ccTLD override costs nothing when WHOIS wins the race — no need to remove
  - .ci/.bj report not-found in content lines (already worked); comment-style markers verified only for .sn so far
  - Deploy: commit 045e313; live verified hello.sn unregistered/high, nic.sn full fields (NS x5)

[Project Knowledge Summary]
- Date: 2026-09-03
- Context: multilingual ccTLD WHOIS parsing + unhandledRejection / .tg TCP / JPRS / DNS-LU banner fixes (commits 6b62118, 0fd292a)
- Category: Troubleshooting & Debugging
- Instructions:
  - Node fires unhandledRejection the tick a promise rejects with zero attached handlers; handlers attached 100ms+ later (after an await) are TOO LATE. Any promise created before a slow await (rdapPromise at lookup.ts:720 before queryManualServerRacing) needs an immediate no-op `.catch(()=>{})` at the creation site
  - queryWhoisTcp must NOT call socket.end() after write — JWhoisServer (.tg) discards the query on FIN and returns zero bytes; standard WHOIS flow is write query, server responds and closes (whoiser never half-closes). Timeout handler should resolve accumulated data when non-empty
  - whoiser appends `/e` to .jp queries (English JPRS output: [Registrant]/[Created on]/[Expires on]); the static-map TCP path queries WITHOUT /e so the race alternates between Japanese and English raw — common_parser needs BOTH key sets (登録者名 and [Name])
  - common_parser lines are pre-trimmed before the loop — indentation-based continuation detection is impossible; use "no bracket + no colon" line test instead (JPRS [Postal Address] multi-line)
  - DNS-LU (whois.dns.lu) returns the FULL policy banner with zero data lines to Vercel egress (works from residential IPs): isPolicyBannerOnly() detects it, lookup.ts fails with an explanatory message + registryWebUrl map links the captcha-gated web WHOIS at dns.lu/en/domaines/whois-web; the /en/domains/availability form (no captcha, Drupal form_build_id 2-step POST, input expects SLD only — it appends .lu itself) gives registered/unregistered only
  - .tg JWhoisServer redacts contacts with [PRIVEE] — isRedactedValue filters it; sandbox DNS to ccTLD WHOIS hosts is intermittently broken (getent vs node resolve4 can differ) — retest before blaming code
  - Transient WHOIS failures poison failure stats: whoiser bypass (only suppresses whoiser call, static TCP always runs) + tld_failure_stats; both self-heal via resetWhoiserFailureCounter/clearTldFailureStats on the next success
  - Vercel deploy list API: j.deployments[0].meta.githubCommitSha identifies the live commit — verify BEFORE online testing; alias traffic switch lags READY by ~20s
  - Bench: esbuild bundle common_parser (alias @=./src) over raw samples in /tmp/opencode/samples{,2}; multilingual cases lifted bo 2→6/11, fi 4→10, jp 3→9, sn 7→10, th 6→10; dot-padded keys (.fi/.no/.kz/.tn) fixed by key.replace(/\.+$/,"") after split(":")

[Project Knowledge Summary]
- Date: 2026-09-04
- Context: full admin panel audit (30 pages) — bug fixes, mobile adaptation (commit 01a4250)
- Category: Troubleshooting & Debugging
- Instructions:
  - Admin pages render client-side behind next-auth; curl-based E2E can only verify compilation (200/307) — functional bugs need code review; use 3 parallel explore agents over pages/admin/*.tsx for audits
  - Common admin-page failure modes found: fetch to nonexistent API route (always 404), success toast without checking res.ok (false success), toast inside state updater (fires twice under reactStrictMode), setTimeout closure over stale state, opacity-0 group-hover buttons invisible on touchscreens (fix: opacity-100 sm:opacity-0), grid-cols-N without sm: fallback
  - Admin i18n is a known catalog-wide gap: all 30 pages hardcode Simplified Chinese while frontend uses useTranslation — deliberate scope decision, not a bug
  - No ESLint config in project (next lint enters interactive setup); rely on npx tsc --noEmit + dev-server compile + curl sweep for verification
  - Dev server (port 3777) compiles pages on first curl; check /tmp/terminal_term_*.log for compile errors after edits

[Project Knowledge Summary]
- Date: 2026-09-04
- Context: frontend 8-locale i18n completion + tlds/links/index migration (commits 0d64605, c838762)
- Category: Build Methods
- Instructions:
  - i18n key parity checker: /tmp/opencode/parity.cjs (flatten locales/*.json, diff vs en; 1782-key baseline)
  - Locale is NOT path-based: /ja/foo 308-redirects to /foo; locale comes from NEXT_LOCALE cookie (cookie > navigator.language > en, src/lib/locale-context.tsx); verify SSR translations with curl -H "Cookie: NEXT_LOCALE=xx"
  - Rendering modes decide curl behavior: pages WITH getStaticProps+revalidate (index.tsx) are ISR — curl shows stale first frame, not a bug; pages without are per-request SSR via _app.getInitialProps
  - locale JSON format: 2-space indent + trailing newline; batch edits via node scripts with JSON.stringify(j,null,2)
  - t() supports {{var}} interpolation; React.memo cards call useTranslation internally (passing t as prop breaks memo)
  - Client-only states (useEffect-filled) can't be verified via curl SSR; static keys are the curl-verifiable proxy
  - index.tsx SEO: DB settings values win over locale fallbacks; SEO_FALLBACKS only replaces exact Chinese DEFAULT_* strings

[Project Knowledge Summary]
- Date: 2026-09-04
- Context: full-site audit fix batch P0-P3 (commits ebb2188, 9fca731, 12066d4, 001bb53) deploy + live verification
- Category: Operations & Deployment
- Instructions:
  - Vercel Hobby rejects sub-daily cron expressions at deployment CREATION, and that rejection silently kills the git-webhook deploy (no deployment ever appears); keep vercel.json crons daily — for 15-min email-queue drain use an external scheduler GETting /api/admin/process-email-queue with Authorization: Bearer <CRON_SECRET> (endpoint accepts it, verified 200)
  - next build regenerates public/sw.js + swaps the workbox-*.js hash (next-pwa artifacts, tracked since initial upload): git checkout both before committing; Vercel rebuilds them per deploy
  - Vercel deployments API embeds raw control chars in githubCommitMessage — node JSON.parse fails; sanitize with .replace(/[\x00-\x1f]+/g," ") before parsing; compare FULL sha
  - Vercel edge serves cached responses with rewritten cache-control (just "public"): judge edge caching by x-vercel-cache MISS->HIT + age headers, not the cache-control string
  - pnpm 10+ writes pnpm-workspace.yaml allowBuilds placeholder ("set this to true or false") when build scripts are ignored — set it explicitly before committing
  - Query-page result cards are client-rendered (curl SSR shows skeleton only): confirm new client code shipped by grepping the deployed [...query] chunk for its string constants
  - Long-running dev server + dep removal pitfall: stale nested node_modules paths (e.g. @radix-ui/react-dialog/node_modules/react-slot) break hot recompile with ENOENT while pnpm install says "already up to date" — restart the dev terminal, store links are fine
  - SSRF guard is shared in src/lib/ssrf-guard.ts (http/check + ssl/cert import isBlockedHost): never anchor prefix alternations inside ^(a|b)$ — "127\." only matched the literal "127." and 127.0.0.1 passed; remember WHATWG URL canonicalizes integer hosts (http://2130706433 -> hostname "127.0.0.1")
  - Zero-side-effect rate-limit test: POST {} 4x — rate limit runs before body validation, so 400,400,400,429 proves enforcement

[Project Knowledge Summary]
- Date: 2026-09-04
- Context: audit leftovers execution — Sentry wiring, logger rollout, rate-limit unification, query-page split (commits 0e8c7ca, 728574b)
- Category: Build Methods
- Instructions:
  - Sentry is wired but INERT until operator sets SENTRY_DSN + NEXT_PUBLIC_SENTRY_DSN (both in .env.example with comments); no source-map upload (@sentry/cli build script deliberately denied in pnpm-workspace.yaml)
  - Every new dependency with build scripts must be added to pnpm-workspace.yaml allowBuilds (false) — pnpm build's implicit deps-status-check FAILS the whole build on unapproved scripts, not just warns
  - Logger migration pattern: createLogger methods take (msg, ...args) mirroring console.* so migration is a pure textual rename; server NDJSON (ctx = file path), error level auto-reports Error args to Sentry; LOG_LEVEL env filters (prod default info, dev debug)
  - Rate limiting is now single-implementation src/lib/rate-limit.ts checkRateLimit (local->Redis->DB fallback, returns resetMs): 31 endpoints, old src/lib/server/rate-limit.ts deleted; semantics changed sliding-window -> fixed-window on the 10 migrated hot endpoints (X-RateLimit-Reset ~60s)
  - Extraction scripts over line ranges: verify the closing brace of the last extracted function (an off-by-one swallowed targetToDisplayName's final `}`); esbuild --outfile=/dev/null is the fastest syntax check before tsc
  - Stale next-start pitfall: an old prod server keeps serving its startup-time route table from memory even after .next is rebuilt (new API route 404s into [...query]); kill by PID from ss -ltnp, prod.pid may only hold the npx parent
  - Deployed query page still 94 kB after the 2802->2411 line split; gSSP helpers (looksLikeDomainQuery in lookup-helpers.ts) drive the bare-word 404 — verify with /invalidbareword123

[Project Knowledge Summary]
- Date: 2026-09-04
- Context: Sentry DSN provided by user and activated across local + Vercel (commit 5e57ca0)
- Category: Operations & Deployment
- Instructions:
  - Sentry org o4512028731244544, project id 4512028742713344, region us; DSN (client-visible by design) lives in /workspace/.env.local and as encrypted Vercel env vars SENTRY_DSN + NEXT_PUBLIC_SENTRY_DSN (production/preview/development, all three targets)
  - Vercel env-var changes require a NEW deployment to take effect: POST /v13/deployments with gitSource ref main rebuilds the same commit with fresh env (no empty commit needed)
  - logger.error reporting rule: Error-instance args -> captureException; plain-string errors -> captureMessage(level=error) — both fire-and-forget, so on Vercel a small fraction of post-response events may be dropped by lambda freeze (same known limitation as logQuery)
  - Verify client DSN activation by grepping the deployed _app chunk for the ingest host; verify server wiring by triggering the paypal webhook 503 path (POST /api/payment/webhook/paypal {})
  - No Sentry source maps (no SENTRY_AUTH_TOKEN); stacks reference built files. Environments seen in the dashboard: dsn-test (SDK direct), development (local dev), production

[Project Knowledge Summary]
- Date: 2026-09-04
- Context: Sentry source-map upload activated with user-provided auth token (commit cee13c3)
- Category: Operations & Deployment
- Instructions:
  - Sentry org slug whois-h4, project slug javascript-nextjs, region us; auth token (user token, org+project write) stored ONLY in /workspace/.env.local (SENTRY_AUTH_TOKEN) and as an encrypted production-only Vercel env var — never in code or chat output
  - Source-map pipeline: withSentryConfig wraps withPWA(nextConfig) in next.config.js, build-time only, fully disabled when SENTRY_AUTH_TOKEN unset (contributor builds unaffected); debug-ID based symbolication (release-independent); deleteSourcemapsAfterUpload keeps client maps off the CDN (server maps in .next/server are never publicly served)
  - Runtime release tagging does NOT flow through the lazy-init path (SDK define injection missed) — monitoring-server.ts sets release from VERCEL_GIT_COMMIT_SHA explicitly; next.config.js passes the same var to the plugin so Vercel upload release == runtime event release (verified: event release cee13c3... matched the uploaded release)
  - attachStacktrace:true added to both inits — without it captureMessage events carry zero frames; captureException events always carry the original stack
  - Verify uploads via GET /api/0/organizations/whois-h4/releases/ (SHA-named release from Vercel builds, BUILD_ID-named from local builds); verify symbolication via the latest event's exception frames — app frames show src/**.ts paths while SDK frames stay unsymbolicated (node_modules sources not uploaded, expected)
  - Vercel env: SENTRY_AUTH_TOKEN encrypted + SENTRY_ORG + SENTRY_PROJECT are production-target only, so preview builds skip upload gracefully
  - captureMessage stacks show only the first app frame (monitoring-server.ts call site) because the dynamic-import callback boundary breaks the async chain; real captureException events carry full original stacks

[Project Knowledge Summary]
- Date: 2026-09-05
- Context: User decision on the deferred version-upgrade proposal (Next 14.2.35 -> 15, next-auth v4 -> v5) after all audit leftovers shipped
- Category: Workflow & Collaboration
- Instructions:
  - Stay on the current versions: Next 14.2.35 + React 18.3.1 + next-pwa@5.6.0 + next-auth v4 hold — do NOT propose or start these upgrades unprompted; Next 14.2 is still in security support and there is no feature driver
  - Re-evaluate only on a real trigger: a new dependency requiring Next 15, a security advisory, or an explicit user request
  - If an upgrade round is ever greenlit: swap next-pwa -> workbox-build directly in next.config.js (PWA needs here are only sw.js precache + asset caching; pwa-install UI is independent), then handle React 19 peer churn, then next-auth v5 (getServerSession call-site rewrite) as a separate round; roll back via Vercel promote of a pre-upgrade deployment

[Project Knowledge Summary]
- Date: 2026-09-05
- Context: user-center subscription enhancement, batch 1 (defects) + batch 2 (management) implemented, tested, deployed live (commits 91752ce, 353ce85)
- Category: Build Methods
- Instructions:
  - Batch 1 R1-R4: delete-account single data-modifying CTE (reminders soft-cancel cancel_reason='account_deleted' + email_queue pending drain + stamps delete, returns cleaned counts); profile email migration moves reminders/stamps ownership with users.email rollback on failure; threshold engine = shared pure function nextReminderFiring(thresholds, daysToExpiry, expiry, sentKeys, now) in src/lib/lifecycle.ts (interval semantics: tier t fires only while daysToExpiry <= t && > next-lower tier); WHOIS refresh budget 20->50 sorted by days-remaining ascending (no-expiry bulk rows backfilled last); dropped branch deletes that domain's stamps
  - Batch 2 R5-R8: PATCH /api/user/subscriptions accepts thresholds[], phase_flags{}, notify_email, paused (+ GET returns notify_email/paused); bulk import POST /api/user/subscriptions/bulk (per-line/comma/semicolon, dedupe vs existing active, free-tier headroom truncation, WHOIS backfilled via daily cron); process.ts excludes paused=true and routes all mail to notify_email ?? email; EditExpiryModal got threshold multi-select + phase toggles + per-domain notification email; SubscriptionsTab has pause/resume button + paused badge + bulk import + free usage bar (x/5); 22 new dashboard i18n keys across all 8 locales
  - reminders schema now carries: notify_email, paused, last_epp_status, hold_notified_at, reserved_notified_at, membership_remind_stage, thresholds_json, phase_flags; user_notifications table created (batch 3 notification-center target)
  - Validation loop for this feature: npx vitest run (lifecycle.test.ts interval cases), npx tsc --noEmit, pnpm build (restore public/sw.js + workbox hash after), Vercel poll, live curl with --resolve (health + unauthenticated 401 + SSR 200)

[Project Knowledge Summary]
- Date: 2026-09-05
- Context: user-center subscription enhancement, batch 3 (R9-R12 notifications) implemented, tested, deployed live (commit a936f64, Vercel READY next-whois-nkkfyn4wm-teifan-8447s-projects.vercel.app)
- Category: Build Methods
- Instructions:
  - R9 hold/reserved engine in process.ts: WHOIS refresh persists last_epp_status; reminders query pulls last_epp_status/hold_notified_at/reserved_notified_at, epp_status falls back to persisted value; clientHold/serverHold -> hold email + hold_notified_at set, reserved/inactive -> reserved email + reserved_notified_at, release clears flags (idempotent re-notify). Hold detection only covers 90-day WHOIS sync window (accepted limit)
  - R10 notification center: user_notifications table; recordNotification/markNotificationRead/markAllNotificationsRead best-effort (warn only, never blocks mail pipeline) in src/lib/notifications.ts; GET /api/user/notifications (list limit 1-100 + unread count) + POST (id | markAll); navbar NotificationBell (unread badge, 60s poll + visibilitychange refresh, fixed dropdown); /notifications page (mark read per-item on tap, mark-all-read, empty/error states); type labels via notifications.* i18n keys
  - R11 membership reminders staged NULL->'7d'->'1d'->'expired' via membership_remind_stage on users; payment success resets stage to NULL in 3 UPDATEs (payment.ts 144-165); templates in email.ts membershipRenewHtml, copy in email-strings.ts mr_* block
  - R12 iCal export: src/lib/ics.ts buildIcs (RFC 5545 all-day events, fold + escape); GET /api/user/subscriptions/ics exports active subs' expiry/grace/redemption/drop events (computeLifecycle + loadLifecycleOverrides); SubscriptionsTab header iCal download link (dashboard.export_ics key)
  - process.ts recordNotification wired to all events: threshold/grace/redemption/pending_delete/drop_soon/dropped/hold/reserved/membership (body from email-strings pe_*/mr_* keys where available)
  - Notification emails reuse existing subj_* subject keys; new i18n only where UI-facing: notifications.* block + dashboard.export_ics added to all 8 locales (en.json drives TranslationKey type so UI keys must exist there first)
  - Batch 4 remaining: R13/R14 drops calendar (GET /api/drops public + /drops.tsx + admin toggle drop_calendar_public)

[Project Knowledge Summary]
- Date: 2026-09-05
- Context: user-center subscription enhancement, batch 4 (R13/R14 drops calendar) implemented, tested, deployed live (commit 3c7c013, Vercel READY next-whois-khtidm1yl-teifan-8447s-projects.vercel.app) — all 4 batches shipped
- Category: Build Methods
- Instructions:
  - R13 GET /api/drops?days=30: public part = expired_domain_leads WHERE status='available' AND available_date BETWEEN today AND today+days (TEXT YYYY-MM-DD string compare), ORDER BY date/domain LIMIT 500, grouped by date; private part (session only) = active reminders with computeLifecycle dropDate in window (whois_expiry_date ?? expiration_date), grouped by date; public_locked=true when drop_calendar_public='0' AND no session; Cache-Control public max-age=300
  - /drops.tsx: date-grouped glass-panel cards, today highlight, empty + error/retry + login-guard states, monitor button per domain → POST /api/remind/submit {domain, email} (reuses subscription flow: WHOIS sync + confirm email); handles 409 ALREADY_SUBSCRIBED (mark monitored) / 403 LIMIT_EXCEEDED (upgrade hint); unauthenticated click routes to /login; monitoredSet = user_drops domains + locally-subscribed
  - site_settings new key drop_calendar_public default '1' — add to SiteSettings interface + DEFAULT_SETTINGS (site-settings.tsx); admin/settings.tsx NAV_FEATURES gets FeatureCard toggle (adminLink /drops); ALLOWED_KEYS auto-derived from DEFAULT_SETTINGS so no settings API change needed
  - navbar NavDrawer NAV_GROUPS gets nav_drops entry gated by settingKey enable_remind (needs RiCalendarLine import); nav_drops/nav_drops_desc i18n keys required since NavItem keys are typed TranslationKey
  - i18n reminder: any UI-facing key must exist in en.json first (TranslationKey type derives from it), then sync other 7 locales; check-locale-keys.mjs validates
  - All batches done: 91752ce (R1-R4), 353ce85 (R5-R8), a936f64 (R9-R12), 3c7c013 (R13-R14); feature fully live

[Project Knowledge Summary]
- Date: 2026-09-05
- Context: post-batch-4 live regression against production Supabase (aws-0-us-east-1.pooler.supabase.com:6543 via SUPABASE_DATABASE_URL in .env.local) — read-only + tx-rollback checks
- Category: Troubleshooting & Debugging
- Instructions:
  - Schema verified present: reminders new cols (notify_email, paused, last_epp_status, hold_notified_at, reserved_notified_at, membership_remind_stage, thresholds_json, phase_flags), users.membership_remind_stage, user_notifications (id,email,type,title,body,domain,read_at,created_at); drop_calendar_public not yet stored in site_settings so default '1' (open) applies
  - **expired_domain_leads is EMPTY (0 rows)** — the drop calendar's public part will show the empty state until the expireddomains.net crawler runs; admin must configure the crawl (credentials + cron /api/admin/expired-domains-crawl) for /drops to have content
  - Grouping query validated via BEGIN/INSERT/ROLLBACK tx (window filter excludes out-of-window, groups by date) — no data persisted; do NOT seed production leads for tests (no-delete rule blocks cleanup); use tx-rollback pattern instead
  - 13 active reminders in prod; user_notifications empty (cron hasn't fired today); unauthenticated API paths already return 401/503 correctly
  - Login-state end-to-end (subscribe/notify-read) can't be exercised without real credentials; covered by 401 paths + SSR 200 checks instead

[Project Knowledge Summary]
- Date: 2026-09-05
- Context: crawler config completion — expireddomains.net login migrated + /api/drops grouping fix, deployed (commit 90e8405, Vercel READY next-whois-id5ly9rp8-teifan-8447s-projects.vercel.app)
- Category: Troubleshooting & Debugging
- Instructions:
  - expireddomains.net migrated login to the www domain: GET https://www.expireddomains.net/login/ then POST https://www.expireddomains.net/logincheck/ with form fields `login`/`password`/`rememberme=1` (NO csrfmiddlewaretoken anymore); the response 302s to member.expireddomains.net/auth/?token=... which sets the member-subdomain session cookie named `ExpiredDomainssessid` (not sessionid). Crawl endpoint src/pages/api/admin/expired-domains-crawl.ts must follow that /auth/ redirect and check for ExpiredDomainssessid. Verified working both from dev sandbox and Vercel production (prod run inserted 25 leads)
  - Crawled leads only carry a YEAR in available_date/deleted_date (e.g. "2026", "2022") — the exact-date window filter (available_date BETWEEN today AND today+days) matches nothing; /api/drops public query now groups ALL available leads by available_date (LIMIT 500) and the page falls back to displaying the raw year string (fmtDay: new Date("2026T00:00:00Z") is invalid → isNaN → label=iso)
  - drops.subtitle i18n key no longer takes a {{days}} param — rewrote all 8 locales to neutral phrasing ("crawled domains grouped by availability")
  - vercel.json cron `0 5 * * *` → /api/admin/expired-domains-crawl?action=crawl&mode=length (05:00 UTC, avoids remind 09:00 / email-queue 02:00 / tld-scrape 03:00); crawl action accepts CRON_SECRET Bearer/x-cron-secret OR admin session, all other actions stay requireAdmin
  - PWA build artifacts (public/sw.js, public/workbox-*.js) are generated by next-pwa during build — now in .gitignore; delete stale tracked copies on next commit

[Project Knowledge Summary]
- Date: 2026-09-05
- Context: restored v0/mobile-layout-redesign branch optimizations onto main (commit 52ee134, Vercel READY next-whois-q2xa6zqlx-teifan-8447s-projects.vercel.app)
- Category: Workflow & Collaboration
- Instructions:
  - The GitHub repo carries 3 v0 bot branches (v0/domain-1458-751f3090, v0/mobile-layout-redesign, v0/project-ad39f111) that fork from the initial e6d85f0 upload — they were NEVER merged into main, so main's pages lacked v0's UI optimizations ("顶掉" symptom). They are parallel histories; do NOT merge them wholesale (they'd delete batch features: bulk import, notification bell, drops, whois-servers nav). Port fixes file-by-file instead
  - Restore pattern: if a target file is identical between main and e6d85f0 (git diff e6d85f0 HEAD -- <file> empty), `git checkout origin/v0/<branch> -- <file>` is safe; else manually merge the v0 hunk while preserving main-only lines (verified: EditStampModal/CardThemePicker/TagStylePicker were untouched → direct checkout; admin-layout/admin/index/dashboard had main edits → hand-merged, re-added whois-servers nav + logged/anon search stats)
  - v0/mobile-layout-redesign content: dashboard header→mobile card + 3-col action grid; admin StatCard/quick-action/core-stats responsive; admin-layout mobile header compaction + icon-only back btn (aria-label=admin.frontend); EditStampModal picker with live preview + gallery/editorial/compact modes; CardThemePicker/TagStylePicker horizontal option rows
  - v0/domain-1458-751f3090 head commits hold homepage search_box.tsx + index.tsx fixes (debounce, StrictMode double-mount guard, loading-guard submit, async history) — ported later, see the 2026-09-05 domain-1458 entry

[Project Knowledge Summary]
- Date: 2026-09-05
- Context: ported v0/domain-1458 search-box/homepage fixes onto main (commit 798a7e0, Vercel READY next-whois-jkebtahe1-teifan-8447s-projects.vercel.app)
- Category: Build Methods
- Instructions:
  - v0/domain-1458 head commits a5b2823 (search-box rendering) + 44883f2 (dup search/loading) target v0's OWN search_box/index versions — do NOT git checkout them wholesale (they drop main's prefetchLookup + real-time unknown-TLD validation). Hand-port the fixes instead
  - Ported into src/components/search_box.tsx: mountedRef StrictMode double-mount guard; async history load via requestAnimationFrame (try/catch for localStorage); suggestionTimeoutRef cleanup on unmount; computeDropdownPos memoized with position-changed no-op; mount/autoFocus position recompute; listeners deps +computeDropdownPos; 50ms-debounced suggestion generation (keep synchronous TLD validation + 400ms prefetch); portal dropdownPos fallback to live input rect; handleSearch/handleSuggestionClick loading+empty guards
  - src/pages/index.tsx: isNavigatingRef guards duplicate router.push (double Enter/click); reset only in routeChangeError handler (main keeps isSearching + searchingDomain state, QueryLoadingSkeleton path)
  - Verify chain same as batches: tsc → dev SSR 200 (/, /google.com) → next build → rm PWA artifacts → commit → push → poll → --resolve live curl

[Project Knowledge Summary]
- Date: 2026-09-06
- Context: signed-in navbar overflow on mobile — ported v0/project-ad39f111 navbar responsive fixes onto main (commit 6e3cef7, Vercel READY next-whois-j4jqul213-teifan-8447s-projects.vercel.app)
- Category: Build Methods
- Instructions:
  - The headline fix for "signed-in top bar overflows on mobile (title + icons pushed off-screen)" lives in v0/project-ad39f111's src/components/navbar.tsx: container capped to max-w-[calc(100vw-1rem)], gap-6 -> gap-2 sm:gap-6, the nav divider hidden below sm, and the right button group gap-3 -> gap-1 sm:gap-3. Extract with git diff e6d85f0 origin/v0/project-ad39f111 -- src/components/navbar.tsx (it changed only navbar.tsx, admin-layout.tsx and admin/index.tsx; those last two are already covered by the mobile-layout-redesign port)
  - main additionally hides the VERSION chip below 390px (hidden min-[390px]:inline) and lets logoText truncate with min-w-0 so the title never squeezes out — keep these when re-applying
  - signed-in mobile row is ThemeToggle/LanguageSwitcher/NotificationBell/UserButton/NavDrawer + logo — all 44px min-width; after the port total ~228px + logo, verified to fit 320px iPhone SE; verify in SSR HTML by grepping for max-w-[calc(100vw-1rem)] / gap-2 sm:gap-6 / hidden sm:block h-4 w-[1px]

[Project Knowledge Summary]
- Date: 2026-09-06
- Context: TLD failure events pipeline testing + real-data backfill + admin panel completion (test file failure-events.test.ts, script backfill-failure-events.mjs)
- Category: Testing Methods
- Instructions:
  - Vitest: when spying on a module function that returns a rejected promise, do NOT use mockRejectedValue/mockRejectedValueOnce — Vitest treats the unhandled rejection as a test failure. Use vi.spyOn(dbQuery, "run").mockResolvedValue(...) so run() never rejects and no unhandledRejection fires
  - tld_failure_events (diagnostic fact source: legacy-migration + query-log-backfill contexts) and query_logs (metric fact source) keep a strict responsibility split; fail_count on tld_failure_stats is frozen at 0 since R5 and is only kept for backward compat
  - Real-data backfill is preferred over synthetic migrations: scripts/backfill-failure-events.mjs re-derives events from query_logs failure rows (19 TLDs / 87 failed rows -> 72 events) preserving original timestamps; legacy-migration batch (130 events) all share one synthetic created_at (2026-09-06 06:55:56) so the panel trend shows a one-day spike — expected
  - In SQL for this project (node-postgres pg.Client), numeric aggregate outputs arrive as strings (COUNT(*)::text pattern is used to avoid parseInt ambiguity); date formatting uses to_char in the query rather than JS
  - Admin pages have no ESLint config (next lint opens interactive setup — cancel); verification chain is npx tsc --noEmit -> npx vitest run -> npx next build (via background terminal, restore public/sw.js + workbox hash after build if gitignored artifacts changed)
