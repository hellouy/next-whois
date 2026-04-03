/**
 * TLD lifecycle (grace / redemption / pending-delete) data.
 * Used by both the frontend dialog and the backend cron processor.
 *
 * Phase reminder special `days_before` keys stored in reminder_logs:
 *   GRACE_KEY        = -1
 *   REDEMPTION_KEY   = -2
 *   PENDING_KEY      = -3
 *
 * Phase detection priority:
 *   1. Live EPP status codes from WHOIS/RDAP  (most accurate)
 *   2. Date arithmetic against expiry + TLD table  (fallback)
 *
 * Sources:
 *   ICANN RAA (gTLD standard: grace 30d / RGP 30d / pendingDelete 5d)
 *   Namecheap KB (updated 2025-09-10): https://www.namecheap.com/support/knowledgebase/article.aspx/9916/2207/tlds-grace-periods
 *   Dynadot TLD pages (verified 2026-03): https://www.dynadot.com/domain/[tld]
 *   Enom TLD Reference Chart (2026-03): https://docs.google.com/spreadsheets/d/1oVNszsvqhxh3hlT1LYMfcwq3lw_e6J7DeBePvN4t2aw
 *   Registry policy pages (CNNIC, HKIRC, Nominet, AFNIC, DENIC, auDA …)
 *   IANA root-zone database
 */

export const GRACE_KEY = -1;
export const REDEMPTION_KEY = -2;
export const PENDING_KEY = -3;

export interface TldLifecycle {
  /** Days of grace period after expiry (0 = no grace) */
  grace: number;
  /** Days of redemption period after grace ends (0 = no redemption) */
  redemption: number;
  /** Days of pending-delete period after redemption ends (0 = no pending-delete) */
  pendingDelete: number;
  /** Human-readable registry / authority name */
  registry?: string;
  /** Data confidence: "high" = verified from registry docs, "est" = estimated */
  confidence?: "high" | "est";

  // ── Precise drop-time fields ──────────────────────────────────────────────
  /** Hour (0-23) in dropTimezone when pending-delete domains are released */
  dropHour?: number;
  /** Minute (0-59) of drop time */
  dropMinute?: number;
  /** Second (0-59) of drop time */
  dropSecond?: number;
  /** IANA timezone for dropHour/dropMinute (default: "UTC") */
  dropTimezone?: string;
  /** Days the registry deletes the domain BEFORE nominal expiry date (e.g. .nl=3, .au=10) */
  preExpiryDays?: number;
}

/**
 * Format a TldLifecycle drop time as "HH:MM:SS TZ" or null.
 * Used to display the estimated moment a pending-delete domain becomes available.
 */
export function formatDropTime(lc: TldLifecycle): string | null {
  if (lc.dropHour === undefined || lc.dropHour === null) return null;
  const h = String(lc.dropHour).padStart(2, "0");
  const m = String(lc.dropMinute ?? 0).padStart(2, "0");
  const s = String(lc.dropSecond ?? 0).padStart(2, "0");
  const tz = lc.dropTimezone ?? "UTC";
  return `${h}:${m}:${s} ${tz}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Named presets — reuse these for common registry policy families
// ─────────────────────────────────────────────────────────────────────────────

/** Standard ICANN gTLD lifecycle (RAA-mandated, ~30d grace in practice). Used as default for all unknown gTLDs. */
const STD: TldLifecycle = { grace: 30, redemption: 30, pendingDelete: 5, confidence: "high" };

/** AFNIC-managed ccTLDs (.fr, .re, .pm, .tf, .wf, .yt, .nc, .pf, .gp, .mq …)
 *  No grace period; 30-day RGA (restore); 5-day pendingDelete.
 *  Verified: Dynadot .pm / .wf Grace=0, Delete=5, Restore=30 (2026-03) */
const AFNIC: TldLifecycle = { grace: 0, redemption: 30, pendingDelete: 5, registry: "AFNIC", confidence: "high" };

/** Immediate-delete ccTLDs: no grace, no redemption, no pendingDelete */
const IMMEDIATE: TldLifecycle = { grace: 0, redemption: 0, pendingDelete: 0, confidence: "high" };

/** Nominet-style (UK): ~90-day total renewal window, no separate RGP fee, 5-day pendingDelete.
 *  Drop time: 00:00 UTC on the suspension date.
 *  Dynadot: Grace=85, Delete=5; Namecheap: 90d total. Using 90/5 as rounded policy values. */
const NOMINET: TldLifecycle = {
  grace: 90, redemption: 0, pendingDelete: 5, registry: "Nominet", confidence: "high",
  dropHour: 0, dropMinute: 0, dropSecond: 0, dropTimezone: "UTC",
};

/** CNNIC (.cn and its second-level variants): no registry grace, 15-day RGP, 5-day pendingDelete.
 *  Drop batch typically runs ~00:00 CST (Asia/Shanghai).
 *  Dynadot: Grace=38 (registrar grace), Restore=15d; registry-level grace=0. Using restore=15. */
const CNNIC: TldLifecycle = {
  grace: 0, redemption: 15, pendingDelete: 5, registry: "CNNIC", confidence: "high",
  dropHour: 0, dropMinute: 0, dropSecond: 0, dropTimezone: "Asia/Shanghai",
};

/** HKIRC (.hk and its second-level variants): 30-day grace, 60-day RGP, no pendingDelete.
 *  Dynadot verified: Grace=30, Restore=60, Delete=0 (2026-03); total renewal window 90 days. */
const HKIRC: TldLifecycle = { grace: 30, redemption: 60, pendingDelete: 0, registry: "HKIRC", confidence: "high" };

/** Registro.br (.br and sub-TLDs): immediate, no grace/redemption/pendingDelete */
const REGISTROBR: TldLifecycle = { grace: 0, redemption: 0, pendingDelete: 0, registry: "Registro.br", confidence: "high" };

/** NIC Argentina (.ar and sub-TLDs): immediate deletion */
const NICAR: TldLifecycle = { ...IMMEDIATE, registry: "NIC Argentina" };

/** JPRS (.jp and sub-TLDs): immediate deletion */
const JPRS: TldLifecycle = { ...IMMEDIATE, registry: "JPRS" };

/**
 * Comprehensive gTLD + ccTLD lifecycle table.
 * 300+ entries covering major TLDs worldwide.
 *
 * Accuracy notes (Dynadot-verified 2026-03; Namecheap KB updated 2025-09-10):
 *  - .cn: CNNIC — registry grace=0, RGP=15d, pendingDelete=5d.
 *  - .hk: HKIRC — grace=30d, RGP=60d, pendingDelete=0.
 *  - .ph: PH Domains Foundation — grace=50d, no redemption, no pendingDelete.
 *  - .uk: Nominet — ~90d renewal window, no RGP fee, pendingDelete=5d.
 *  - .de: DENIC — variable grace 0-20d, RGP=30d, pendingDelete=25d (NOT immediate).
 *  - .it: Registro.it — grace=10d, RGP=30d, no pendingDelete (NOT immediate).
 *  - .pl: NASK — no grace, RGP=30d, no pendingDelete (NOT immediate).
 *  - .no: Norid — grace=89d, no RGP, no pendingDelete (long grace, NOT immediate).
 *  - .ie: IEDR — grace=30d, RGP=30d, pendingDelete=14d (NOT immediate).
 *  - .be: DNS Belgium — no grace, RGP=30d, no pendingDelete (Enom 2026-03; 3d pre-expiry deletion).
 *  - .ch/.li: SWITCH/NIC.LI — no grace, RGP=14d, no pendingDelete (Enom 2026-03; 10d pre-expiry).
 *  - .eu: EURid — no grace, RGP=30d, no pendingDelete (Enom 2026-03; 3d pre-expiry deletion).
 *  - .nl: SIDN — no grace, RGP=30d, no pendingDelete (Enom 2026-03; 3d pre-expiry deletion).
 *  - .es: Red.es — no grace, RGP=14d only, no pendingDelete (Enom 2026-03; 12d pre-expiry).
 *  - .fr/.re etc.: AFNIC — no grace, 30-day RGA (restore), 5-day pendingDelete.
 *  - .tw: TWNIC — grace=32d, no RGP, pendingDelete=10d.
 *  - .nz: InternetNZ — no grace, RGP=90d, 5d pendingDelete (Enom 2026-03; 3d pre-expiry).
 *  - .cl: NIC Chile — grace=10d, RGP=30d, pendingDelete=10d (NOT immediate).
 *  - .cm: NIC-Cameroon — IMMEDIATE (expires = deleted; Enom 2026-03 confirmed: N/N/3d before).
 *  - .nu: Nunames — grace=7d, RGP=60d (Namecheap 2025-09-10; Enom 2026-03 confirmed).
 *  - .gg: Island Networks — grace=28d, RGP=12d, no pendingDelete.
 *  - .au (new 2022 TLD): auDA — no grace, RGP=31d (Enom 2026-03; 10d pre-expiry deletion).
 *  - com.au/net.au: auDA — grace 30d, RGP 30d, pendingDelete 5d.
 */
export const LIFECYCLE_TABLE: Record<string, TldLifecycle> = {

  // ── Tier-1 gTLDs ─────────────────────────────────────────────────────────
  // Verisign runs 5 deletion cycles through the day; no single fixed time
  com:    { ...STD, registry: "Verisign" },
  net:    { ...STD, registry: "Verisign" },
  org:    { ...STD, registry: "Public Interest Registry" },
  info:   { ...STD, registry: "Identity Digital" },
  biz:    { ...STD, registry: "Identity Digital" },
  name:   { ...STD, registry: "Verisign" },
  mobi:   { ...STD, registry: "Identity Digital" },
  tel:    { ...STD, registry: "Telnic" },
  us:     { ...STD, registry: "Neustar" },
  co:     { ...STD, registry: "GoDaddy" },
  pro:    { ...STD, registry: "Identity Digital" },
  jobs:   { ...STD, registry: "Employ Media" },
  travel: { ...STD, registry: "Donuts" },
  museum: { grace: 45, redemption: 30, pendingDelete: 5, registry: "MuseDoma", confidence: "high" },
  coop:   { ...STD, registry: "DotCooperation" },
  aero:   { ...STD, registry: "SITA" },
  int:    { grace: 45, redemption: 30, pendingDelete: 5, registry: "IANA", confidence: "high" },
  edu:    { grace: 45, redemption: 30, pendingDelete: 5, registry: "Educause", confidence: "high" },
  gov:    { grace: 45, redemption: 30, pendingDelete: 5, registry: "CISA", confidence: "high" },
  mil:    { grace: 45, redemption: 30, pendingDelete: 5, registry: "DoD", confidence: "high" },
  xxx:    { ...STD, registry: "ICM Registry" },
  post:   { ...STD, registry: "UPU" },
  cat:    { ...STD, registry: "Fundació puntCAT" },

  // ── Google / Squarespace new gTLDs ────────────────────────────────────────
  app:    { ...STD, registry: "Google" },
  dev:    { ...STD, registry: "Google" },
  page:   { ...STD, registry: "Google" },
  zip:    { ...STD, registry: "Google" },
  dad:    { ...STD, registry: "Google" },
  phd:    { ...STD, registry: "Google" },
  nexus:  { ...STD, registry: "Google" },
  web:    { ...STD, registry: "Identity Digital" },

  // ── Very popular new gTLDs ────────────────────────────────────────────────
  xyz:    { ...STD, registry: "XYZ.COM LLC" },
  club:   { ...STD, registry: ".CLUB Domains" },
  fun:    { ...STD, registry: "Radix" },
  icu:    { ...STD, registry: "ShortDot SA" },
  top:    { ...STD, registry: "Jiangsu Bangning Science" },
  vip:    { ...STD, registry: "Minds + Machines" },
  wiki:   { ...STD, registry: "Top Level Design" },
  ink:    { ...STD, registry: "Top Level Design" },
  buzz:   { ...STD, registry: "DOTSTRATEGY" },
  website:{ ...STD, registry: "Radix" },
  uno:    { ...STD, registry: "Dot Latin LLC" },
  bio:    { ...STD, registry: "Identity Digital" },
  ski:    { ...STD, registry: "Dot Ski" },
  ltd:    { ...STD, registry: "Namera Capital" },
  llc:    { ...STD, registry: "Dot Trademark" },
  srl:    { ...STD, registry: "InterNetX" },
  gmbh:   { ...STD, registry: "InterNetX" },
  // .inc: Intercap Holdings — 42-day grace, 30-day RGP (Enom 2026-03: 42/30; 42d pre-expiry deletion)
  inc:    { grace: 42, redemption: 30, pendingDelete: 5, registry: "Intercap Holdings", confidence: "high" },
  bar:    { ...STD, registry: "Punto 2012 Sociedad Anonima" },
  fit:    { ...STD, registry: "Donuts" },
  fan:    { ...STD, registry: "Asiamix Digital" },
  bet:    { ...STD, registry: "Identity Digital" },
  best:   { ...STD, registry: "GoDaddy" },
  cash:   { ...STD, registry: "Donuts" },
  deal:   { ...STD, registry: "Amazon" },

  // ── Standard new gTLD — business & professional ───────────────────────────
  shop:        { ...STD },
  blog:        { ...STD },
  cloud:       { ...STD },
  tech:        { ...STD },
  online:      { ...STD },
  site:        { ...STD },
  store:       { ...STD },
  live:        { ...STD },
  link:        { ...STD },
  media:       { ...STD },
  news:        { ...STD },
  email:       { ...STD },
  space:       { ...STD },
  world:       { ...STD },
  work:        { ...STD },
  tools:       { ...STD },
  run:         { ...STD },
  team:        { ...STD },
  digital:     { ...STD },
  global:      { ...STD },
  network:     { ...STD },
  host:        { ...STD },
  studio:      { ...STD },
  design:      { ...STD },
  agency:      { ...STD },
  group:       { ...STD },
  plus:        { ...STD },
  guru:        { ...STD },
  expert:      { ...STD },
  solutions:   { ...STD },
  systems:     { ...STD },
  services:    { ...STD },
  support:     { ...STD },
  help:        { ...STD },
  guide:       { ...STD },
  review:      { ...STD },
  reviews:     { ...STD },
  social:      { ...STD },
  photos:      { ...STD },
  video:       { ...STD },
  audio:       { ...STD },
  music:       { ...STD },
  art:         { ...STD },
  gallery:     { ...STD },
  sale:        { ...STD },
  deals:       { ...STD },
  events:      { ...STD },
  fashion:     { ...STD },
  sport:       { ...STD },
  health:      { ...STD },
  care:        { ...STD },
  yoga:        { ...STD },
  finance:     { ...STD },
  money:       { ...STD },
  fund:        { ...STD },
  capital:     { ...STD },
  bank:        { ...STD, registry: "SWIFT" },
  law:         { ...STD },
  legal:       { ...STD },
  academy:     { ...STD },
  accountant:  { ...STD },
  accountants: { ...STD },
  actor:       { ...STD },
  adult:       { ...STD },
  apartments:  { ...STD },
  associates:  { ...STD },
  auction:     { ...STD },
  bargains:    { ...STD },
  bike:        { ...STD },
  bingo:       { ...STD },
  black:       { ...STD },
  blue:        { ...STD },
  boutique:    { ...STD },
  builders:    { ...STD },
  cab:         { ...STD },
  cafe:        { ...STD },
  camera:      { ...STD },
  camp:        { ...STD },
  careers:     { ...STD },
  casino:      { ...STD },
  catering:    { ...STD },
  center:      { ...STD },
  chat:        { ...STD },
  cheap:       { ...STD },
  church:      { ...STD },
  city:        { ...STD },
  claims:      { ...STD },
  cleaning:    { ...STD },
  clinic:      { ...STD },
  clothing:    { ...STD },
  coach:       { ...STD },
  codes:       { ...STD },
  coffee:      { ...STD },
  college:     { ...STD },
  community:   { ...STD },
  company:     { ...STD },
  computer:    { ...STD },
  condos:      { ...STD },
  construction:{ ...STD },
  consulting:  { ...STD },
  contractors: { ...STD },
  cooking:     { ...STD },
  coupons:     { ...STD },
  credit:      { ...STD },
  dance:       { ...STD },
  dating:      { ...STD },
  delivery:    { ...STD },
  dental:      { ...STD },
  diamonds:    { ...STD },
  direct:      { ...STD },
  directory:   { ...STD },
  discount:    { ...STD },
  doctor:      { ...STD },
  dog:         { ...STD },
  earth:       { ...STD },
  energy:      { ...STD },
  engineering: { ...STD },
  enterprises: { ...STD },
  equipment:   { ...STD },
  estate:      { ...STD },
  exchange:    { ...STD },
  exposed:     { ...STD },
  express:     { ...STD },
  fail:        { ...STD },
  farm:        { ...STD },
  financial:   { ...STD },
  fitness:     { ...STD },
  flights:     { ...STD },
  florist:     { ...STD },
  foundation:  { ...STD },
  furniture:   { ...STD },
  games:       { ...STD },
  glass:       { ...STD },
  gold:        { ...STD },
  golf:        { ...STD },
  graphics:    { ...STD },
  green:       { ...STD },
  gripe:       { ...STD },
  guitars:     { ...STD },
  haus:        { ...STD },
  healthcare:  { ...STD },
  hockey:      { ...STD },
  homes:       { ...STD },
  horse:       { ...STD },
  house:       { ...STD },
  immo:        { ...STD },
  immobilien:  { ...STD },
  industries:  { ...STD },
  institute:   { ...STD },
  insure:      { ...STD },
  international:{ ...STD },
  investments: { ...STD },
  jetzt:       { ...STD },
  kitchen:     { ...STD },
  land:        { ...STD },
  lease:       { ...STD },
  lighting:    { ...STD },
  limited:     { ...STD },
  limo:        { ...STD },
  loans:       { ...STD },
  maison:      { ...STD },
  management:  { ...STD },
  marketing:   { ...STD },
  mba:         { ...STD },
  memorial:    { ...STD },
  moda:        { ...STD },
  mortgage:    { ...STD },
  movie:       { ...STD },
  ninja:       { ...STD },
  partners:    { ...STD },
  parts:       { ...STD },
  pet:         { ...STD },
  photography: { ...STD },
  pics:        { ...STD },
  pizza:       { ...STD },
  place:       { ...STD },
  plumbing:    { ...STD },
  press:       { ...STD },
  productions: { ...STD },
  properties:  { ...STD },
  property:    { ...STD },
  pub:         { ...STD },
  racing:      { ...STD },
  radio:       { ...STD },
  realty:      { ...STD },
  recipes:     { ...STD },
  rehab:       { ...STD },
  rentals:     { ...STD },
  repair:      { ...STD },
  report:      { ...STD },
  republican:  { ...STD },
  rest:        { ...STD },
  restaurant:  { ...STD },
  rocks:       { ...STD },
  rodeo:       { ...STD },
  rugby:       { ...STD },
  schule:      { ...STD },
  school:      { ...STD },
  security:    { ...STD },
  sexy:        { ...STD },
  shoes:       { ...STD },
  singles:     { ...STD },
  solar:       { ...STD },
  soy:         { ...STD },
  supplies:    { ...STD },
  supply:      { ...STD },
  surgery:     { ...STD },
  tax:         { ...STD },
  taxi:        { ...STD },
  technology:  { ...STD },
  tennis:      { ...STD },
  tips:        { ...STD },
  tires:       { ...STD },
  today:       { ...STD },
  tours:       { ...STD },
  town:        { ...STD },
  toys:        { ...STD },
  trade:       { ...STD },
  training:    { ...STD },
  university:  { ...STD },
  vacations:   { ...STD },
  ventures:    { ...STD },
  villas:      { ...STD },
  vision:      { ...STD },
  voyage:      { ...STD },
  wine:        { ...STD },
  works:       { ...STD },
  wtf:         { ...STD },
  zone:        { ...STD },

  // ── Geographic / city new gTLDs (all standard ICANN) ──────────────────────
  amsterdam:   { ...STD, registry: "Gemeente Amsterdam" },
  barcelona:   { ...STD, registry: "Fundació puntBCN" },
  berlin:      { ...STD, registry: "dotBERLIN GmbH" },
  brussels:    { ...STD, registry: "DNS.be" },
  capetown:    { ...STD, registry: "ZA Central Registry" },
  cologne:     { ...STD, registry: "dotKoeln GmbH" },
  koeln:       { ...STD, registry: "dotKoeln GmbH" },
  dubai:       { ...STD, registry: "Dubai DED" },
  istanbul:    { ...STD, registry: "Istanbul Metropolitan Municipality" },
  london:      { ...STD, registry: "Dot London Domains" },
  miami:       { ...STD, registry: "Minds + Machines" },
  moscow:      { ...STD, registry: "Foundation for Assistance" },
  nagoya:      { ...STD, registry: "GMO Registry" },
  nyc:         { ...STD, registry: "The City of New York" },
  okinawa:     { ...STD, registry: "BusinessRalliart" },
  osaka:       { ...STD, registry: "Interlink" },
  paris:       { ...STD, registry: "City of Paris" },
  quebec:      { ...STD, registry: "PointQuébec" },
  rio:         { ...STD, registry: "Empresa Municipal" },
  ryukyu:      { ...STD, registry: "BusinessRalliart" },
  saarland:    { ...STD, registry: "dotSaarland GmbH" },
  tirol:       { ...STD, registry: "punkt Tirol GmbH" },
  tokyo:       { ...STD, registry: "GMO Registry" },
  vegas:       { ...STD, registry: "Dot Vegas, Inc." },
  wien:        { ...STD, registry: "punkt.wien GmbH" },
  yokohama:    { ...STD, registry: "GMO Registry" },
  zuerich:     { ...STD, registry: "Kanton Zürich" },
  boston:      { ...STD, registry: "Minds + Machines" },
  wales:       { ...STD, registry: "Nominet" },
  scot:        { ...STD, registry: "dot.Scot Registry" },
  irish:       { ...STD, registry: "Dot-Irish" },
  // .eus: Basque Country — grace=45d, RGP=30d, pendingDelete=5d (PUNTUEUS; comparable to nTLD standard)
  eus:         { grace: 45, redemption: 30, pendingDelete: 5, registry: "PUNTUEUS", confidence: "est" },
  africa:      { ...STD, registry: "ZA Central Registry" },
  arab:        { ...STD, registry: "League of Arab States" },
  asia:        { ...STD, registry: "DotAsia Organisation" },
  nrw:         { ...STD, registry: "dotNRW GmbH" },
  // Amazon nTLDs — grace=40d, RGP=30d, pendingDelete=5d (Enom 2026-03: 40/30 for all Amazon-operated)
  free:        { grace: 40, redemption: 30, pendingDelete: 5, registry: "Amazon Registry Services", confidence: "high" },
  fast:        { grace: 40, redemption: 30, pendingDelete: 5, registry: "Amazon Registry Services", confidence: "high" },
  hot:         { grace: 40, redemption: 30, pendingDelete: 5, registry: "Amazon Registry Services", confidence: "high" },
  spot:        { grace: 40, redemption: 30, pendingDelete: 5, registry: "Amazon Registry Services", confidence: "high" },
  talk:        { grace: 40, redemption: 30, pendingDelete: 5, registry: "Amazon Registry Services", confidence: "high" },
  you:         { grace: 40, redemption: 30, pendingDelete: 5, registry: "Amazon Registry Services", confidence: "high" },

  // ── ccTLD-origin domains widely used as generic ───────────────────────────
  // .io: BIOT/Identity Digital — 32-day grace, 30-day RGP, 5-day pendingDelete (Enom 2026-03)
  io:     { grace: 32, redemption: 30, pendingDelete: 5,  registry: "Identity Digital (BIOT)", confidence: "high" },
  // .ai: Anguilla NIC — 45-day grace, 30-day RGP, 5-day pendingDelete (Enom 2026-03)
  ai:     { grace: 45, redemption: 30, pendingDelete: 5,  registry: "Anguilla NIC", confidence: "high" },
  // .gg: Island Networks — 28-day grace, 12-day RGP, no pendingDelete (Dynadot 2026-03; Namecheap: 28d then 26d RGP)
  gg:     { grace: 28, redemption: 12, pendingDelete: 0,  registry: "Island Networks (Guernsey)", confidence: "high" },
  je:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "Island Networks (Jersey)", confidence: "est" },
  // .la: NIC Laos — 30-day grace, 30-day RGP (Enom 2026-03)
  la:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "NIC Laos (CentralNic)", confidence: "high" },
  cc:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "VeriSign (Cocos Islands)", confidence: "high" },
  // .tv: GoDaddy Registry (Tuvalu) — 42-day grace, 30-day RGP, 5-day pendingDelete (Enom 2026-03)
  tv:     { grace: 42, redemption: 30, pendingDelete: 5,  registry: "GoDaddy Registry (Tuvalu)", confidence: "high" },
  ws:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "Samoa NIC", confidence: "est" },
  me:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "doMEn (Montenegro)", confidence: "high" },
  // .ac: NIC.AC (Ascension) — 32-day grace, 30-day RGP (Enom 2026-03)
  ac:     { grace: 32, redemption: 30, pendingDelete: 5,  registry: "NIC.AC (Ascension)", confidence: "high" },
  // .sh: NIC.SH (Saint Helena) — 32-day grace, 30-day RGP (Enom 2026-03)
  sh:     { grace: 32, redemption: 30, pendingDelete: 5,  registry: "NIC.SH (St Helena)", confidence: "high" },
  cx:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "Christmas Island NIC", confidence: "est" },
  // .nu: Nunames — 7-day grace, 60-day RGP, no pendingDelete (Namecheap 2025-09-10; Enom 2026-03 confirmed)
  nu:     { grace: 7,  redemption: 60, pendingDelete: 0,  registry: "Nunames (Niue)", confidence: "high" },
  pw:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "Afilias (Palau)", confidence: "high" },
  // .sc: Afilias (Seychelles) — IMMEDIATE, no grace or redemption (Enom 2026-03: N/N)
  sc:     { ...IMMEDIATE,                                  registry: "Afilias (Seychelles)" },
  // .mn: Afilias (Mongolia) — IMMEDIATE, deleted 2 days before expiry (Enom 2026-03: N/N)
  mn:     { ...IMMEDIATE, preExpiryDays: 2,                registry: "Afilias (Mongolia)" },
  // .fm: CentralNic (Fed. States of Micronesia) — IMMEDIATE, no grace or redemption (Enom 2026-03: N/N)
  fm:     { ...IMMEDIATE,                                  registry: "CentralNic (Micronesia)" },
  gl:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "TELE Greenland", confidence: "est" },
  vc:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "VINNIC (St Vincent)", confidence: "est" },
  // .ms: MNI Networks (Montserrat) — IMMEDIATE, no grace or redemption (Enom 2026-03: N/N)
  ms:     { ...IMMEDIATE,                                  registry: "MNI Networks (Montserrat)" },
  // .gs: CoCCA (South Georgia) — IMMEDIATE, deleted 3 days before expiry (Enom 2026-03: N/N)
  gs:     { ...IMMEDIATE, preExpiryDays: 3,                registry: "CoCCA (South Georgia)" },
  // .bz: Identity Digital (Belize) — IMMEDIATE, no grace or redemption (Enom 2026-03: N/N)
  bz:     { ...IMMEDIATE,                                  registry: "Identity Digital (Belize)" },
  ag:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "UHSA (Antigua)", confidence: "est" },
  lc:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "NATCOM (St Lucia)", confidence: "est" },
  // .to: Tonga NIC — 40-day grace, 30-day RGP, 5-day pendingDelete (Dynadot 2026-03)
  to:     { grace: 40, redemption: 30, pendingDelete: 5,  registry: "Tonga Network Info Center", confidence: "high" },
  // .vg: NIC.VG (British Virgin Islands) — 32-day grace, 30-day RGP, 5-day pendingDelete (Enom 2026-03)
  vg:     { grace: 32, redemption: 30, pendingDelete: 5,  registry: "NIC.VG (British Virgin Islands)", confidence: "high" },
  // .tc: NIC.TC (Turks & Caicos) — 32-day grace, 30-day RGP, 5-day pendingDelete (Enom 2026-03)
  tc:     { grace: 32, redemption: 30, pendingDelete: 5,  registry: "NIC.TC (Turks & Caicos)", confidence: "high" },
  vi:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "US VI NIC", confidence: "est" },
  pr:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "Puerto Rico NIC", confidence: "est" },
  // .tk: Freenom (Tokelau) — IMMEDIATE, deleted 3 days before expiry (Enom 2026-03: N/N)
  tk:     { ...IMMEDIATE, preExpiryDays: 3,                registry: "Freenom (Tokelau)" },
  ml:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "SOTELMA (Mali)", confidence: "est" },
  ga:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "Gabon NIC", confidence: "est" },
  cf:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "CAF NIC (Cent. Africa)", confidence: "est" },

  // ── Asia-Pacific ccTLD ────────────────────────────────────────────────────
  // .cn: CNNIC — no registry grace, 15-day RGP, 5-day pendingDelete (Dynadot restore=15, 2026-03)
  cn:     { ...CNNIC },
  // .tw: TWNIC — 32-day grace, no RGP, 10-day pendingDelete (Dynadot 2026-03)
  tw:     { grace: 32, redemption: 0,  pendingDelete: 10, registry: "TWNIC",  confidence: "high" },
  // .hk: HKIRC — 30-day grace, 60-day RGP, no pendingDelete (Dynadot 2026-03; total window 90d)
  hk:     { ...HKIRC },
  mo:     { grace: 0,  redemption: 30, pendingDelete: 5,  registry: "MONIC (Macau)", confidence: "est" },
  jp:     { ...JPRS },
  kr:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "KISA",   confidence: "high" },
  // .sg: SGNIC (Singapore) — no grace, 14-day RGP, no pendingDelete (Enom 2026-03: N/14; 10d pre-expiry deletion)
  sg:     { grace: 0,  redemption: 14, pendingDelete: 0,  registry: "SGNIC",  confidence: "high",
            preExpiryDays: 10, dropHour: 0, dropMinute: 0, dropSecond: 0, dropTimezone: "Asia/Singapore" },
  my:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "MYNIC",  confidence: "high" },
  // .ph: PH Domains Foundation — 50-day grace, no redemption, no pendingDelete (Dynadot 2026-03)
  ph:     { grace: 50, redemption: 0,  pendingDelete: 0,  registry: "PH Domains", confidence: "high" },
  // .id: PANDI — 40-day grace, 30-day RGP, 5-day pendingDelete (Dynadot 2026-03)
  id:     { grace: 40, redemption: 30, pendingDelete: 5,  registry: "PANDI",  confidence: "high" },
  vn:     { grace: 0,  redemption: 30, pendingDelete: 0,  registry: "VNNIC",  confidence: "high" },
  th:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "THNIC",  confidence: "high" },
  mm:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Myanmar NIC", confidence: "est" },
  kh:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NiC.KH", confidence: "est" },
  bn:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "BNNIC",  confidence: "est" },
  tl:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC.TL (Timor-Leste)", confidence: "est" },
  // .au: auDA — no grace, 31-day RGP, 5-day pendingDelete (Enom 2026-03: N/31; 10d pre-expiry deletion)
  au:     { grace: 0,  redemption: 31, pendingDelete: 5,  registry: "auDA",   confidence: "high",
            preExpiryDays: 10, dropHour: 0, dropMinute: 0, dropSecond: 0, dropTimezone: "Australia/Sydney" },
  // .nz: InternetNZ — no grace, 90-day RGP, 5-day pendingDelete (Enom 2026-03: N/90; 3d pre-expiry deletion)
  nz:     { grace: 0,  redemption: 90, pendingDelete: 5,  registry: "InternetNZ", confidence: "high",
            preExpiryDays: 3, dropHour: 0, dropMinute: 0, dropSecond: 0, dropTimezone: "Pacific/Auckland" },
  // .in: NIXI — 30-day grace, 30-day RGP, 5-day pendingDelete (Enom 2026-03: 30/30; Deleted 30d before expiry)
  in:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "NIXI",   confidence: "high",
            preExpiryDays: 30 },
  pk:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "PKNIC",  confidence: "est" },
  bd:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "BTCL",   confidence: "est" },
  lk:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "LK Domain Registry", confidence: "est" },
  np:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Mercantile",   confidence: "est" },
  ir:     { grace: 0,  redemption: 0,  pendingDelete: 0,  registry: "IRNIC",  confidence: "est" },
  iq:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC.iq",  confidence: "est" },
  il:     { grace: 60, redemption: 0,  pendingDelete: 0,  registry: "ISOC-IL", confidence: "high" },
  // .ae: aeDA — 20-day grace, no RGP, no pendingDelete (Dynadot 2026-03)
  ae:     { grace: 20, redemption: 0,  pendingDelete: 0,  registry: "aeDA",   confidence: "high" },
  sa:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "SaudiNIC", confidence: "est" },
  kw:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "CITRA (Kuwait)", confidence: "est" },
  om:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "TRA (Oman)", confidence: "est" },
  qa:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "ictQATAR", confidence: "est" },
  jo:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NITC (Jordan)", confidence: "est" },
  lb:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "OGERO (Lebanon)", confidence: "est" },
  ye:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "TeleYemen", confidence: "est" },
  sy:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "SCS-NET (Syria)", confidence: "est" },
  ps:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "PNINA (Palestine)", confidence: "est" },
  fj:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "University of S. Pacific (Fiji)", confidence: "est" },
  pg:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Papua New Guinea NIC", confidence: "est" },
  sb:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Solomon Islands NIC", confidence: "est" },
  vu:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "VANUATU NIC", confidence: "est" },
  ki:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Kiribati NIC", confidence: "est" },
  nr:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Cenpac.net.nr (Nauru)", confidence: "est" },
  ck:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Telecom Cook Islands", confidence: "est" },
  wf:     { ...AFNIC },
  pf:     { ...AFNIC,  registry: "AFNIC (French Polynesia)" },
  nc:     { ...AFNIC,  registry: "AFNIC (New Caledonia)" },
  as:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "AS NIC (American Samoa)", confidence: "est" },

  // ── Europe ccTLD ──────────────────────────────────────────────────────────
  uk:     { ...NOMINET },
  // .de: DENIC — no grace, 30-day RGP, 25-day pendingDelete (Enom 2026-03: N/30; 1d pre-expiry deletion)
  // Drop: 05:00 Europe/Berlin on day 1 of pendingDelete phase (DENIC documented schedule)
  de:     { grace: 0,  redemption: 30, pendingDelete: 25, registry: "DENIC",  confidence: "high",
            preExpiryDays: 1, dropHour: 5, dropMinute: 0, dropSecond: 0, dropTimezone: "Europe/Berlin" },
  fr:     { ...AFNIC },
  pm:     { ...AFNIC },
  re:     { ...AFNIC },
  tf:     { ...AFNIC },
  yt:     { ...AFNIC },
  gp:     { ...AFNIC,  registry: "AFNIC (Guadeloupe)" },
  mq:     { ...AFNIC,  registry: "AFNIC (Martinique)" },
  // .nl: SIDN — no grace, 30-day RGP, no pendingDelete (Enom 2026-03; 3d pre-expiry deletion)
  nl:     { grace: 0,  redemption: 30, pendingDelete: 0,  registry: "SIDN",   confidence: "high",
            preExpiryDays: 3, dropHour: 0, dropMinute: 0, dropSecond: 0, dropTimezone: "UTC" },
  // .eu: EURid — no grace, 30-day RGP, no pendingDelete (Enom 2026-03; 3d pre-expiry deletion)
  eu:     { grace: 0,  redemption: 30, pendingDelete: 0,  registry: "EURid",  confidence: "high",
            preExpiryDays: 3 },
  // .es: Red.es — no grace, 14-day RGP only, no pendingDelete (Enom 2026-03; 12d pre-expiry deletion)
  es:     { grace: 0,  redemption: 14, pendingDelete: 0,  registry: "Red.es", confidence: "high",
            preExpiryDays: 12 },
  // .it: Registro.it — grace=10d, 30-day RGP, no pendingDelete (Dynadot 2026-03; NOT immediate)
  it:     { grace: 10, redemption: 30, pendingDelete: 0,  registry: "Registro.it", confidence: "high" },
  // .pl: NASK — no grace, 30-day RGP, no pendingDelete (Dynadot 2026-03; NOT immediate)
  pl:     { grace: 0,  redemption: 30, pendingDelete: 0,  registry: "NASK",   confidence: "high" },
  se:     { ...IMMEDIATE,                                  registry: "IIS"     },
  // .no: Norid — 89-day grace, no RGP, no pendingDelete (Dynadot 2026-03; NOT immediate)
  no:     { grace: 89, redemption: 0,  pendingDelete: 0,  registry: "Norid",  confidence: "high" },
  fi:     { ...IMMEDIATE,                                  registry: "Traficom" },
  dk:     { ...IMMEDIATE,                                  registry: "DK Hostmaster" },
  // .be: DNS Belgium — no grace, 30-day RGP, no pendingDelete (Enom 2026-03: N/30; 3d pre-expiry deletion)
  be:     { grace: 0,  redemption: 30, pendingDelete: 0,  registry: "DNS Belgium", confidence: "high",
            preExpiryDays: 3 },
  at:     { ...IMMEDIATE,                                  registry: "nic.at"  },
  // .ch: SWITCH — no grace, 14-day RGP, no pendingDelete (Enom 2026-03: N/14; 10d pre-expiry deletion)
  ch:     { grace: 0,  redemption: 14, pendingDelete: 0,  registry: "SWITCH", confidence: "high",
            preExpiryDays: 10 },
  // .li: NIC.LI — no grace, 14-day RGP, no pendingDelete (Enom 2026-03: N/14; 10d pre-expiry deletion)
  li:     { grace: 0,  redemption: 14, pendingDelete: 0,  registry: "NIC.LI (Liechtenstein)", confidence: "high" },
  // .pt: DNS.PT — 29-day grace, no RGP, no pendingDelete (Dynadot 2026-03)
  pt:     { grace: 29, redemption: 0,  pendingDelete: 0,  registry: "DNS.PT", confidence: "high" },
  // .ie: IEDR — 30-day grace, 30-day RGP, 14-day pendingDelete (Dynadot 2026-03; NOT immediate)
  ie:     { grace: 30, redemption: 30, pendingDelete: 14, registry: "IEDR",   confidence: "high" },
  is:     { ...IMMEDIATE,                                  registry: "ISNIC"   },
  // .cz: CZ.NIC — 59-day grace, no RGP, no pendingDelete (Dynadot 2026-03)
  cz:     { grace: 59, redemption: 0,  pendingDelete: 0,  registry: "CZ.NIC", confidence: "high" },
  sk:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "SK-NIC", confidence: "est" },
  hu:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "ISZT",   confidence: "est" },
  // .ro: RoTLD — 80-day grace, no RGP, no pendingDelete (Dynadot 2026-03)
  ro:     { grace: 80, redemption: 0,  pendingDelete: 0,  registry: "RoTLD",  confidence: "high" },
  bg:     { grace: 30, redemption: 0,  pendingDelete: 5,  registry: "Register.BG", confidence: "est" },
  hr:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "CARNet", confidence: "est" },
  si:     { ...IMMEDIATE,                                  registry: "ARNES"   },
  rs:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "RNIDS (Serbia)", confidence: "est" },
  ba:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "UTIC (Bosnia)", confidence: "est" },
  mk:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "MARnet (N.Macedonia)", confidence: "est" },
  al:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "AKEP (Albania)", confidence: "est" },
  gr:     { grace: 30, redemption: 0,  pendingDelete: 5,  registry: "ICS.FORTH (Greece)", confidence: "est" },
  cy:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "CYNIC",  confidence: "est" },
  mt:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC.mt", confidence: "est" },
  lu:     { grace: 30, redemption: 0,  pendingDelete: 5,  registry: "RESTENA (Luxembourg)", confidence: "est" },
  // .lt: DOMREG.lt — no grace, 30-day RGP, no pendingDelete (Dynadot 2026-03)
  lt:     { grace: 0,  redemption: 30, pendingDelete: 0,  registry: "DOMREG.lt", confidence: "high" },
  // .lv: NIC.lv — no grace, 30-day RGP, no pendingDelete (Dynadot 2026-03)
  lv:     { grace: 0,  redemption: 30, pendingDelete: 0,  registry: "NIC.lv (Latvia)", confidence: "high" },
  ee:     { ...IMMEDIATE,                                  registry: "EENet (Estonia)" },
  md:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "MoldData", confidence: "est" },
  by:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "HOSTER.BY", confidence: "est" },
  ua:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "HOSTMASTER.UA", confidence: "est" },
  ru:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "RIPN",   confidence: "high" },
  su:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "RIPN",   confidence: "high" },
  kz:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "KAZDOMAIN", confidence: "est" },
  uz:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "UzNIC",  confidence: "est" },
  kg:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "TDDKK (Kyrgyzstan)", confidence: "est" },
  tj:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "TLD.tj (Tajikistan)", confidence: "est" },
  // .tm: NIC.TM (Turkmenistan) — IMMEDIATE, no grace or redemption (Enom 2026-03: N/N)
  tm:     { ...IMMEDIATE,                                  registry: "NIC.TM (Turkmenistan)" },
  az:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "AZNIC (Azerbaijan)", confidence: "est" },
  ge:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC.ge (Georgia)", confidence: "est" },
  // .am: AMNIC (Armenia) — IMMEDIATE, deleted 3 days before expiry (Enom 2026-03: N/N)
  am:     { ...IMMEDIATE,                                  registry: "AMNIC (Armenia)" },
  tr:     { ...IMMEDIATE,                                  registry: "NIC TR"  },
  fo:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Faroese NIC", confidence: "est" },
  mc:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Monaco", confidence: "est" },
  sm:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Sec. of State (San Marino)", confidence: "est" },
  ad:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Andorra Telecom", confidence: "est" },
  gi:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Sapphire Networks (Gibraltar)", confidence: "est" },
  im:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "Domicilium (Isle of Man)", confidence: "est" },
  xk:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "IKOSOVA (Kosovo)", confidence: "est" },

  // ── Americas ccTLD ────────────────────────────────────────────────────────
  // .ca: CIRA — 30-day grace, 30-day RGP, 5-day pendingDelete (Enom 2026-03: 30/30)
  ca:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "CIRA",   confidence: "high" },
  br:     { ...REGISTROBR },
  mx:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "NIC México", confidence: "high" },
  ar:     { ...NICAR },
  // .cl: NIC Chile — 10-day grace, 30-day RGP, 10-day pendingDelete (Dynadot 2026-03; NOT immediate)
  cl:     { grace: 10, redemption: 30, pendingDelete: 10, registry: "NIC Chile", confidence: "high" },
  // .pe: Punto.PE (Peru) — no grace, 10-day RGP, 5-day pendingDelete (Enom 2026-03: N/10; 10d pre-expiry)
  pe:     { grace: 0,  redemption: 10, pendingDelete: 5,  registry: "Punto.PE", confidence: "high" },
  ec:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC.ec (Ecuador)", confidence: "est" },
  bo:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "ADSIB (Bolivia)", confidence: "est" },
  py:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC.PY (Paraguay)", confidence: "est" },
  uy:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "ANTEL (Uruguay)", confidence: "est" },
  ve:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Venezuela", confidence: "est" },
  cr:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Costa Rica", confidence: "est" },
  gt:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "UVG (Guatemala)", confidence: "est" },
  // .hn: NIC.HN (Honduras) — 30-day grace, 30-day RGP, 5-day pendingDelete (Enom 2026-03: 30/30)
  hn:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "NIC.HN (Honduras)", confidence: "high" },
  ni:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "UNI-NIC (Nicaragua)", confidence: "est" },
  sv:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "SVNET (El Salvador)", confidence: "est" },
  pa:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Panama", confidence: "est" },
  do:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "INDOTEL (Dominican Republic)", confidence: "est" },
  cu:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "MINCOM (Cuba)", confidence: "est" },
  ht:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "CONATEL (Haiti)", confidence: "est" },
  jm:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NICT (Jamaica)", confidence: "est" },
  tt:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "TTNIC (Trinidad)", confidence: "est" },
  gd:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "MHC (Grenada)", confidence: "est" },
  dm:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "DM Registry (Dominica)", confidence: "est" },
  bb:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Barbados NIC", confidence: "est" },
  ky:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "ICTA (Cayman Islands)", confidence: "est" },
  bm:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Bermuda NIC", confidence: "est" },
  bs:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "BNICA (Bahamas)", confidence: "est" },
  kn:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "MHC (St Kitts)", confidence: "est" },
  fk:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Falkland Islands NIC", confidence: "est" },
  sr:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Parbo NIC (Suriname)", confidence: "est" },
  aw:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "SETAR (Aruba)", confidence: "est" },
  cw:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "UoNA (Curaçao)", confidence: "est" },
  sx:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "SX Registry (Sint Maarten)", confidence: "est" },

  // ── Africa / Middle-East ccTLD ────────────────────────────────────────────
  za:     { ...IMMEDIATE,                                  registry: "ZADNA"   },
  ng:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "NIRA (Nigeria)", confidence: "est" },
  ke:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "KENIC (Kenya)", confidence: "est" },
  gh:     { grace: 30, redemption: 30, pendingDelete: 5,  registry: "NCA (Ghana)", confidence: "est" },
  tz:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "TZNIC (Tanzania)", confidence: "est" },
  ug:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "UIXP (Uganda)", confidence: "est" },
  rw:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "RICTA (Rwanda)", confidence: "est" },
  et:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "EthiopTelecom", confidence: "est" },
  eg:     { ...IMMEDIATE,                                  registry: "NTRA (Egypt)" },
  ma:     { ...IMMEDIATE,                                  registry: "ANRT (Morocco)" },
  tn:     { ...IMMEDIATE,                                  registry: "ATI (Tunisia)" },
  dz:     { ...IMMEDIATE,                                  registry: "ENIC (Algeria)" },
  ly:     { ...IMMEDIATE,                                  registry: "LYNIC (Libya)" },
  sd:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "SUDATEL (Sudan)", confidence: "est" },
  // .cm: NIC-Cameroon — IMMEDIATE (expires = deleted same day; no grace, no RGP — Namecheap 2025-09-10)
  cm:     { ...IMMEDIATE,                                  registry: "NIC-Cameroon" },
  sn:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Senegal", confidence: "est" },
  ci:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC CI (Côte d'Ivoire)", confidence: "est" },
  mz:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC.mz (Mozambique)", confidence: "est" },
  zw:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "POTRAZ (Zimbabwe)", confidence: "est" },
  zm:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "ZICTA (Zambia)", confidence: "est" },
  ao:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Angola NIC", confidence: "est" },
  bi:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Burundi", confidence: "est" },
  bj:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Bénin", confidence: "est" },
  bf:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "ARCE (Burkina Faso)", confidence: "est" },
  td:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Chad", confidence: "est" },
  cg:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Congo", confidence: "est" },
  cd:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "ICPTC (DR Congo)", confidence: "est" },
  gq:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Equatorial Guinea", confidence: "est" },
  gw:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Guinea-Bissau", confidence: "est" },
  mr:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Mauritania", confidence: "est" },
  ne:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Niger", confidence: "est" },
  tg:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Togo", confidence: "est" },
  bw:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "BOCRA (Botswana)", confidence: "est" },
  na:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NAN (Namibia)", confidence: "est" },
  ls:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "LNDC (Lesotho)", confidence: "est" },
  sz:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "SPTC (Eswatini)", confidence: "est" },
  mw:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Malawi NIC", confidence: "est" },
  mg:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Madagascar", confidence: "est" },
  // .mu: ICTA (Mauritius) — 40-day grace, 30-day RGP, 5-day pendingDelete (Enom 2026-03: 40/30)
  mu:     { grace: 40, redemption: 30, pendingDelete: 5,  registry: "ICTA (Mauritius)", confidence: "high" },
  km:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Comoros", confidence: "est" },
  so:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Somalia NIC", confidence: "est" },
  dj:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Djibouti", confidence: "est" },
  er:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "Eritrea NIC", confidence: "est" },
  st:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC São Tomé", confidence: "est" },
  cv:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "ANAC (Cabo Verde)", confidence: "est" },
  gn:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Guinea", confidence: "est" },
  sl:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "SIERRATEL (Sierra Leone)", confidence: "est" },
  lr:     { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Liberia", confidence: "est" },
  gmb:    { grace: 30, redemption: 0,  pendingDelete: 0,  registry: "NIC Gambia", confidence: "est" },

  // ── Selected second-level domain (SLD) overrides ─────────────────────────

  // --- UK (Nominet) ---
  "co.uk":   { ...NOMINET },
  "org.uk":  { ...NOMINET },
  "me.uk":   { ...NOMINET },
  "net.uk":  { ...NOMINET },
  "ltd.uk":  { ...NOMINET },
  "plc.uk":  { ...NOMINET },

  // --- Australia (auDA) — SLDs: 30-day grace, 30-day RGP (same policy as pre-2022; bare .au differs) ---
  "com.au":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "auDA",   confidence: "high" },
  "net.au":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "auDA",   confidence: "high" },
  "org.au":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "auDA",   confidence: "high" },
  "id.au":   { grace: 30, redemption: 30, pendingDelete: 5, registry: "auDA",   confidence: "est" },
  "asn.au":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "auDA",   confidence: "est" },
  "edu.au":  { grace: 0,  redemption: 0,  pendingDelete: 0, registry: "auDA",   confidence: "high" },
  "gov.au":  { grace: 0,  redemption: 0,  pendingDelete: 0, registry: "auDA",   confidence: "high" },

  // --- China (CNNIC) — grace=0, RGP=15d, pendingDelete=5d (Dynadot 2026-03) ---
  "com.cn":  { ...CNNIC },
  "net.cn":  { ...CNNIC },
  "org.cn":  { ...CNNIC },

  // --- Taiwan (TWNIC) ---
  "com.tw":  { grace: 0,  redemption: 30, pendingDelete: 5, registry: "TWNIC",  confidence: "est" },
  "net.tw":  { grace: 0,  redemption: 30, pendingDelete: 5, registry: "TWNIC",  confidence: "est" },
  "org.tw":  { grace: 0,  redemption: 30, pendingDelete: 5, registry: "TWNIC",  confidence: "est" },
  "idv.tw":  { grace: 0,  redemption: 30, pendingDelete: 5, registry: "TWNIC",  confidence: "est" },
  "edu.tw":  { grace: 0,  redemption: 30, pendingDelete: 5, registry: "TWNIC",  confidence: "est" },
  "gov.tw":  { grace: 0,  redemption: 30, pendingDelete: 5, registry: "TWNIC",  confidence: "est" },

  // --- Hong Kong (HKIRC) — 30-day grace, 60-day RGP, no pendingDelete (Dynadot 2026-03) ---
  "com.hk":  { ...HKIRC },
  "net.hk":  { ...HKIRC },
  "org.hk":  { ...HKIRC },
  "idv.hk":  { ...HKIRC },
  "edu.hk":  { ...HKIRC },
  "gov.hk":  { ...HKIRC },

  // --- New Zealand (InternetNZ) — same policy as .nz (Enom 2026-03: grace=0, RGP=90, delete=5) ---
  "co.nz":   { grace: 0,  redemption: 90, pendingDelete: 5, registry: "InternetNZ", confidence: "high" },
  "net.nz":  { grace: 0,  redemption: 90, pendingDelete: 5, registry: "InternetNZ", confidence: "high" },
  "org.nz":  { grace: 0,  redemption: 90, pendingDelete: 5, registry: "InternetNZ", confidence: "high" },
  "school.nz":{ grace: 0, redemption: 90, pendingDelete: 5, registry: "InternetNZ", confidence: "est" },
  "govt.nz": { grace: 0,  redemption: 0,  pendingDelete: 0,  registry: "InternetNZ", confidence: "est" },

  // --- Japan (JPRS) ---
  "co.jp":   { ...JPRS },
  "or.jp":   { ...JPRS },
  "ne.jp":   { ...JPRS },
  "gr.jp":   { ...JPRS },
  "ac.jp":   { ...JPRS },
  "go.jp":   { ...JPRS },

  // --- Korea (KISA) ---
  "co.kr":   { grace: 30, redemption: 30, pendingDelete: 5, registry: "KISA",   confidence: "high" },
  "or.kr":   { grace: 30, redemption: 30, pendingDelete: 5, registry: "KISA",   confidence: "est" },

  // --- Singapore (SGNIC) — no grace, 14-day RGP, no pendingDelete (Enom 2026-03: N/14; 10d pre-expiry) ---
  "com.sg":  { grace: 0,  redemption: 14, pendingDelete: 0, registry: "SGNIC",  confidence: "high" },
  "net.sg":  { grace: 0,  redemption: 14, pendingDelete: 0, registry: "SGNIC",  confidence: "high" },
  "org.sg":  { grace: 0,  redemption: 14, pendingDelete: 0, registry: "SGNIC",  confidence: "high" },
  "edu.sg":  { grace: 0,  redemption: 14, pendingDelete: 0, registry: "SGNIC",  confidence: "high" },
  "gov.sg":  { grace: 0,  redemption: 0,  pendingDelete: 0, registry: "SGNIC",  confidence: "est" },

  // --- Malaysia (MYNIC) ---
  "com.my":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "MYNIC",  confidence: "est" },
  "net.my":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "MYNIC",  confidence: "est" },
  "org.my":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "MYNIC",  confidence: "est" },
  "edu.my":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "MYNIC",  confidence: "est" },

  // --- Philippines (PH Domains — no redemption, no pendingDelete; Dynadot 2026-03: grace=50, delete=0) ---
  "com.ph":  { grace: 50, redemption: 0,  pendingDelete: 0, registry: "PH Domains", confidence: "high" },
  "net.ph":  { grace: 50, redemption: 0,  pendingDelete: 0, registry: "PH Domains", confidence: "high" },
  "org.ph":  { grace: 50, redemption: 0,  pendingDelete: 0, registry: "PH Domains", confidence: "high" },

  // --- India (NIXI) — 30-day grace matching .in TLD (Enom 2026-03: 30/30) ---
  "co.in":   { grace: 30, redemption: 30, pendingDelete: 5, registry: "NIXI",   confidence: "high" },
  "net.in":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "NIXI",   confidence: "high" },
  "org.in":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "NIXI",   confidence: "high" },

  // --- Israel (ISOC-IL) ---
  "co.il":   { grace: 60, redemption: 0,  pendingDelete: 0, registry: "ISOC-IL", confidence: "est" },
  "org.il":  { grace: 60, redemption: 0,  pendingDelete: 0, registry: "ISOC-IL", confidence: "est" },
  "net.il":  { grace: 60, redemption: 0,  pendingDelete: 0, registry: "ISOC-IL", confidence: "est" },

  // --- South Africa (ZADNA) ---
  "co.za":   { ...IMMEDIATE, registry: "ZADNA" },
  "org.za":  { ...IMMEDIATE, registry: "ZADNA" },
  "net.za":  { ...IMMEDIATE, registry: "ZADNA" },
  "web.za":  { ...IMMEDIATE, registry: "ZADNA" },

  // --- Kenya (KENIC) ---
  "co.ke":   { grace: 30, redemption: 30, pendingDelete: 5, registry: "KENIC",  confidence: "est" },
  "or.ke":   { grace: 30, redemption: 30, pendingDelete: 5, registry: "KENIC",  confidence: "est" },
  "ne.ke":   { grace: 30, redemption: 30, pendingDelete: 5, registry: "KENIC",  confidence: "est" },

  // --- Nigeria (NIRA) ---
  "com.ng":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "NIRA (Nigeria)", confidence: "est" },
  "org.ng":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "NIRA (Nigeria)", confidence: "est" },
  "net.ng":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "NIRA (Nigeria)", confidence: "est" },

  // --- Brazil (Registro.br — immediate) ---
  "com.br":  { ...REGISTROBR },
  "net.br":  { ...REGISTROBR },
  "org.br":  { ...REGISTROBR },
  "edu.br":  { ...REGISTROBR },
  "gov.br":  { ...REGISTROBR },

  // --- Mexico (NIC México) — com.mx: 40-day grace, no RGP (Enom 2026-03: 40/N; only COM.MX offered) ---
  "com.mx":  { grace: 40, redemption: 0,  pendingDelete: 0, registry: "NIC México", confidence: "high" },
  "org.mx":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "NIC México", confidence: "est" },
  "net.mx":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "NIC México", confidence: "est" },

  // --- Argentina (NIC Argentina — immediate) ---
  "com.ar":  { ...NICAR },
  "net.ar":  { ...NICAR },
  "org.ar":  { ...NICAR },

  // --- Colombia ---
  "com.co":  { grace: 45, redemption: 30, pendingDelete: 5, registry: "NIC Colombia", confidence: "est" },

  // --- Peru (Punto.PE) — no grace, 10-day RGP (Enom 2026-03: N/10; 10d pre-expiry deletion) ---
  "com.pe":  { grace: 0,  redemption: 10, pendingDelete: 5, registry: "Punto.PE", confidence: "high" },

  // --- Ukraine ---
  "com.ua":  { grace: 30, redemption: 30, pendingDelete: 5, registry: "HOSTMASTER.UA", confidence: "est" },

  // --- Turkey (NIC TR — immediate) ---
  "com.tr":  { ...IMMEDIATE, registry: "NIC TR" },
  "org.tr":  { ...IMMEDIATE, registry: "NIC TR" },
  "net.tr":  { ...IMMEDIATE, registry: "NIC TR" },

  // --- Venezuela ---
  "com.ve":  { grace: 30, redemption: 0,  pendingDelete: 0, registry: "NIC Venezuela", confidence: "est" },

  // --- Mauritius SLDs (ICTA) — same policy as .mu (Enom 2026-03: 40/30) ---
  "com.mu":  { grace: 40, redemption: 30, pendingDelete: 5, registry: "ICTA (Mauritius)", confidence: "high" },
  "net.mu":  { grace: 40, redemption: 30, pendingDelete: 5, registry: "ICTA (Mauritius)", confidence: "high" },
  "org.mu":  { grace: 40, redemption: 30, pendingDelete: 5, registry: "ICTA (Mauritius)", confidence: "high" },

};

export const DEFAULT_LIFECYCLE: TldLifecycle = {
  grace: 45,
  redemption: 30,
  pendingDelete: 5,
  confidence: "est",
};

/** Get lifecycle config for a domain (by TLD), with optional admin overrides applied first. */
export function getTldLifecycle(domain: string, overrides?: Record<string, TldLifecycle>): TldLifecycle {
  const parts = domain.toLowerCase().split(".");
  const tld = parts.pop() ?? "";
  // Check for two-level ccTLD (e.g., co.uk) — not common but handle
  const twoLevel = parts.length > 0 ? `${parts[parts.length - 1]}.${tld}` : "";
  // Admin DB overrides take priority
  if (overrides) {
    if (twoLevel && overrides[twoLevel]) return overrides[twoLevel];
    if (overrides[tld]) return overrides[tld];
  }
  if (twoLevel && LIFECYCLE_TABLE[twoLevel]) return LIFECYCLE_TABLE[twoLevel];
  return LIFECYCLE_TABLE[tld] ?? DEFAULT_LIFECYCLE;
}

export type LifecyclePhase = "active" | "grace" | "redemption" | "pendingDelete" | "dropped";

export interface LifecycleInfo {
  phase: LifecyclePhase;
  expiry: Date;
  graceEnd: Date;
  redemptionEnd: Date;
  dropDate: Date;
  cfg: TldLifecycle;
  tld: string;
  /** Days remaining until expiry (negative when past expiry) */
  daysToExpiry: number;
  /** Whether the phase was overridden from EPP status (more accurate) */
  phaseSource: "epp" | "dates";
}

/**
 * Map EPP status codes to a lifecycle phase.
 * Returns null if no phase-specific EPP code is detected.
 * EPP codes: https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en
 */
export function getPhaseFromEppStatus(eppStatuses: string[]): LifecyclePhase | null {
  if (!eppStatuses || eppStatuses.length === 0) return null;
  const normalized = eppStatuses.map((s) =>
    s.toLowerCase().replace(/[\s_-]/g, "").split(/\s+/)[0]
  );
  // Most specific first
  if (normalized.some((s) => s.includes("pendingdelete"))) return "pendingDelete";
  if (normalized.some((s) => s.includes("pendingpurge"))) return "pendingDelete";
  if (normalized.some((s) => s.includes("redemptionperiod"))) return "redemption";
  if (normalized.some((s) => s.includes("pendingrestore"))) return "redemption";
  if (normalized.some((s) => s.includes("autorenewperiod"))) return "grace";
  if (normalized.some((s) => s.includes("addperiod"))) return "grace";
  return null;
}

/** Compute the full lifecycle for a domain, optionally overriding phase with EPP status. */
export function computeLifecycle(
  domain: string,
  expirationDate: string | null,
  eppStatuses?: string[],
  overrides?: Record<string, TldLifecycle>
): LifecycleInfo | null {
  if (!expirationDate) return null;
  const expiry = new Date(expirationDate);
  if (isNaN(expiry.getTime())) return null;

  const tld = domain.split(".").pop()?.toLowerCase() ?? "";
  const cfg = getTldLifecycle(domain, overrides);
  const ms = (d: number) => d * 86_400_000;
  const graceEnd = new Date(expiry.getTime() + ms(cfg.grace));
  const redemptionEnd = new Date(graceEnd.getTime() + ms(cfg.redemption));
  const dropDate = new Date(redemptionEnd.getTime() + ms(cfg.pendingDelete));
  const now = new Date();
  const daysToExpiry = Math.ceil((expiry.getTime() - now.getTime()) / 86_400_000);

  // Try EPP override first
  const eppPhase = eppStatuses ? getPhaseFromEppStatus(eppStatuses) : null;

  let phase: LifecyclePhase;
  let phaseSource: "epp" | "dates" = "dates";

  if (eppPhase) {
    phase = eppPhase;
    phaseSource = "epp";
  } else {
    if (now < expiry) phase = "active";
    else if (now < graceEnd) phase = "grace";
    else if (now < redemptionEnd) phase = "redemption";
    else if (now < dropDate) phase = "pendingDelete";
    else phase = "dropped";
  }

  return { phase, expiry, graceEnd, redemptionEnd, dropDate, cfg, tld, daysToExpiry, phaseSource };
}

/** Format a Date to YYYY/MM/DD (UTC). Used in emails and short displays. */
export function fmtDate(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}/${pad(d.getUTCMonth() + 1)}/${pad(d.getUTCDate())}`;
}

/** Format a Date to YYYY/MM/DD HH:mm:ss UTC (full precision). */
export function fmtDateTime(d: Date, showTz = true): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  const date = `${d.getUTCFullYear()}/${pad(d.getUTCMonth() + 1)}/${pad(d.getUTCDate())}`;
  const time = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
  return showTz ? `${date} ${time} UTC` : `${date} ${time}`;
}

/**
 * Humanised countdown with hours precision when ≤ 7 days remain.
 * Returns e.g. "40天" or "3天14小时" or "5小时20分".
 */
export function fmtCountdown(targetDate: Date, isZh = true): string {
  const ms = targetDate.getTime() - Date.now();
  if (ms <= 0) return isZh ? "已过期" : "expired";
  const totalMins = Math.floor(ms / 60_000);
  const days = Math.floor(totalMins / 1440);
  const hours = Math.floor((totalMins % 1440) / 60);
  const mins = totalMins % 60;
  if (days >= 7) return isZh ? `${days}天` : `${days}d`;
  if (days > 0)  return isZh ? `${days}天${hours}小时` : `${days}d ${hours}h`;
  if (hours > 0) return isZh ? `${hours}小时${mins}分` : `${hours}h ${mins}m`;
  return isZh ? `${mins}分钟` : `${mins}min`;
}

/**
 * Format a nullable date string for locale-aware display.
 * Returns "—" for null/invalid/"Unknown" values.
 * Used in the remind page and other UI that shows subscription dates.
 */
export function fmtLocalDate(raw: string | null, locale: string): string {
  if (!raw || raw === "Unknown") return "—";
  const d = new Date(raw);
  if (isNaN(d.getTime())) return raw;
  return d.toLocaleDateString(locale, { year: "numeric", month: "2-digit", day: "2-digit" });
}

/**
 * Format a nullable date string as a relative time description using i18n keys.
 * Returns null for null/invalid/"Unknown" values.
 * Used in the remind page to show "3 days ago", "2 months ago", etc.
 */
export function fmtRelativeDate(raw: string | null, t: (k: string) => string): string | null {
  if (!raw || raw === "Unknown") return null;
  const d = new Date(raw);
  if (isNaN(d.getTime())) return null;
  const diffDays = Math.round((Date.now() - d.getTime()) / 86_400_000);
  if (diffDays < 1) return t("remind.today");
  if (diffDays < 30) return t("remind.days_ago").replace("{{n}}", String(diffDays));
  const months = Math.round(diffDays / 30);
  if (months < 12) return t("remind.months_ago").replace("{{n}}", String(months));
  const years = Math.floor(diffDays / 365);
  const remMonths = Math.round((diffDays % 365) / 30);
  return remMonths > 0
    ? t("remind.years_months_ago").replace("{{n}}", String(years)).replace("{{m}}", String(remMonths))
    : t("remind.years_ago").replace("{{n}}", String(years));
}

/**
 * Format a days-remaining count as a human-readable string using i18n keys.
 * Handles expired (negative), days, months, and years.
 * Used in the remind page subscription cards.
 */
export function fmtDaysRemainingText(days: number, t: (k: string) => string): string {
  if (days <= 0) return t("remind.expired_n_days").replace("{{n}}", String(Math.abs(days)));
  if (days < 30) return t("remind.expires_in_days").replace("{{n}}", String(days));
  if (days < 365) {
    const months = Math.floor(days / 30);
    const rem = days % 30;
    return rem > 0
      ? t("remind.expires_in_months_days").replace("{{n}}", String(months)).replace("{{d}}", String(rem))
      : t("remind.expires_in_months").replace("{{n}}", String(months));
  }
  const years = Math.floor(days / 365);
  const remDays = days % 365;
  const months = Math.floor(remDays / 30);
  if (months > 0) return t("remind.expires_in_years_months").replace("{{n}}", String(years)).replace("{{m}}", String(months));
  return t("remind.expires_in_years").replace("{{n}}", String(years));
}

export const PHASE_META = {
  active:        { zh: "正常有效", en: "Active",         color: "#059669", bg: "#ecfdf5" },
  grace:         { zh: "宽限期",   en: "Grace Period",   color: "#d97706", bg: "#fffbeb" },
  redemption:    { zh: "赎回期",   en: "Redemption",     color: "#ea580c", bg: "#fff7ed" },
  pendingDelete: { zh: "待删除",   en: "Pending Delete", color: "#dc2626", bg: "#fef2f2" },
  dropped:       { zh: "已释放",   en: "Available",      color: "#6b7280", bg: "#f9fafb" },
} as const;
