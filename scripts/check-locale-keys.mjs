/**
 * Locale key completeness checker — run from project root.
 *
 *   node scripts/check-locale-keys.mjs
 *
 * Exits 0 when all locale files have exactly the same keys as en.json.
 * Exits 1 when any key is missing or extra (compared to en.json as baseline).
 *
 * Use in CI:
 *   - Add to package.json scripts: "check:i18n": "node scripts/check-locale-keys.mjs"
 *   - Commit will fail if a locale key is forgotten.
 */

import { readFileSync, readdirSync } from "fs";
import { join } from "path";

const LOCALE_DIR = "locales";
const BASELINE   = "en.json";

const files = readdirSync(LOCALE_DIR)
  .filter((f) => f.endsWith(".json"))
  .sort();

if (!files.includes(BASELINE)) {
  console.error(`[i18n] Baseline file "${BASELINE}" not found in ${LOCALE_DIR}/`);
  process.exit(1);
}

const data = {};
for (const file of files) {
  const raw  = readFileSync(join(LOCALE_DIR, file), "utf8");
  const json = JSON.parse(raw);
  data[file] = new Set(Object.keys(json));
}

const baseline = data[BASELINE];
let errors = 0;
let warns  = 0;

console.log(`[i18n] Checking ${files.length} locale files against "${BASELINE}" (${baseline.size} keys)…\n`);

for (const file of files) {
  if (file === BASELINE) continue;

  const keys   = data[file];
  const missing = [...baseline].filter((k) => !keys.has(k));
  const extra   = [...keys].filter((k) => !baseline.has(k));

  if (missing.length === 0 && extra.length === 0) {
    console.log(`  ✓  ${file} (${keys.size} keys — in sync)`);
    continue;
  }

  if (missing.length > 0) {
    console.error(`  ❌ ${file} — missing ${missing.length} key(s):`);
    for (const k of missing) {
      console.error(`       - "${k}"`);
    }
    errors += missing.length;
  }

  if (extra.length > 0) {
    console.warn(`  ⚠  ${file} — ${extra.length} extra key(s) not in en.json:`);
    for (const k of extra) {
      console.warn(`       + "${k}"`);
    }
    warns += extra.length;
  }
}

console.log("");

if (errors > 0) {
  console.error(`[i18n] FAILED — ${errors} missing key(s) across locale files. Add them before committing.`);
  process.exit(1);
} else if (warns > 0) {
  console.warn(`[i18n] OK with warnings — ${warns} extra key(s) present (not a blocking error).`);
} else {
  console.log(`[i18n] All ${files.length} locale files are in sync. ✓`);
}
