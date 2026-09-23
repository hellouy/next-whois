import { describe, it, expect } from "vitest";
import { CREATE_TABLES, ALTER_COLUMNS, CREATE_INDEXES } from "./db";
import type { DropStage, DateType } from "./drop-types";

const ALL_SQL = [...CREATE_TABLES, ...ALTER_COLUMNS, ...CREATE_INDEXES].join("\n");

describe("drop calendar migration", () => {
  it("creates the drop_source_status table", () => {
    expect(ALL_SQL).toMatch(/CREATE TABLE IF NOT EXISTS drop_source_status/);
    for (const col of ["source", "enabled", "last_success_at", "last_error", "last_error_at", "items_last_run"]) {
      expect(ALL_SQL).toContain(col);
    }
  });

  it("adds every drop-calendar column idempotently", () => {
    const cols = ["drop_date", "expiry_date", "stage", "date_type", "value_score", "value_tier", "value_reasons"];
    for (const col of cols) {
      expect(ALL_SQL).toMatch(
        new RegExp(`ALTER TABLE expired_domain_leads ADD COLUMN IF NOT EXISTS ${col}\\b`),
      );
    }
  });

  it("creates the drop-calendar indexes idempotently", () => {
    for (const idx of ["idx_edl_drop_date", "idx_edl_stage", "idx_edl_value"]) {
      expect(ALL_SQL).toMatch(new RegExp(`CREATE INDEX IF NOT EXISTS ${idx}\\b`));
    }
  });

  it("keeps every additive statement guarded with IF NOT EXISTS", () => {
    for (const sql of [...CREATE_TABLES, ...ALTER_COLUMNS, ...CREATE_INDEXES]) {
      const normalized = sql.replace(/\s+/g, " ").trim().toUpperCase();
      if (normalized.startsWith("CREATE TABLE")) {
        expect(normalized).toContain("IF NOT EXISTS");
      } else if (normalized.startsWith("CREATE INDEX") || normalized.startsWith("CREATE UNIQUE INDEX")) {
        expect(normalized).toContain("IF NOT EXISTS");
      } else if (normalized.startsWith("ALTER TABLE") && normalized.includes("ADD COLUMN")) {
        expect(normalized).toContain("IF NOT EXISTS");
      }
    }
  });

  it("exposes only legal stage and date-type values", () => {
    const stages: DropStage[] = ["pending_delete", "expiring", "deleted"];
    const dateTypes: DateType[] = ["source", "derived"];
    expect(new Set(stages).size).toBe(3);
    expect(new Set(dateTypes).size).toBe(2);
    const stageDefault = ALL_SQL.match(/stage\s+TEXT NOT NULL DEFAULT '([a-z_]+)'/);
    const dateTypeDefault = ALL_SQL.match(/date_type\s+TEXT NOT NULL DEFAULT '([a-z_]+)'/);
    expect(stages).toContain(stageDefault?.[1] as DropStage);
    expect(dateTypes).toContain(dateTypeDefault?.[1] as DateType);
  });
});
