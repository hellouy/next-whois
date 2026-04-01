/**
 * Thin query helpers that wrap the pg Pool returned by getDbReady().
 * Provides one<T>, many<T>, and run() to replace Supabase ORM calls.
 */
import { getDbReady } from "./db";

/** Run a SELECT and return the first row, or null if no rows found. */
export async function one<T = Record<string, any>>(
  sql: string,
  params?: any[],
): Promise<T | null> {
  const db = await getDbReady();
  if (!db) return null;
  const result = await db.query(sql, params);
  return (result.rows[0] as T) ?? null;
}

/** Run a SELECT and return all matching rows. */
export async function many<T = Record<string, any>>(
  sql: string,
  params?: any[],
): Promise<T[]> {
  const db = await getDbReady();
  if (!db) return [];
  const result = await db.query(sql, params);
  return result.rows as T[];
}

/**
 * Run an INSERT / UPDATE / DELETE and return the number of rows affected.
 * Returns -1 when the database is unavailable.
 */
export async function run(sql: string, params?: any[]): Promise<number> {
  const db = await getDbReady();
  if (!db) return -1;
  const result = await db.query(sql, params);
  return result.rowCount ?? 0;
}

/** Convenience: return true when the db is reachable (pool not null). */
export async function isDbReady(): Promise<boolean> {
  try {
    const db = await getDbReady();
    return db !== null;
  } catch {
    return false;
  }
}
