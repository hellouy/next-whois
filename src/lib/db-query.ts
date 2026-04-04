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

/**
 * Run a sequence of queries inside a single DB transaction.
 * If the callback throws, the transaction is rolled back and the error re-thrown.
 * Returns whatever the callback returns.
 */
export async function withTransaction<T>(
  fn: (client: {
    one: <R = Record<string, any>>(sql: string, params?: any[]) => Promise<R | null>;
    many: <R = Record<string, any>>(sql: string, params?: any[]) => Promise<R[]>;
    run: (sql: string, params?: any[]) => Promise<number>;
  }) => Promise<T>,
): Promise<T> {
  const db = await getDbReady();
  if (!db) throw new Error("Database unavailable");
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const result = await fn({
      one: async <R>(sql: string, params?: any[]) => {
        const r = await client.query(sql, params);
        return (r.rows[0] as R) ?? null;
      },
      many: async <R>(sql: string, params?: any[]) => {
        const r = await client.query(sql, params);
        return r.rows as R[];
      },
      run: async (sql: string, params?: any[]) => {
        const r = await client.query(sql, params);
        return r.rowCount ?? 0;
      },
    });
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
