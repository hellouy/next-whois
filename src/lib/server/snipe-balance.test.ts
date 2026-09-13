import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Module mocks (before importing the service) ─────────────────────────────
const mocks = {
  many: vi.fn(),
  run: vi.fn(),
  withTransaction: vi.fn(),
  sendEmail: vi.fn(),
};

vi.mock("@/lib/db-query", () => ({
  one: (...a: unknown[]) => {
    throw new Error("one should not be called in balance tests");
  },
  many: (...a: unknown[]) => mocks.many(...a),
  run: (...a: unknown[]) => mocks.run(...a),
  withTransaction: (...a: unknown[]) => mocks.withTransaction(...a),
}));

vi.mock("@/lib/email", () => ({
  sendEmail: (...a: unknown[]) => mocks.sendEmail(...a),
  snipeArmedHtml: () => "<html></html>",
}));

import {
  freezeForSnipe,
  settleSnipeCharge,
  releaseSnipeHold,
  createUserSnipeTarget,
  cancelUserSnipeTarget,
  autoArmBlockedTargets,
  SnipeTakenError,
} from "../server/snipe-balance";

import type { TxClient } from "@/lib/db-query";

// ── In-memory fake TxClient ──────────────────────────────────────────────────
type Row = Record<string, any>;
interface State {
  users: Map<string, Row>;
  targets: Map<string, Row>;
  txs: Row[];
}
type FakeTx = TxClient & { state: State };

function findTarget(state: State, sql: string, params: unknown[]): Row | null {
  for (const row of state.targets.values()) {
    if (sql.includes("WHERE domain = $1 AND user_email = $2")) {
      if (row.domain === params[0] && row.user_email === params[1]) return { ...row };
    } else if (sql.includes("WHERE domain = $1")) {
      if (row.domain === params[0]) return { ...row };
    } else if (sql.includes("WHERE id = $1")) {
      if (row.id === params[0]) return { ...row };
    }
  }
  return null;
}

function findUser(state: State, params: unknown[]): Row | null {
  for (const row of state.users.values()) {
    if (row.email === params[0]) return row;
  }
  return null;
}

function makeTx(over: Partial<State> = {}): FakeTx {
  const state: State = {
    users: new Map(over.users),
    targets: new Map(over.targets),
    txs: over.txs ?? [],
  };

  return {
    state,
    async one<R = Record<string, any>>(sql: string, params: unknown[] = []): Promise<R | null> {
      const s = sql.trimStart();
      // create-new-target INSERT with RETURNING (id column is UUID, server-generated)
      if (s.startsWith("INSERT INTO snipe_targets") && s.includes("RETURNING id")) {
        const id = `gen-${state.targets.size + 1}`;
        state.targets.set(id, {
          id,
          domain: params[0],
          tld: params[1],
          status: "watching",
          user_email: params[2],
          service_price_cents: params[3],
          frozen_cents: 0,
          expiration_date: params[4],
        });
        return { id } as R;
      }
      // user lookup by email
      if (s.startsWith("SELECT id FROM users") && s.includes("WHERE email = $1")) {
        return (findUser(state, params) ?? null) as R | null;
      }
      // available balance read (insufficient path)
      if (s.startsWith("SELECT balance_cents FROM users") && s.includes("WHERE id = $1")) {
        return (state.users.get(params[0] as string) ?? null) as R | null;
      }
      // atomic conditional freeze (RETURNING) — mutates user balances
      if (s.startsWith("UPDATE users") && s.includes("RETURNING balance_cents")) {
        const row = state.users.get(params[0] as string);
        if (!row) return null;
        const debit = params[1] as number;
        if ((row.balance_cents as number) < debit) return null;
        row.balance_cents -= debit;
        row.frozen_cents = (row.frozen_cents as number) + debit;
        return { balance_cents: row.balance_cents } as R;
      }
      // existing snipe charge guard
      if (s.startsWith("SELECT id FROM balance_transactions") && s.includes("target_id")) {
        const type = s.match(/type = '(\w+)'/)?.[1];
        return (state.txs.find((t) => t.target_id === params[0] && t.type === type) ?? null) as R | null;
      }
      // snipe target reads (frozen_cents / hold_keys)
      if (s.startsWith("SELECT") && s.includes("FROM snipe_targets")) {
        return findTarget(state, s, params) as R | null;
      }
      return null;
    },
    async many<R = Record<string, any>>(sql: string, params: unknown[] = []): Promise<R[]> {
      if (sql.includes("FROM snipe_targets") && sql.includes("status = 'blocked_balance'")) {
        const out: Row[] = [];
        for (const row of state.targets.values()) {
          if (row.user_email === params[0] && row.status === "blocked_balance") out.push(row);
        }
        return out as R[];
      }
      return [] as R[];
    },
    async run(sql: string, params: unknown[] = []): Promise<number> {
      const s = sql.trimStart();
      if (s.startsWith("INSERT INTO balance_transactions")) {
        state.txs.push({
          user_id: params[0],
          amount_cents: params[1],
          type: params[2],
          description: params[3],
          target_id: params[4],
        });
        return 1;
      }
      // target updates — operate on the map entry directly (in-place)
      if (s.startsWith("UPDATE snipe_targets")) {
        let target: Row | null = null;
        for (const row of state.targets.values()) {
          const byId = s.includes("WHERE id = $1") && row.id === params[0];
          const byDomain = s.includes("WHERE domain = $1") && row.domain === params[0];
          if (byId || byDomain) { target = row; break; }
        }
        if (!target) return 0;
        if (s.includes("SET frozen_cents = $2, hold_keys = $3")) {
          target.frozen_cents = params[1];
          target.hold_keys = params[2];
          return 1;
        }
        if (s.includes("SET frozen_cents = 0, hold_keys = $2")) {
          target.frozen_cents = 0;
          target.hold_keys = params[1];
          return 1;
        }
        if (s.includes("SET status = 'watching'")) {
          target.status = "watching";
          return 1;
        }
        if (s.includes("SET status = 'cancelled'")) {
          if (target.status === "succeeded" || target.status === "cancelled") return 0;
          target.status = "cancelled";
          return 1;
        }
        return 1;
      }
      // user balance mutation without refund
      if (s.startsWith("UPDATE users") && s.includes("frozen_cents = frozen_cents - $2") && !s.includes("balance_cents = balance_cents + $2")) {
        const row = state.users.get(params[0] as string);
        if (!row) return 0;
        row.frozen_cents -= params[1] as number;
        return 1;
      }
      // user balance mutation with refund (release)
      if (s.startsWith("UPDATE users") && s.includes("balance_cents = balance_cents + $2")) {
        const row = state.users.get(params[0] as string);
        if (!row) return 0;
        const amt = params[1] as number;
        row.frozen_cents -= amt;
        row.balance_cents += amt;
        return 1;
      }
      return 1;
    },
  };
}

function seedUser(state: State, id: string, email: string, balance: number, frozen = 0) {
  state.users.set(id, { id, email, balance_cents: balance, frozen_cents: frozen });
}

describe("snipe-balance", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("freezeForSnipe", () => {
    it("debits the shortfall and records a hold transaction", async () => {
      const tx = makeTx();
      seedUser(tx.state, "u1", "user@example.com", 1000);
      tx.state.targets.set("t1", { id: "t1", domain: "a.example", frozen_cents: 0 });

      const result = await freezeForSnipe(tx, "t1", "user@example.com", 600);
      expect(result).toMatchObject({ ok: true, insufficient: false, frozenCents: 600 });
      expect(tx.state.users.get("u1")?.balance_cents).toBe(400);
      expect(tx.state.users.get("u1")?.frozen_cents).toBe(600);
      expect(tx.state.txs).toHaveLength(1);
      expect(tx.state.txs[0]).toMatchObject({ type: "hold", amount_cents: 600, target_id: "t1" });
      expect(tx.state.targets.get("t1")?.frozen_cents).toBe(600);
      expect(tx.state.targets.get("t1")?.hold_keys).toContain("t1:snipe");
    });

    it("does not touch money again when the full amount is already frozen", async () => {
      const tx = makeTx();
      seedUser(tx.state, "u1", "user@example.com", 1000, 600);
      tx.state.targets.set("t1", { id: "t1", domain: "a.example", frozen_cents: 600 });

      const result = await freezeForSnipe(tx, "t1", "user@example.com", 600);
      expect(result).toMatchObject({ ok: true, insufficient: false, frozenCents: 600 });
      expect(tx.state.txs).toHaveLength(0);
    });

    it("reports insufficient when balance cannot cover the shortfall and leaves funds untouched", async () => {
      const tx = makeTx();
      seedUser(tx.state, "u1", "user@example.com", 200);
      tx.state.targets.set("t1", { id: "t1", domain: "a.example", frozen_cents: 0 });

      const result = await freezeForSnipe(tx, "t1", "user@example.com", 600);
      expect(result).toMatchObject({ ok: false, insufficient: true, frozenCents: 0, balanceCents: 200 });
      expect(tx.state.users.get("u1")?.balance_cents).toBe(200);
      expect(tx.state.txs).toHaveLength(0);
    });

    it("reports insufficient when no user account exists", async () => {
      const tx = makeTx();
      tx.state.targets.set("t1", { id: "t1", domain: "a.example", frozen_cents: 0 });
      const result = await freezeForSnipe(tx, "t1", "ghost@example.com", 500);
      expect(result.insufficient).toBe(true);
      expect(tx.state.txs).toHaveLength(0);
    });
  });

  describe("settleSnipeCharge", () => {
    it("converts the frozen hold into a snipe charge and zeroes the freeze", async () => {
      const tx = makeTx({ txs: [] });
      seedUser(tx.state, "u1", "user@example.com", 0, 600);
      tx.state.targets.set("t1", {
        id: "t1",
        domain: "a.example",
        frozen_cents: 600,
        hold_keys: JSON.stringify({ hold: "t1:snipe" }),
      });

      await settleSnipeCharge(tx, "t1", "user@example.com", 600);
      expect(tx.state.users.get("u1")?.frozen_cents).toBe(0);
      expect(tx.state.txs).toHaveLength(1);
      expect(tx.state.txs[0]).toMatchObject({ type: "snipe", amount_cents: 600 });
      expect(JSON.parse(tx.state.targets.get("t1")!.hold_keys as string).charge).toBe("t1:snipe");
    });

    it("is a no-op when the snipe charge was already settled", async () => {
      const tx = makeTx({ txs: [] });
      seedUser(tx.state, "u1", "user@example.com", 0, 600);
      tx.state.targets.set("t1", { id: "t1", domain: "a.example", frozen_cents: 600 });
      tx.state.txs.push({ user_id: "u1", amount_cents: 600, type: "snipe", target_id: "t1" });

      const before = tx.state.users.get("u1")?.frozen_cents;
      await settleSnipeCharge(tx, "t1", "user@example.com", 600);
      expect(tx.state.users.get("u1")?.frozen_cents).toBe(before);
      expect(tx.state.txs).toHaveLength(1);
    });

    it("is a no-op when the user has no account", async () => {
      const tx = makeTx({ txs: [] });
      tx.state.targets.set("t1", { id: "t1", domain: "a.example", frozen_cents: 600 });
      await expect(settleSnipeCharge(tx, "t1", "ghost@example.com", 600)).resolves.toBeUndefined();
      expect(tx.state.txs).toHaveLength(0);
    });
  });

  describe("releaseSnipeHold", () => {
    it("returns frozen funds to the available balance and writes an unhold row", async () => {
      const tx = makeTx({ txs: [] });
      seedUser(tx.state, "u1", "user@example.com", 100, 600);
      tx.state.targets.set("t1", {
        id: "t1",
        domain: "a.example",
        frozen_cents: 600,
        hold_keys: JSON.stringify({ hold: "t1:snipe" }),
      });

      await releaseSnipeHold(tx, "t1", "user@example.com", 600);
      expect(tx.state.users.get("u1")?.balance_cents).toBe(700);
      expect(tx.state.users.get("u1")?.frozen_cents).toBe(0);
      expect(tx.state.txs).toHaveLength(1);
      expect(tx.state.txs[0]).toMatchObject({ type: "unhold", amount_cents: 600 });
      expect(JSON.parse(tx.state.targets.get("t1")!.hold_keys as string).unhold).toBe("t1:unhold");
    });

    it("releases at most the frozen amount", async () => {
      const tx = makeTx({ txs: [] });
      seedUser(tx.state, "u1", "user@example.com", 100, 300);
      tx.state.targets.set("t1", { id: "t1", domain: "a.example", frozen_cents: 300, hold_keys: null });

      await releaseSnipeHold(tx, "t1", "user@example.com", 600);
      expect(tx.state.users.get("u1")?.balance_cents).toBe(400);
      expect(tx.state.txs[0].amount_cents).toBe(300);
    });

    it("is a no-op once already released", async () => {
      const tx = makeTx({ txs: [] });
      seedUser(tx.state, "u1", "user@example.com", 100, 0);
      tx.state.targets.set("t1", {
        id: "t1",
        domain: "a.example",
        frozen_cents: 0,
        hold_keys: JSON.stringify({ unhold: "t1:unhold" }),
      });

      await releaseSnipeHold(tx, "t1", "user@example.com", 600);
      expect(tx.state.txs).toHaveLength(0);
    });
  });

  describe("createUserSnipeTarget", () => {
    it("creates a new watching target", async () => {
      const tx = makeTx();
      const id = await createUserSnipeTarget(tx, {
        domain: "fresh.example",
        tld: "example",
        userEmail: "user@example.com",
        serviceCents: 5000,
        expirationDate: null,
      });
      expect(id).toBeTruthy();
      expect(tx.state.targets.get(id)).toMatchObject({
        status: "watching",
        user_email: "user@example.com",
        service_price_cents: 5000,
      });
    });

    it("throws SnipeTakenError when another user already occupies the domain", async () => {
      const tx = makeTx({
        targets: new Map([["t0", {
          id: "t0",
          domain: "taken.example",
          status: "armed",
          user_email: "other@example.com",
        }]]),
      });
      await expect(createUserSnipeTarget(tx, {
        domain: "taken.example",
        tld: "example",
        userEmail: "user@example.com",
        serviceCents: 5000,
        expirationDate: null,
      })).rejects.toBeInstanceOf(SnipeTakenError);
    });

    it("throws when the domain is already occupied by an admin target", async () => {
      const tx = makeTx({
        targets: new Map([["t0", {
          id: "t0",
          domain: "admin.example",
          status: "watching",
          user_email: null,
        }]]),
      });
      await expect(createUserSnipeTarget(tx, {
        domain: "admin.example",
        tld: "example",
        userEmail: "user@example.com",
        serviceCents: 5000,
        expirationDate: null,
      })).rejects.toBeInstanceOf(SnipeTakenError);
    });
  });

  describe("cancelUserSnipeTarget", () => {
    it("releases the hold and soft-cancels", async () => {
      const tx = makeTx({ txs: [] });
      seedUser(tx.state, "u1", "user@example.com", 100, 600);
      tx.state.targets.set("t1", {
        id: "t1",
        domain: "cancel.example",
        status: "armed",
        user_email: "user@example.com",
        frozen_cents: 600,
        hold_keys: JSON.stringify({ hold: "t1:snipe" }),
      });

      const released = await cancelUserSnipeTarget(tx, {
        domain: "cancel.example",
        userEmail: "user@example.com",
      });
      expect(released).toBe(600);
      expect(tx.state.users.get("u1")?.balance_cents).toBe(700);
      expect(tx.state.users.get("u1")?.frozen_cents).toBe(0);
      expect(tx.state.targets.get("t1")?.status).toBe("cancelled");
    });

    it("is a no-op when the target belongs to a different user", async () => {
      const tx = makeTx({ txs: [] });
      tx.state.targets.set("t1", {
        id: "t1",
        domain: "other.example",
        status: "armed",
        user_email: "someone@example.com",
        frozen_cents: 600,
      });
      const released = await cancelUserSnipeTarget(tx, {
        domain: "other.example",
        userEmail: "user@example.com",
      });
      expect(released).toBe(0);
    });
  });

  describe("autoArmBlockedTargets", () => {
    it("arms a blocked target when the freeze succeeds and sends a mail", async () => {
      mocks.many.mockResolvedValue([{
        id: "t1",
        domain: "blocked.example",
        user_email: "user@example.com",
        service_price_cents: 500,
        frozen_cents: 0,
      }]);
      mocks.run.mockResolvedValue(1);

      const tx = makeTx();
      seedUser(tx.state, "u1", "user@example.com", 1000);
      tx.state.targets.set("t1", {
        id: "t1",
        domain: "blocked.example",
        status: "blocked_balance",
        user_email: "user@example.com",
        service_price_cents: 500,
        frozen_cents: 0,
      });
      mocks.withTransaction.mockImplementation(async (fn: (t: FakeTx) => unknown) => fn(tx));

      const count = await autoArmBlockedTargets("user@example.com");
      expect(mocks.withTransaction).toHaveBeenCalled();
      expect(mocks.sendEmail).toHaveBeenCalled();
      expect(count).toBe(1);
      // freeze applied to the user balance
      expect(tx.state.users.get("u1")?.frozen_cents).toBe(500);
      expect(tx.state.users.get("u1")?.balance_cents).toBe(500);
    });

    it("skips a blocked target whose freeze still fails", async () => {
      mocks.many.mockResolvedValue([{
        id: "t1",
        domain: "blocked.example",
        user_email: "user@example.com",
        service_price_cents: 500,
        frozen_cents: 0,
      }]);
      mocks.run.mockResolvedValue(1);
      const tx = makeTx();
      seedUser(tx.state, "u1", "user@example.com", 100);
      tx.state.targets.set("t1", {
        id: "t1",
        domain: "blocked.example",
        status: "blocked_balance",
        user_email: "user@example.com",
        service_price_cents: 500,
        frozen_cents: 0,
      });
      mocks.withTransaction.mockImplementation(async (fn: (t: FakeTx) => unknown) => fn(tx));

      const count = await autoArmBlockedTargets("user@example.com");
      expect(count).toBe(0);
      expect(mocks.sendEmail).not.toHaveBeenCalled();
    });
  });
});