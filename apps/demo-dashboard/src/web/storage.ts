/**
 * Where the policy opening lives at rest in Phase 3: this origin's IndexedDB, in the policy
 * owner's browser. The agent runs in a separate, sandboxed process with no file or network access,
 * so it cannot read it; the tool server never receives it. The opening leaves the browser only to
 * arm the firewall, which keeps it in memory.
 *
 * This is not custody fit for real funds: anything running as the same OS user, or with access to
 * the browser profile, can read IndexedDB. Phase 5's hosted version needs encrypted server-side
 * custody instead (see the README).
 */
import type { PolicyOpeningWire } from '../shared/api.ts';
import type { ScopeName } from '../shared/demo-config.ts';

export interface StoredPayee {
  readonly label: string;
  readonly account: string;
}

export interface StoredPolicy {
  readonly policyCommitment: string;
  readonly name: string;
  /** ISO time. */
  readonly createdAt: string;
  /** The human-readable definition, for display. */
  readonly definition: {
    readonly maxAmountUsdc: string;
    readonly payees: readonly StoredPayee[];
    readonly scopes: readonly ScopeName[];
    /** Unix seconds. */
    readonly expiry: string;
  };
  /** The secret: everything the prover needs. */
  readonly opening: PolicyOpeningWire;
}

const DB = 'zkif-dashboard';
const STORE = 'policies';

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: 'policyCommitment' });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB unavailable'));
  });
}

async function tx<T>(mode: IDBTransactionMode, f: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const r = f(db.transaction(STORE, mode).objectStore(STORE));
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error ?? new Error('IndexedDB request failed'));
    });
  } finally {
    db.close();
  }
}

export async function listPolicies(): Promise<StoredPolicy[]> {
  const all = await tx<StoredPolicy[]>('readonly', (s) => s.getAll() as IDBRequest<StoredPolicy[]>);
  return all.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function savePolicy(p: StoredPolicy): Promise<void> {
  await tx('readwrite', (s) => s.put(p));
}

export async function deletePolicy(policyCommitment: string): Promise<void> {
  await tx('readwrite', (s) => s.delete(policyCommitment));
}
