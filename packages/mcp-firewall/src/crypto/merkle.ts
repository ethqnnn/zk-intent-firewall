/**
 * The recipient allowlist tree (docs/circuit-spec.md, section 5.6): binary, fixed depth 20, empty
 * positions hold 0, empty subtrees of height h hold Z[h]. Only the occupied prefix is stored.
 */
import { MAX_LEAVES, TREE_DEPTH } from './constants.js';
import { assertField } from './field.js';
import type { ProtocolHasher } from './hash.js';

export interface MerkleWitness {
  /** u32, below 2^20. Position of the recipient's leaf. */
  readonly leafIndex: number;
  /** Sibling hashes, from the leaf level up. Exactly TREE_DEPTH entries. */
  readonly path: readonly bigint[];
}

/**
 * How recipients are placed. `sorted` (the default, as the spec recommends) places the distinct
 * recipients at positions 0 ... n-1 in ascending order of field value, so the root depends only on
 * the set. `insertion` keeps the given order, which is how the fixtures were built.
 */
export type AllowlistOrder = 'sorted' | 'insertion';

export class AllowlistTree {
  readonly #levels: readonly (readonly bigint[])[];
  readonly #positions: ReadonlyMap<bigint, number>;
  readonly #zero: readonly bigint[];
  readonly recipients: readonly bigint[];
  readonly root: bigint;

  private constructor(recipients: bigint[], levels: bigint[][], zero: readonly bigint[]) {
    this.recipients = Object.freeze(recipients);
    this.#levels = levels;
    this.#zero = zero;
    this.#positions = new Map(recipients.map((r, i) => [r, i]));
    const top = levels[TREE_DEPTH]!;
    this.root = top.length === 0 ? zero[TREE_DEPTH]! : top[0]!;
  }

  static build(hasher: ProtocolHasher, recipients: readonly bigint[], order: AllowlistOrder = 'sorted'): AllowlistTree {
    const list = recipients.map((r, i) => assertField(r, `recipient ${i}`));
    if (new Set(list).size !== list.length) throw new Error('allowlist recipients must be distinct');
    if (list.length > MAX_LEAVES) throw new Error(`an allowlist holds at most ${MAX_LEAVES} recipients`);
    if (order === 'sorted') list.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

    const zero = hasher.zeroHashes();
    const levels: bigint[][] = [list.map((r) => hasher.leaf(r))];
    for (let h = 0; h < TREE_DEPTH; h++) {
      const below = levels[h]!;
      const above: bigint[] = [];
      for (let i = 0; i < below.length; i += 2) above.push(hasher.node(below[i]!, below[i + 1] ?? zero[h]!));
      levels.push(above);
    }
    return new AllowlistTree(list, levels, zero);
  }

  get size(): number {
    return this.recipients.length;
  }

  has(recipient: bigint): boolean {
    return this.#positions.has(recipient);
  }

  /** The Merkle witness of an allowlisted recipient, or undefined if it is not on the list. */
  witness(recipient: bigint): MerkleWitness | undefined {
    const leafIndex = this.#positions.get(recipient);
    if (leafIndex === undefined) return undefined;
    const path: bigint[] = [];
    for (let h = 0; h < TREE_DEPTH; h++) {
      const sibling = (leafIndex >> h) ^ 1;
      path.push(this.#levels[h]![sibling] ?? this.#zero[h]!);
    }
    return { leafIndex, path: Object.freeze(path) };
  }

  /** The root the circuit recomputes from a leaf, its index and its path. */
  static computeRoot(hasher: ProtocolHasher, leaf: bigint, witness: MerkleWitness): bigint {
    if (witness.path.length !== TREE_DEPTH) throw new Error(`a Merkle path has ${TREE_DEPTH} entries`);
    let cur = leaf;
    for (let h = 0; h < TREE_DEPTH; h++) {
      const sibling = witness.path[h]!;
      cur = ((witness.leafIndex >> h) & 1) === 0 ? hasher.node(cur, sibling) : hasher.node(sibling, cur);
    }
    return cur;
  }
}
