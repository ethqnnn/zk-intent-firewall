/**
 * UltraHonk verification against the pinned verification keys, with @aztec/bb.js 5.3.0 on its
 * WASM backend. This is spec 10.3 step 6 only; IntentVerifier does the rest of the checklist.
 */
import { BackendType, Barretenberg } from '@aztec/bb.js';
import { loadVerificationKey, proofSettings, type PublicInputs, type VerifierTarget, VERIFIER_TARGETS } from '../circuit.js';
import { fieldToBytes } from '../crypto/field.js';

export interface ProofVerifierOptions {
  /** WASM threads. Verification is cheap; default 1. */
  readonly threads?: number;
  readonly crsPath?: string;
}

export class ProofVerifier {
  readonly #api: Barretenberg;
  readonly #vks: ReadonlyMap<VerifierTarget, Uint8Array>;
  #queue: Promise<unknown> = Promise.resolve();

  private constructor(api: Barretenberg, vks: Map<VerifierTarget, Uint8Array>) {
    this.#api = api;
    this.#vks = vks;
  }

  static async create(options: ProofVerifierOptions = {}): Promise<ProofVerifier> {
    const vks = new Map(VERIFIER_TARGETS.map((t) => [t, loadVerificationKey(t)] as const));
    const api = await Barretenberg.new({
      backend: BackendType.Wasm,
      threads: options.threads ?? 1,
      ...(options.crsPath !== undefined ? { crsPath: options.crsPath } : {}),
    });
    return new ProofVerifier(api, vks);
  }

  /**
   * True only if `proof` is a valid proof, for the pinned key of `target`, of the statement with
   * exactly these public inputs. Malformed proofs are false, never an exception.
   */
  verify(target: VerifierTarget, proof: Uint8Array, publicInputs: PublicInputs): Promise<boolean> {
    // One call at a time on the WASM instance.
    const run = this.#queue.then(() => this.#verify(target, proof, publicInputs));
    this.#queue = run.catch(() => undefined);
    return run;
  }

  async #verify(target: VerifierTarget, proof: Uint8Array, publicInputs: PublicInputs): Promise<boolean> {
    const vk = this.#vks.get(target);
    if (vk === undefined || proof.length === 0 || proof.length % 32 !== 0 || publicInputs.length !== 3) return false;
    const fields: Uint8Array[] = [];
    for (let i = 0; i < proof.length; i += 32) fields.push(proof.slice(i, i + 32));
    try {
      const { verified } = await this.#api.circuitVerify({
        verificationKey: vk,
        publicInputs: publicInputs.map((x) => fieldToBytes(x)),
        proof: fields,
        settings: proofSettings(target),
      });
      return verified === true;
    } catch {
      return false;
    }
  }

  async destroy(): Promise<void> {
    await this.#queue;
    await this.#api.destroy();
  }
}
