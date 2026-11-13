/**
 * The prover interface. The firewall depends only on this, so a hosted prover (Phase 5) can
 * replace LocalWasmProver without any change to the interceptor.
 *
 * A prover receives the complete witness, policy opening included. Under the trust model
 * (spec section 2) that is inherent: whoever proves sees the policy. A hosted prover is therefore
 * a party the policy owner must trust with the policy, and the transport to it must be private.
 */
import type { CircuitAssertion, CircuitInputs, PublicInputs, VerifierTarget } from '../circuit.js';
import { CIRCUIT_ASSERTIONS } from '../circuit.js';

export interface ProofRequest {
  readonly inputs: CircuitInputs;
  readonly target: VerifierTarget;
}

export interface IntentProof {
  readonly target: VerifierTarget;
  /** The proof, as Barretenberg's concatenated 32-byte field elements, without public inputs. */
  readonly proof: Uint8Array;
  /** The public inputs the proof is for: [policy_commitment, current_timestamp, action_binding]. */
  readonly publicInputs: PublicInputs;
}

export interface Prover {
  /** A short name for logs, such as "local-wasm". */
  readonly name: string;
  /**
   * Proves the statement for `request.inputs`. Rejects with ProofGenerationError when the inputs
   * do not satisfy the circuit or proving fails. Never resolves with a proof for other inputs.
   */
  prove(request: ProofRequest): Promise<IntentProof>;
  /** Releases the backend. */
  destroy(): Promise<void>;
}

const KNOWN_ASSERTIONS = new Set<string>(Object.values(CIRCUIT_ASSERTIONS));

export class ProofGenerationError extends Error {
  override readonly name = 'ProofGenerationError';
  /**
   * `witness`: the inputs do not satisfy the circuit (the action is outside the policy, or the
   * encoding disagrees with the circuit). `proving`: the backend failed.
   */
  readonly stage: 'witness' | 'proving';
  /** The circuit assertion that failed, when the failure is a named assertion. */
  readonly assertion: CircuitAssertion | undefined;

  constructor(stage: 'witness' | 'proving', message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.stage = stage;
    const m = /Circuit execution failed: (.+)$/m.exec(message);
    const candidate = m?.[1]?.trim();
    this.assertion = candidate !== undefined && KNOWN_ASSERTIONS.has(candidate) ? (candidate as CircuitAssertion) : undefined;
  }
}
