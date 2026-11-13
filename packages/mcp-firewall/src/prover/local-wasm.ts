/**
 * Proving on this machine: witness generation with @noir-lang/noir_js 1.0.0 and UltraHonk proving
 * with @aztec/bb.js 5.3.0 on its WASM backend.
 */
import { gunzipSync } from 'node:zlib';
import { availableParallelism } from 'node:os';
import { BackendType, Barretenberg } from '@aztec/bb.js';
import { type CompiledCircuit, Noir } from '@noir-lang/noir_js';
import {
  loadCircuit,
  loadVerificationKey,
  proofSettings,
  publicInputsOf,
  toInputMap,
  type VerifierTarget,
} from '../circuit.js';
import { bytesToField } from '../crypto/field.js';
import { type IntentProof, ProofGenerationError, type ProofRequest, type Prover } from './types.js';

export interface LocalWasmProverOptions {
  /** WASM threads. Default: the available parallelism, at most 8. */
  readonly threads?: number;
  /** Where Barretenberg caches its reference string. Default: bb.js's own default. */
  readonly crsPath?: string;
  /** Override the compiled circuit (tests only). */
  readonly circuit?: CompiledCircuit;
}

export class LocalWasmProver implements Prover {
  readonly name = 'local-wasm';
  readonly #noir: Noir;
  readonly #api: Barretenberg;
  readonly #bytecode: Uint8Array;
  readonly #vks = new Map<VerifierTarget, Uint8Array>();
  #queue: Promise<unknown> = Promise.resolve();

  private constructor(circuit: CompiledCircuit, api: Barretenberg) {
    this.#noir = new Noir(circuit);
    this.#api = api;
    this.#bytecode = gunzipSync(Buffer.from(circuit.bytecode, 'base64'));
  }

  static async create(options: LocalWasmProverOptions = {}): Promise<LocalWasmProver> {
    const api = await Barretenberg.new({
      backend: BackendType.Wasm,
      threads: options.threads ?? Math.min(availableParallelism(), 8),
      ...(options.crsPath !== undefined ? { crsPath: options.crsPath } : {}),
    });
    return new LocalWasmProver(options.circuit ?? loadCircuit(), api);
  }

  /** Proofs are made one at a time: the WASM backend is single-instance. */
  prove(request: ProofRequest): Promise<IntentProof> {
    const run = this.#queue.then(() => this.#prove(request));
    this.#queue = run.catch(() => undefined);
    return run;
  }

  async #prove({ inputs, target }: ProofRequest): Promise<IntentProof> {
    const settings = proofSettings(target);
    let witness: Uint8Array;
    try {
      ({ witness } = await this.#noir.execute(toInputMap(inputs)));
    } catch (e) {
      throw new ProofGenerationError('witness', e instanceof Error ? e.message : String(e), { cause: e });
    }

    let vk = this.#vks.get(target);
    if (vk === undefined) {
      vk = loadVerificationKey(target);
      this.#vks.set(target, vk);
    }

    let result;
    try {
      result = await this.#api.circuitProve({
        witness: gunzipSync(witness),
        circuit: { name: 'proof_of_intent', bytecode: this.#bytecode, verificationKey: vk },
        settings,
      });
    } catch (e) {
      throw new ProofGenerationError('proving', e instanceof Error ? e.message : String(e), { cause: e });
    }

    const expected = publicInputsOf(inputs);
    const got = result.publicInputs.map((b) => bytesToField(b));
    if (got.length !== 3 || got.some((x, i) => x !== expected[i])) {
      throw new ProofGenerationError('proving', 'the proof is not for the requested public inputs');
    }
    const proof = new Uint8Array(result.proof.length * 32);
    result.proof.forEach((fr, i) => proof.set(fr, i * 32));
    return { target, proof, publicInputs: expected };
  }

  async destroy(): Promise<void> {
    await this.#queue;
    await this.#api.destroy();
  }
}
