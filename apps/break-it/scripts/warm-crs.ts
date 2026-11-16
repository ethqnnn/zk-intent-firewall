/**
 * Fills Barretenberg's reference-string cache (BREAKIT_CRS_PATH, default ~/.bb-crs) by starting a
 * prover and a verifier once. Run at build time; the sandboxed engine cannot download it later.
 */
import { homedir } from 'node:os';
import { join } from 'node:path';
import { LocalWasmProver, ProofVerifier } from '@zk-intent-firewall/mcp-firewall';

const crsPath = process.env['BREAKIT_CRS_PATH'] || join(homedir(), '.bb-crs');
const prover = await LocalWasmProver.create({ crsPath, threads: 1 });
const verifier = await ProofVerifier.create({ crsPath });
await prover.destroy();
await verifier.destroy();
console.log(`reference string cached in ${crsPath}`);
