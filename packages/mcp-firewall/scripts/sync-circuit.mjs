#!/usr/bin/env node
// Keeps circuit/ in step with packages/zk-circuit.
//
//   node scripts/sync-circuit.mjs           check (default): exit 1 if anything differs
//   node scripts/sync-circuit.mjs --write   copy the compiled circuit and rewrite the keys
//
// circuit/proof_of_intent.json  copy of packages/zk-circuit/target/proof_of_intent.json (run
//                               `pnpm --filter @zk-intent-firewall/zk-circuit run compile` first)
// circuit/vk/<target>.vk        verification key computed by the pinned @aztec/bb.js
//
// It also checks each key's Barretenberg hash against packages/zk-circuit/fixtures/vk_hashes.txt
// and prints the SHA-256 of each key file, which src/circuit.ts pins.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { Barretenberg, BackendType } from '@aztec/bb.js';

const write = process.argv.includes('--write');
const here = dirname(fileURLToPath(import.meta.url));
const pkg = join(here, '..');
const circuitPkg = join(pkg, '..', 'zk-circuit');
const built = join(circuitPkg, 'target', 'proof_of_intent.json');
const local = join(pkg, 'circuit', 'proof_of_intent.json');
let failed = false;

if (existsSync(built)) {
  const a = JSON.parse(readFileSync(built, 'utf8'));
  const b = existsSync(local) ? JSON.parse(readFileSync(local, 'utf8')) : null;
  const same = b && a.bytecode === b.bytecode && JSON.stringify(a.abi) === JSON.stringify(b.abi) && a.noir_version === b.noir_version;
  if (!same && write) {
    writeFileSync(local, readFileSync(built));
    console.log('copied the compiled circuit');
  } else if (!same) {
    console.log('circuit/proof_of_intent.json differs from the compiled circuit');
    failed = true;
  } else {
    console.log('circuit/proof_of_intent.json matches the compiled circuit');
  }
} else {
  console.log(`no compiled circuit at ${built}: skipping the artifact comparison`);
}

const recorded = Object.fromEntries(
  readFileSync(join(circuitPkg, 'fixtures', 'vk_hashes.txt'), 'utf8')
    .split('\n')
    .filter((l) => l.trim() && !l.startsWith('#'))
    .map((l) => l.trim().split(/\s+/)),
);
const circuit = JSON.parse(readFileSync(local, 'utf8'));
const bytecode = gunzipSync(Buffer.from(circuit.bytecode, 'base64'));
const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1 });
const settings = {
  'noir-recursive': { ipaAccumulation: false, oracleHashType: 'poseidon2', disableZk: false, optimizedSolidityVerifier: false },
  evm: { ipaAccumulation: false, oracleHashType: 'keccak', disableZk: false, optimizedSolidityVerifier: false },
};
mkdirSync(join(pkg, 'circuit', 'vk'), { recursive: true });
for (const [target, s] of Object.entries(settings)) {
  const { bytes, hash } = await api.circuitComputeVk({ circuit: { name: 'proof_of_intent', bytecode }, settings: s });
  const bbHash = '0x' + Buffer.from(hash).toString('hex');
  if (bbHash !== recorded[target]) {
    console.log(`${target}: vk hash ${bbHash} differs from vk_hashes.txt ${recorded[target]}`);
    failed = true;
  }
  const file = join(pkg, 'circuit', 'vk', `${target}.vk`);
  const same = existsSync(file) && Buffer.compare(readFileSync(file), Buffer.from(bytes)) === 0;
  if (!same && write) writeFileSync(file, bytes);
  else if (!same) {
    console.log(`${target}: circuit/vk/${target}.vk differs from the computed key`);
    failed = true;
  }
  console.log(`${target}: bb hash ${bbHash}, sha256 ${createHash('sha256').update(bytes).digest('hex')}, ${bytes.length} bytes`);
}
await api.destroy();
process.exit(failed ? 1 : 0);
