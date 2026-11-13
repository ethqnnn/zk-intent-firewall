#!/usr/bin/env node
// Compatibility check between the installed @aztec/bb.js and noir_js, the compiled circuit, the
// verification key hashes recorded in packages/zk-circuit/fixtures/vk_hashes.txt, and native `bb`.
//
//   node scripts/bbjs-roundtrip.mjs
//
// For each zero-knowledge verifier target it:
//   1. generates the witness of fixtures/Prover.toml's inputs (from vectors.json) with noir_js,
//   2. computes the verification key with bb.js and compares its hash with fixtures/vk_hashes.txt,
//   3. proves with bb.js and verifies with bb.js against that key,
//   4. checks the proof's public inputs are the three fixture values in order,
//   5. checks that changing any public input or the proof makes verification fail,
//   6. if a native `bb` is found ($BB, or PATH outside node_modules): verifies the bb.js proof with native bb, and the native bb proof
//      (packages/zk-circuit/target/bb/<target>) with bb.js.
//
// Exits non-zero on any mismatch. Never uses a "-no-zk" target.
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { delimiter, dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Barretenberg, BackendType, UltraHonkBackend, UltraHonkVerifierBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';

const here = dirname(fileURLToPath(import.meta.url));
// Neither package exports its package.json, so read the installed copies directly.
const installedVersion = (name) =>
  JSON.parse(readFileSync(join(here, '..', 'node_modules', name, 'package.json'), 'utf8')).version;
const bbjsVersion = installedVersion('@aztec/bb.js');
const noirJsVersion = installedVersion('@noir-lang/noir_js');
const circuitDir = join(here, '..', '..', 'zk-circuit');
const artifactPath = process.env.CIRCUIT_ARTIFACT ?? join(here, '..', 'circuit', 'proof_of_intent.json');
const circuit = JSON.parse(readFileSync(artifactPath, 'utf8'));
const vectors = JSON.parse(readFileSync(join(circuitDir, 'fixtures', 'vectors.json'), 'utf8'));
const recordedVkHashes = Object.fromEntries(
  readFileSync(join(circuitDir, 'fixtures', 'vk_hashes.txt'), 'utf8')
    .split('\n')
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => l.trim().split(/\s+/)),
);

const hex = (u8) => '0x' + Buffer.from(u8).toString('hex');
let failures = 0;
const check = (ok, msg) => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${msg}`);
  if (!ok) failures++;
};

const inputs = {
  policy_commitment: vectors.policy_commitment,
  current_timestamp: vectors.current_timestamp,
  action_binding: vectors.action_binding,
  policy: vectors.policy,
  action: vectors.action,
  leaf_index: vectors.merkle_witness.leaf_index,
  merkle_path: vectors.merkle_witness.merkle_path,
};

const noir = new Noir(circuit);
const { witness } = await noir.execute(inputs);
check(witness.length > 0, `noir_js ${noirJsVersion} generated the witness (${witness.length} bytes gzipped)`);

const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1 });
const backend = new UltraHonkBackend(circuit.bytecode, api);
const verifier = new UltraHonkVerifierBackend(api);
// The native bb to cross-check against: $BB, or the first `bb` on PATH outside node_modules.
// (pnpm puts node_modules/.bin first, where bb.js links its own bundled binary, which would make
// the cross-check bb.js against itself.)
const bbPath =
  process.env.BB ??
  (process.env.PATH ?? '')
    .split(delimiter)
    .filter((d) => d && !d.split(sep).includes('node_modules'))
    .map((d) => join(d, 'bb'))
    .find((f) => existsSync(f));
const nativeBb = (() => {
  if (!bbPath) return null;
  try {
    return execFileSync(bbPath, ['--version'], { encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
})();
console.log(`bb.js ${bbjsVersion}, backend: Wasm. native bb: ${nativeBb ? `${nativeBb} (${bbPath})` : 'none'}`);

// Scratch files for the native cross-check live in the package's gitignored target/ directory.
const work = join(here, '..', 'target', 'bbjs-roundtrip');
rmSync(work, { recursive: true, force: true });
for (const target of ['noir-recursive', 'evm']) {
  const opts = { verifierTarget: target };
  const vkRes = await api.circuitComputeVk({
    circuit: { name: 'circuit', bytecode: backend.acirUncompressedBytecode },
    settings: {
      ipaAccumulation: false,
      oracleHashType: target === 'evm' ? 'keccak' : 'poseidon2',
      disableZk: false,
      optimizedSolidityVerifier: false,
    },
  });
  const vk = await backend.getVerificationKey(opts);
  check(Buffer.compare(Buffer.from(vk), Buffer.from(vkRes.bytes)) === 0, `${target}: getVerificationKey matches circuitComputeVk`);
  check(hex(vkRes.hash) === recordedVkHashes[target], `${target}: vk hash ${hex(vkRes.hash)} == vk_hashes.txt ${recordedVkHashes[target]}`);

  const proofData = await backend.generateProof(witness, opts);
  check(
    JSON.stringify(proofData.publicInputs) === JSON.stringify(vectors.public_inputs),
    `${target}: public inputs are the fixture values in order`,
  );
  check(await verifier.verifyProof({ ...proofData, verificationKey: vk }, opts), `${target}: bb.js proof verifies with bb.js (${proofData.proof.length} bytes)`);

  for (let i = 0; i < 3; i++) {
    const pis = [...proofData.publicInputs];
    const b = Buffer.from(pis[i].slice(2), 'hex');
    b[31] ^= 1;
    pis[i] = hex(b);
    let ok;
    try {
      ok = await verifier.verifyProof({ proof: proofData.proof, publicInputs: pis, verificationKey: vk }, opts);
    } catch {
      ok = false;
    }
    check(!ok, `${target}: changed public input ${i} is rejected`);
  }
  {
    const p = Uint8Array.from(proofData.proof);
    p[p.length >> 1] ^= 1;
    let ok;
    try {
      ok = await verifier.verifyProof({ proof: p, publicInputs: proofData.publicInputs, verificationKey: vk }, opts);
    } catch {
      ok = false;
    }
    check(!ok, `${target}: changed proof is rejected`);
  }

  if (nativeBb) {
    // bb.js proof -> native bb.
    const dir = join(work, target);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'vk'), vk);
    writeFileSync(join(dir, 'proof'), proofData.proof);
    writeFileSync(join(dir, 'public_inputs'), Buffer.concat(proofData.publicInputs.map((x) => Buffer.from(x.slice(2), 'hex'))));
    let nativeOk = true;
    try {
      execFileSync(bbPath, ['verify', '-k', join(dir, 'vk'), '-p', join(dir, 'proof'), '-i', join(dir, 'public_inputs'), '-t', target], { stdio: 'pipe' });
    } catch (e) {
      nativeOk = false;
      console.log(String(e.stderr ?? e));
    }
    check(nativeOk, `${target}: bb.js ${bbjsVersion} proof verifies with native bb ${nativeBb}`);

    // native bb proof -> bb.js.
    const nd = join(circuitDir, 'target', 'bb', target);
    if (existsSync(join(nd, 'proof'))) {
      const nvk = readFileSync(join(nd, 'vk'));
      check(Buffer.compare(nvk, Buffer.from(vk)) === 0, `${target}: native bb vk bytes == bb.js vk bytes`);
      const npi = readFileSync(join(nd, 'public_inputs'));
      const npis = [0, 1, 2].map((i) => hex(npi.subarray(i * 32, i * 32 + 32)));
      const ok = await verifier.verifyProof({ proof: new Uint8Array(readFileSync(join(nd, 'proof'))), publicInputs: npis, verificationKey: vk }, opts);
      check(ok, `${target}: native bb ${nativeBb} proof verifies with bb.js ${bbjsVersion}`);
    } else {
      console.log(`skip ${target}: no native proof at ${nd} (run: pnpm --filter @zk-intent-firewall/zk-circuit run prove)`);
    }
  }
}
await api.destroy();
console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
