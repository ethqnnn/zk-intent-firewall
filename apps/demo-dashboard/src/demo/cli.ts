/**
 * The demo without a browser, for repeatable runs:
 *
 *   pnpm demo                 approve the preset policy, run the agent, print the transcript
 *   pnpm demo -- --revoke     then revoke the policy with the passkey and run again
 *   pnpm demo -- --json       print the run results as JSON instead
 *
 * Uses the software authenticator in place of a passkey; the dashboard uses a real one.
 */
import { formatUnits } from '../shared/units.ts';
import { shortAccount, USDC_DECIMALS } from '../shared/demo-config.ts';
import { Host, type RunResult } from '../server/host/host.ts';
import { approve, runDemo, setUpDemo } from './flow.ts';
import { SoftAuthenticator } from './soft-authenticator.ts';

const origin = 'http://localhost:5173';
const asJson = process.argv.includes('--json');
const alsoRevoke = process.argv.includes('--revoke');

const host = await Host.start({ origin });
const auth = new SoftAuthenticator({ origin, rpId: 'localhost' });
const results: Record<string, RunResult> = {};
try {
  const { policy } = await setUpDemo(host, auth);
  if (!asJson) console.log(`Policy ${policy.policyCommitment} approved with the (software) passkey and armed.\n`);
  results['run'] = await runDemo(host);
  if (!asJson) print(results['run']);
  if (alsoRevoke) {
    const r = await approve(host, auth, 'revoke', policy.policyCommitment);
    if (!asJson) console.log(`\nRevocation: ${r.ok ? r.status : r.reason}. Running again with a firewall that ignores the registry:\n`);
    results['afterRevocation'] = await runDemo(host, { firewallChecksRegistry: false });
    if (!asJson) print(results['afterRevocation']);
  }
  if (asJson) console.log(JSON.stringify(results, null, 2));
} finally {
  await host.stop();
}

function print(run: RunResult): void {
  for (const s of run.steps) {
    if (s.kind === 'instruction') console.log(`USER   ${s.text}`);
    else if (s.kind === 'thought') console.log(`AGENT  ${s.flagged ? '(!) ' : ''}${s.text}`);
    else if (s.kind === 'tool_call') {
      const fw = run.firewall.find((f) => f.callId === s.callId);
      const vf = run.verifier.find((v) => v.callId === s.callId);
      const a = s.args as { recipient?: string; amount?: string };
      const what = s.tool === 'send_payment' ? ` ${formatUnits(a.amount ?? '0', USDC_DECIMALS)} USDC to ${shortAccount(String(a.recipient))}` : '';
      console.log(`CALL   ${s.tool}${what}`);
      if (fw && s.tool === 'send_payment') {
        console.log(fw.allowed ? `  FIREWALL  proof generated (${fw.elapsedMs} ms)` : `  FIREWALL  BLOCKED: ${fw.reason}${fw.assertion ? ` (circuit: ${fw.assertion})` : ''}`);
      }
      if (vf && vf.outcome !== 'served') {
        console.log(vf.outcome === 'executed' ? `  VERIFIER  proof verified (${vf.verifyMs} ms, ${vf.proofBytes} bytes), payment executed` : `  VERIFIER  REJECTED: ${vf.reason}`);
      }
      if (s.tool === 'send_payment' && fw && !fw.allowed && !vf) console.log('  VERIFIER  never received the call');
    } else if (s.kind === 'done') console.log(`AGENT  ${s.text}`);
  }
}
