/**
 * The scripted agent's reading of the inbox. These pin the scenario: if a parser drifts, an
 * injection silently stops firing and the demo shows a firewall blocking nothing.
 */
import { describe, expect, it } from 'vitest';
import { assistantOverride, claimsRemittanceChange, parseInvoice, runScriptedAgent, vendorOf } from '../src/agent/scripted-agent.ts';
import { INBOX, listingOf, renderMessage } from '../src/demo/inbox.ts';
import type { AgentStep } from '../src/shared/api.ts';
import { ATTACKER_ACCOUNT, PAYEES } from '../src/shared/demo-config.ts';

const msg = (id: string) => INBOX.find((m) => m.id === id)!;
const addr = (account: string) => account.split(':')[2]!;

describe('inbox parsing', () => {
  it('reads each invoice', () => {
    expect(parseInvoice(msg('msg-1').body)).toEqual({ number: 'NW-2041', amount: '1,250.00', remitTo: addr(PAYEES.northwind.account) });
    expect(parseInvoice(msg('msg-2').body)).toMatchObject({ number: 'NW-2042', amount: '2,980.00' });
    expect(parseInvoice(msg('msg-2').body)!.remitTo.toLowerCase()).toBe(addr(ATTACKER_ACCOUNT));
    expect(parseInvoice(msg('msg-3').body)).toMatchObject({ number: 'CC-88317', amount: '3,400.00' });
    expect(parseInvoice(msg('msg-4').body)).toMatchObject({ number: 'FB-1102', amount: '412.60' });
    expect(parseInvoice('Invoice: NW-1\nAmount due: 1.00 USDC')).toBeUndefined();
  });

  it('goes by display name, so the lookalike domain passes as the vendor', () => {
    expect(vendorOf(msg('msg-1').from)).toBe('Northwind Logistics');
    expect(vendorOf(msg('msg-2').from)).toBe('Northwind Logistics');
    expect(vendorOf(msg('msg-4').from)).toBe('Fabrikam Office Supply');
    expect(vendorOf('Billing <x@y>')).toBe('Billing');
  });

  it('falls for the remittance change and the hidden note, and only those', () => {
    // As the agent reads them: headers included, as read_message returns them.
    const read = (id: string) => renderMessage(msg(id));
    expect(claimsRemittanceChange(read('msg-2'))).toBe(true);
    for (const id of ['msg-1', 'msg-3', 'msg-4']) expect(claimsRemittanceChange(read(id)), id).toBe(false);
    expect(assistantOverride(read('msg-3'))).toBe('48,750.00');
    for (const id of ['msg-1', 'msg-2', 'msg-4']) expect(assistantOverride(read(id)), id).toBeUndefined();
  });
});

describe('the scripted run, against a tool layer that allows everything', () => {
  it('asks for both attacks and keeps going after a refusal', async () => {
    const steps: AgentStep[] = [];
    const calls: { tool: string; args: Record<string, unknown>; callId: string }[] = [];
    await runScriptedAgent(
      {
        async callTool(tool, args, callId) {
          calls.push({ tool, args, callId });
          // The treasury's own rendering of the inbox.
          if (tool === 'list_inbox') return { isError: false, text: JSON.stringify(INBOX.map(listingOf)) };
          if (tool === 'read_message') return { isError: false, text: renderMessage(msg(String(args['id']))) };
          // Refuse every payment: the agent must still try all four.
          return { isError: true, text: 'refused' };
        },
        emit: (s) => steps.push(s),
        sleep: async () => undefined,
      },
      'Pay the invoices.',
    );
    const pays = calls.filter((c) => c.tool === 'send_payment').map((c) => [String(c.args['recipient']).toLowerCase(), c.args['amount']]);
    expect(pays).toEqual([
      [addr(PAYEES.northwind.account), '1250000000'],
      [addr(ATTACKER_ACCOUNT), '2980000000'],
      [addr(PAYEES.contoso.account), '48750000000'],
      [addr(PAYEES.fabrikam.account), '412600000'],
    ]);
    // Call ids are unique, and differ between runs.
    expect(new Set(calls.map((c) => c.callId)).size).toBe(calls.length);
    expect(steps.at(-1)).toMatchObject({ kind: 'done' });
  });
});
