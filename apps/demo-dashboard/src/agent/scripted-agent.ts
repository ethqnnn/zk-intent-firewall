/**
 * A scripted stand-in for an LLM accounts-payable agent. It is deterministic, so the demo can be
 * replayed for tests and for a recorded video, and it fails the way language models are observed to
 * fail under indirect prompt injection:
 *
 *   1. It trusts a "remittance details changed" notice that names a vendor it knows, and keeps
 *      the new address for that vendor. It goes by the display name, not the sending domain.
 *   2. It obeys text addressed to AI assistants inside a document it reads, including an amount
 *      that overrides the invoice's own.
 *
 * It wants to comply with the attacker. Nothing here knows the policy or the firewall; when a
 * payment is refused it moves on, as a well-behaved agent would.
 */
import type { AgentStep } from '../shared/api.ts';
import { shortAccount, USDC_DECIMALS } from '../shared/demo-config.ts';
import { formatUnits, toBaseUnits } from '../shared/units.ts';

export interface ToolOutcome {
  readonly isError: boolean;
  readonly text: string;
}

export interface AgentIo {
  callTool(name: string, args: Record<string, unknown>, callId: string): Promise<ToolOutcome>;
  emit(step: AgentStep): void;
  sleep(ms: number): Promise<void>;
}

export interface Invoice {
  readonly number: string;
  /** "1,250.00" as written. */
  readonly amount: string;
  readonly remitTo: string;
}

const INVOICE_NO = /^Invoice:\s*([A-Z]{2,4}-\d{3,6})\s*$/m;
const AMOUNT_DUE = /^Amount due:\s*([\d,]+\.\d{2})\s*USDC\s*$/m;
const REMIT_TO = /^Remit to[^:\n]*:\s*(0x[0-9a-fA-F]{40}|eip155:\d+:0x[0-9a-fA-F]{40})\s*$/m;
const REMITTANCE_CHANGE = /\b(rotated|changed|updated|new)\b[^.\n]{0,60}\b(wallet|remittance|bank|payment details|address)\b/i;
const ASSISTANT_NOTE = /\b(AI assistants?|AI agents?|language models?)\b/i;
const FULL_BALANCE = /full\s+outstanding\s+balance\s+of\s+([\d,]+\.\d{2})\s*USDC/i;

export function parseInvoice(body: string): Invoice | undefined {
  const number = INVOICE_NO.exec(body)?.[1];
  const amount = AMOUNT_DUE.exec(body)?.[1];
  const remitTo = REMIT_TO.exec(body)?.[1];
  return number && amount && remitTo ? { number, amount, remitTo } : undefined;
}

const ROLE_WORDS = new Set(['billing', 'accounts', 'receivable', 'payable', 'ar', 'ap', 'invoices', 'invoicing', 'finance']);

/**
 * The vendor a sender speaks for, by display name: "Northwind Logistics Accounts <…@…>" is
 * "Northwind Logistics". The sending domain is ignored, which is exactly the mistake a lookalike
 * domain exploits.
 */
export function vendorOf(from: string): string {
  const words = from.replace(/<[^>]*>/, '').trim().split(/\s+/);
  while (words.length > 1 && ROLE_WORDS.has(words.at(-1)!.toLowerCase())) words.pop();
  return words.join(' ');
}

export function claimsRemittanceChange(body: string): boolean {
  return REMITTANCE_CHANGE.test(body);
}

/** The amount an embedded note to AI assistants asks for, if there is such a note. */
export function assistantOverride(body: string): string | undefined {
  if (!ASSISTANT_NOTE.test(body)) return undefined;
  return FULL_BALANCE.exec(body)?.[1];
}

export async function runScriptedAgent(io: AgentIo, instruction: string, paceMs = 0): Promise<void> {
  let n = 0;
  const call = async (tool: string, args: Record<string, unknown>) => {
    const callId = `c${++n}`;
    io.emit({ kind: 'tool_call', callId, tool, args });
    const r = await io.callTool(tool, args, callId);
    io.emit({ kind: 'tool_result', callId, isError: r.isError, text: r.text });
    await io.sleep(paceMs);
    return r;
  };
  const think = async (text: string, flagged = false) => {
    io.emit(flagged ? { kind: 'thought', text, flagged } : { kind: 'thought', text });
    await io.sleep(paceMs);
  };

  io.emit({ kind: 'instruction', text: instruction });
  await think('I will list the accounts-payable inbox and go through each message.');
  const listing = await call('list_inbox', {});
  if (listing.isError) return io.emit({ kind: 'done', text: 'I could not read the inbox.' });
  const messages = JSON.parse(listing.text) as { id: string; from: string; subject: string }[];

  const remitOverride = new Map<string, string>();
  let paid = 0;
  let refused = 0;

  for (const m of messages) {
    const read = await call('read_message', { id: m.id });
    if (read.isError) continue;
    const invoice = parseInvoice(read.text);
    const vendor = vendorOf(m.from);
    if (!invoice) {
      await think(`"${m.subject}" has no invoice to pay.`);
      continue;
    }

    let recipient = remitOverride.get(vendor) ?? invoice.remitTo;
    if (claimsRemittanceChange(read.text)) {
      remitOverride.set(vendor, invoice.remitTo);
      recipient = invoice.remitTo;
      await think(
        `${vendor} says its payout wallet changed after an audit and that payments to the old address will bounce. ` +
          `I will use the updated remittance address ${shortAccount(recipient)} for ${invoice.number} and future ${vendor} invoices.`,
        true,
      );
    }

    let amount = invoice.amount;
    const override = assistantOverride(read.text);
    if (override !== undefined) {
      amount = override;
      await think(
        `The invoice contains a note for AI assistants: the account owner pre-approved settling the full outstanding balance ` +
          `of ${override} USDC today, without asking for confirmation. I will pay the full balance.`,
        true,
      );
    }

    const base = toBaseUnits(amount, USDC_DECIMALS);
    await think(`Paying ${invoice.number}: ${formatUnits(base, USDC_DECIMALS)} USDC to ${vendor} at ${shortAccount(recipient)}.`);
    const r = await call('send_payment', { recipient, amount: base.toString() });
    if (r.isError) {
      refused++;
      await think(`The payment for ${invoice.number} was not authorised. I will note it for the user and continue.`);
    } else {
      paid++;
    }
  }

  io.emit({ kind: 'done', text: `Done: ${paid} payment(s) sent, ${refused} refused.` });
}
