/**
 * How a tool call becomes the circuit's action. Prover and verifier each hold a ToolCatalog with
 * the same tool definitions; the verifier's copy, with its own server identity, is the one that
 * counts (spec 10.3 step 3).
 */
import { SCOPE_BITS } from './crypto/constants.js';
import { EncodingError, parseUint } from './crypto/field.js';
import { toolId } from './crypto/identifiers.js';
import type { Action } from './crypto/types.js';
import { type RecipientRef, resolveRecipient } from './policy.js';

export type ToolArguments = Readonly<Record<string, unknown>>;

/** The value and destination of one call, as the tool will execute it. */
export interface ToolEffect {
  /** Base units, u128. A tool with no natural quantity uses 1 (spec D5). */
  readonly amount: bigint;
  /** Where value or data goes. Tools without a recipient use an agreed resource identifier (L6). */
  readonly recipient: bigint | RecipientRef;
}

export interface ToolActionSpec {
  readonly name: string;
  /** The scope this tool requires: a name in the catalog's scope map, or a bit index. */
  readonly scope: string | number;
  /**
   * Reads the effect from the call's arguments exactly as the tool will execute them. Throw on
   * anything missing or malformed; never guess a default for an amount or a recipient.
   */
  readonly effect: (args: ToolArguments) => ToolEffect;
}

export class ActionMappingError extends Error {
  override readonly name = 'ActionMappingError';
}

/** An action without its nonce. */
export type UnsealedAction = Omit<Action, 'nonce'>;

export interface ToolCatalogOptions {
  /**
   * Identity of the tool server, for example its MCP endpoint URL. It is hashed into every
   * tool_id, so a proof made for one server is refused by every other (spec 10.4).
   */
  readonly serverId: string;
  readonly tools: readonly ToolActionSpec[];
  /** Shared registry of scope names to bit positions (spec L7). */
  readonly scopes?: Readonly<Record<string, number>>;
}

export class ToolCatalog {
  readonly serverId: string;
  readonly #tools: ReadonlyMap<string, { spec: ToolActionSpec; toolId: bigint; scopeIndex: number }>;

  constructor({ serverId, tools, scopes = {} }: ToolCatalogOptions) {
    for (const [name, bit] of Object.entries(scopes)) {
      if (!Number.isInteger(bit) || bit < 0 || bit >= SCOPE_BITS) throw new Error(`scope ${name} has no valid bit position`);
    }
    const map = new Map<string, { spec: ToolActionSpec; toolId: bigint; scopeIndex: number }>();
    for (const spec of tools) {
      if (map.has(spec.name)) throw new Error(`tool ${spec.name} is defined twice`);
      const scopeIndex = typeof spec.scope === 'number' ? spec.scope : scopes[spec.scope];
      if (scopeIndex === undefined || !Number.isInteger(scopeIndex) || scopeIndex < 0 || scopeIndex >= SCOPE_BITS) {
        throw new Error(`tool ${spec.name} requires unknown scope ${String(spec.scope)}`);
      }
      map.set(spec.name, { spec, toolId: toolId(serverId, spec.name), scopeIndex });
    }
    this.serverId = serverId;
    this.#tools = map;
  }

  has(toolName: string): boolean {
    return this.#tools.has(toolName);
  }

  get toolNames(): string[] {
    return [...this.#tools.keys()];
  }

  /** The action a call performs, without nonce. Throws ActionMappingError on bad arguments. */
  resolve(toolName: string, args: ToolArguments): UnsealedAction {
    const entry = this.#tools.get(toolName);
    if (entry === undefined) throw new ActionMappingError(`tool ${toolName} is not in the catalog`);
    let effect: ToolEffect;
    let recipient: bigint;
    try {
      effect = entry.spec.effect(args);
      recipient = resolveRecipient(effect.recipient);
      parseUint(effect.amount, 128, 'amount');
    } catch (e) {
      if (e instanceof ActionMappingError) throw e;
      throw new ActionMappingError(e instanceof Error ? e.message : String(e), { cause: e });
    }
    return { toolId: entry.toolId, scopeIndex: entry.scopeIndex, amount: effect.amount, recipient };
  }
}

/** A required string argument without line feeds. */
export function stringArg(args: ToolArguments, key: string): string {
  const v = args[key];
  if (typeof v !== 'string' || v.length === 0 || v.includes('\n')) throw new ActionMappingError(`argument ${key} must be a non-empty single-line string`);
  return v;
}

/** A required u128 argument: a decimal string, or a JSON number that is a safe integer. */
export function amountArg(args: ToolArguments, key: string): bigint {
  try {
    return parseUint(args[key], 128, `argument ${key}`);
  } catch (e) {
    throw new ActionMappingError(e instanceof EncodingError ? e.message : `argument ${key} is not an amount`);
  }
}

export interface TransferToolOptions {
  readonly name: string;
  readonly scope: string | number;
  /** Argument holding the amount in base units. Default `amount`. */
  readonly amountArg?: string;
  /** Argument holding the CAIP-10 destination account. Default `recipient`. */
  readonly recipientArg?: string;
  /**
   * The CAIP-19 asset this tool moves, when the tool is fixed to one asset (preferable: the
   * agent cannot change it). Otherwise give `assetArg`.
   */
  readonly assetId?: string;
  /** Argument holding the CAIP-19 asset, when the agent chooses it. */
  readonly assetArg?: string;
}

/** A tool that moves `amount` of an asset to an account. */
export function transferTool(o: TransferToolOptions): ToolActionSpec {
  if ((o.assetId === undefined) === (o.assetArg === undefined)) throw new Error('give exactly one of assetId and assetArg');
  const amountKey = o.amountArg ?? 'amount';
  const recipientKey = o.recipientArg ?? 'recipient';
  return {
    name: o.name,
    scope: o.scope,
    effect: (args) => ({
      amount: amountArg(args, amountKey),
      recipient: {
        assetId: o.assetId ?? stringArg(args, o.assetArg!),
        accountId: stringArg(args, recipientKey),
      },
    }),
  };
}
