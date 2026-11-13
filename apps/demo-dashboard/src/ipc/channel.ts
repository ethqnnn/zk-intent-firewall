/**
 * Messages between the host and its two child processes (the tool server and the agent), over
 * Node's IPC channel. One channel carries MCP traffic, RPC calls and events, told apart by `kind`.
 *
 * The agent and the tool server have no other way to reach the host: no network listener is
 * involved, and the agent runs without network permission at all.
 */
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';

export type IpcMessage =
  | { readonly kind: 'mcp'; readonly message: JSONRPCMessage }
  | { readonly kind: 'rpc'; readonly id: number; readonly method: string; readonly params: unknown }
  | { readonly kind: 'rpc-result'; readonly id: number; readonly ok: true; readonly result: unknown }
  | { readonly kind: 'rpc-result'; readonly id: number; readonly ok: false; readonly error: string }
  | { readonly kind: 'event'; readonly event: unknown };

/** A ChildProcess (host side) or `process` (child side). */
export interface IpcEndpoint {
  // Declared as a method so ChildProcess and process, whose send is overloaded, both fit.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  send?(message: any, callback?: any): boolean;
  on(event: 'message', listener: (message: unknown) => void): unknown;
  on(event: 'disconnect', listener: () => void): unknown;
  off(event: 'message', listener: (message: unknown) => void): unknown;
  off(event: 'disconnect', listener: () => void): unknown;
}

export function isIpcMessage(m: unknown): m is IpcMessage {
  return typeof m === 'object' && m !== null && typeof (m as { kind?: unknown }).kind === 'string';
}

function post(endpoint: IpcEndpoint, message: IpcMessage): Promise<void> {
  return new Promise((resolve, reject) => {
    if (typeof endpoint.send !== 'function') return reject(new Error('no IPC channel'));
    try {
      endpoint.send(message, (err: Error | null) => (err ? reject(err) : resolve()));
    } catch (e) {
      reject(e instanceof Error ? e : new Error(String(e)));
    }
  });
}

export interface IpcTransportOptions {
  /** Sees every MCP message, in either direction, before anything else does. */
  readonly tap?: (direction: 'in' | 'out', message: JSONRPCMessage) => void;
  /**
   * Wraps the delivery of each incoming message, for example to run it inside an async context.
   * Default: deliver directly.
   */
  readonly deliver?: (message: JSONRPCMessage, deliver: () => void) => void;
}

/** An MCP transport over an IPC channel. MCP transports are symmetric: client and server both use it. */
export class IpcMcpTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  readonly #endpoint: IpcEndpoint;
  readonly #options: IpcTransportOptions;
  #closed = false;

  constructor(endpoint: IpcEndpoint, options: IpcTransportOptions = {}) {
    this.#endpoint = endpoint;
    this.#options = options;
  }

  readonly #onMessage = (m: unknown): void => {
    if (!isIpcMessage(m) || m.kind !== 'mcp') return;
    const message = m.message;
    this.#options.tap?.('in', message);
    const deliver = () => this.onmessage?.(message);
    if (this.#options.deliver) this.#options.deliver(message, deliver);
    else deliver();
  };

  readonly #onDisconnect = (): void => {
    void this.close();
  };

  async start(): Promise<void> {
    this.#endpoint.on('message', this.#onMessage);
    this.#endpoint.on('disconnect', this.#onDisconnect);
  }

  async send(message: JSONRPCMessage): Promise<void> {
    if (this.#closed) throw new Error('transport closed');
    this.#options.tap?.('out', message);
    await post(this.#endpoint, { kind: 'mcp', message });
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    this.#endpoint.off('message', this.#onMessage);
    this.#endpoint.off('disconnect', this.#onDisconnect);
    this.onclose?.();
  }
}

/** Calls methods the other side serves with serveRpc. */
export class IpcRpcClient {
  readonly #endpoint: IpcEndpoint;
  readonly #pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  #next = 1;
  readonly #tap: ((method: string, params: unknown) => void) | undefined;

  constructor(endpoint: IpcEndpoint, options: { tap?: (method: string, params: unknown) => void } = {}) {
    this.#endpoint = endpoint;
    this.#tap = options.tap;
    endpoint.on('message', (m) => {
      if (!isIpcMessage(m) || m.kind !== 'rpc-result') return;
      const p = this.#pending.get(m.id);
      if (!p) return;
      this.#pending.delete(m.id);
      if (m.ok) p.resolve(m.result);
      else p.reject(new Error(m.error));
    });
    endpoint.on('disconnect', () => {
      for (const p of this.#pending.values()) p.reject(new Error('IPC channel closed'));
      this.#pending.clear();
    });
  }

  call<T>(method: string, params: unknown = {}): Promise<T> {
    const id = this.#next++;
    this.#tap?.(method, params);
    return new Promise<T>((resolve, reject) => {
      this.#pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      post(this.#endpoint, { kind: 'rpc', id, method, params }).catch((e: Error) => {
        this.#pending.delete(id);
        reject(e);
      });
    });
  }
}

export type RpcHandlers = Readonly<Record<string, (params: unknown) => unknown>>;

/** Serves RPC methods. An unknown method or a thrown error becomes an error result, never a crash. */
export function serveRpc(endpoint: IpcEndpoint, handlers: RpcHandlers): void {
  endpoint.on('message', (m) => {
    if (!isIpcMessage(m) || m.kind !== 'rpc') return;
    const { id, method, params } = m;
    const handler = Object.hasOwn(handlers, method) ? handlers[method] : undefined;
    void (async () => {
      try {
        if (!handler) throw new Error(`unknown method ${method}`);
        const result = await handler(params);
        await post(endpoint, { kind: 'rpc-result', id, ok: true, result: result ?? null });
      } catch (e) {
        await post(endpoint, { kind: 'rpc-result', id, ok: false, error: e instanceof Error ? e.message : String(e) }).catch(() => undefined);
      }
    })();
  });
}

/** Sends an event to the other side. Errors (the other side has gone) are ignored. */
export function emitEvent(endpoint: IpcEndpoint, event: unknown): void {
  void post(endpoint, { kind: 'event', event }).catch(() => undefined);
}
