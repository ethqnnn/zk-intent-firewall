/**
 * The dashboard's client of the host API. Every request carries the session token, which the
 * dashboard reads once from the URL fragment printed in the terminal and keeps in sessionStorage.
 */
import { type HostEvent, SESSION_HEADER } from '../shared/api.ts';

const TOKEN_KEY = 'zkif-session-token';

/** Takes the token from `#token=…` (then removes it from the address bar) or from this tab's storage. */
export function loadToken(): string | undefined {
  const m = /(?:^#|&)token=([0-9a-zA-Z_-]{16,128})/.exec(window.location.hash);
  if (m) {
    try {
      sessionStorage.setItem(TOKEN_KEY, m[1]!);
    } catch {
      // Storage may be unavailable; the token still works for this page load.
    }
    history.replaceState(null, '', window.location.pathname + window.location.search);
    return m[1];
  }
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? undefined;
  } catch {
    return undefined;
  }
}

export class ApiError extends Error {
  override readonly name = 'ApiError';
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export class Api {
  readonly #token: string;

  constructor(token: string) {
    this.#token = token;
  }

  async get<T>(path: string): Promise<T> {
    return this.#parse<T>(await fetch(path, { headers: { [SESSION_HEADER]: this.#token } }));
  }

  async post<T>(path: string, body: unknown = {}): Promise<T> {
    return this.#parse<T>(
      await fetch(path, {
        method: 'POST',
        headers: { [SESSION_HEADER]: this.#token, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
    );
  }

  async #parse<T>(res: Response): Promise<T> {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    if (!res.ok) throw new ApiError(res.status, body.error ?? `HTTP ${res.status}`);
    return body as T;
  }

  /** Streams host events until `signal` aborts, reconnecting after failures. */
  async streamEvents(onEvent: (e: HostEvent) => void, onConnected: (up: boolean) => void, signal: AbortSignal): Promise<void> {
    let delay = 500;
    while (!signal.aborted) {
      try {
        const res = await fetch('/api/events', { headers: { [SESSION_HEADER]: this.#token }, signal });
        if (!res.ok || !res.body) throw new ApiError(res.status, 'event stream refused');
        onConnected(true);
        delay = 500;
        const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
        let buf = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += value;
          let i;
          while ((i = buf.indexOf('\n\n')) >= 0) {
            const chunk = buf.slice(0, i);
            buf = buf.slice(i + 2);
            for (const line of chunk.split('\n')) {
              if (line.startsWith('data: ')) onEvent(JSON.parse(line.slice(6)) as HostEvent);
            }
          }
        }
      } catch (e) {
        if (signal.aborted) return;
        if (e instanceof ApiError && e.status === 401) {
          onConnected(false);
          return;
        }
      }
      onConnected(false);
      await new Promise((r) => setTimeout(r, delay));
      delay = Math.min(delay * 2, 8000);
    }
  }
}
