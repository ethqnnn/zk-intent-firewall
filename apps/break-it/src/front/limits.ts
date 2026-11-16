/**
 * Abuse protection in the front process: per-client token buckets, a global proving budget, and
 * concurrency gates that refuse work instead of queueing it without bound.
 */

/** A token bucket per key. Full buckets are forgotten, so idle clients cost nothing. */
export class RateLimiter {
  readonly capacity: number;
  readonly refillPerSecond: number;
  readonly #buckets = new Map<string, { tokens: number; at: number }>();
  readonly #maxKeys: number;
  readonly #now: () => number;

  constructor(o: { capacity: number; refillPerSecond: number; maxKeys?: number; now?: () => number }) {
    if (!(o.capacity >= 1) || !(o.refillPerSecond > 0)) throw new Error('a rate limit needs a capacity of at least 1 and a positive refill rate');
    this.capacity = o.capacity;
    this.refillPerSecond = o.refillPerSecond;
    this.#maxKeys = o.maxKeys ?? 50_000;
    this.#now = o.now ?? (() => Date.now() / 1000);
  }

  /** Takes one token for `key`. When none is left, says how many seconds until one is. */
  take(key: string): { readonly ok: true } | { readonly ok: false; readonly retryAfterSeconds: number } {
    const now = this.#now();
    const b = this.#buckets.get(key);
    const tokens = b ? Math.min(this.capacity, b.tokens + (now - b.at) * this.refillPerSecond) : this.capacity;
    if (tokens < 1) {
      this.#buckets.set(key, { tokens, at: now });
      return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((1 - tokens) / this.refillPerSecond)) };
    }
    this.#buckets.set(key, { tokens: tokens - 1, at: now });
    if (this.#buckets.size > this.#maxKeys) this.#sweep(now);
    return { ok: true };
  }

  /** Tokens `key` has now, rounded down. */
  remaining(key: string): number {
    const b = this.#buckets.get(key);
    if (!b) return this.capacity;
    return Math.floor(Math.min(this.capacity, b.tokens + (this.#now() - b.at) * this.refillPerSecond));
  }

  #sweep(now: number): void {
    for (const [k, b] of this.#buckets) if (b.tokens + (now - b.at) * this.refillPerSecond >= this.capacity) this.#buckets.delete(k);
    // Still too many: a flood of distinct keys. Forget the oldest half.
    if (this.#buckets.size > this.#maxKeys) {
      let n = this.#buckets.size / 2;
      for (const k of this.#buckets.keys()) {
        if (n-- <= 0) break;
        this.#buckets.delete(k);
      }
    }
  }
}

/**
 * At most `concurrency` tasks run, at most `queue` more wait; anything beyond is refused at once.
 */
export class Gate {
  readonly concurrency: number;
  readonly queue: number;
  #running = 0;
  readonly #waiting: (() => void)[] = [];

  constructor(o: { concurrency: number; queue: number }) {
    this.concurrency = o.concurrency;
    this.queue = o.queue;
  }

  get load(): { readonly running: number; readonly waiting: number } {
    return { running: this.#running, waiting: this.#waiting.length };
  }

  /** Runs `f`, or returns `undefined` at once when the gate is full. */
  async run<T>(f: () => Promise<T>): Promise<{ value: T } | undefined> {
    if (this.#running >= this.concurrency) {
      if (this.#waiting.length >= this.queue) return undefined;
      await new Promise<void>((r) => this.#waiting.push(r));
    } else {
      this.#running += 1;
    }
    try {
      return { value: await f() };
    } finally {
      const next = this.#waiting.shift();
      if (next) next();
      else this.#running -= 1;
    }
  }
}
