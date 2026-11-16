/**
 * The public log of attempts. Every attempt is kept in memory (the most recent `keep`) and counted
 * in the aggregates; with a file, it is also appended as one JSON line, and the file is read back
 * at start, so the log and the leaderboard survive restarts.
 *
 * Nothing here is ever an IP address: records carry a handle or a per-process pseudonym.
 */
import { createReadStream, createWriteStream, existsSync, statSync, type WriteStream } from 'node:fs';
import { createInterface } from 'node:readline';
import type { AttemptRecord, Verdict } from '../shared/types.ts';

export interface AttemptLogOptions {
  /** JSON-lines file to append to and load from. Omit to keep the log in memory only. */
  readonly file?: string;
  /** Records kept in memory for listing. Default 5000. */
  readonly keep?: number;
  /** Stop appending once the file reaches this size. Default 256 MiB. */
  readonly maxFileBytes?: number;
  /** Distinct visitors tracked on the leaderboard. Default 20,000. */
  readonly maxVisitors?: number;
}

export interface CheckCount {
  readonly layer: string;
  readonly check: string;
  readonly count: number;
}

export interface LogStats {
  readonly total: number;
  readonly byVerdict: Readonly<Record<Verdict, number>>;
  readonly byRoute: Readonly<Record<string, number>>;
  /** Checks that caught something, most frequent first. */
  readonly byCheck: readonly CheckCount[];
  /** Every attempt judged a break (at most the 100 most recent). */
  readonly breaks: readonly AttemptRecord[];
  readonly firstAt: string | null;
  readonly lastAt: string | null;
  readonly persisted: boolean;
}

export interface LeaderboardRow {
  readonly who: string;
  readonly attempts: number;
  /** Distinct layer:check pairs this visitor triggered: a measure of how many defences they probed. */
  readonly distinctChecks: number;
  readonly breaks: number;
  readonly lastAt: string;
}

export interface ListQuery {
  readonly limit?: number;
  /** Return records older than this id. */
  readonly before?: string;
  readonly verdict?: string;
  readonly layer?: string;
  readonly check?: string;
  readonly who?: string;
  readonly route?: string;
}

interface Visitor {
  attempts: number;
  checks: Set<string>;
  breaks: number;
  lastAt: string;
}

export class AttemptLog {
  readonly #keep: number;
  readonly #maxFileBytes: number;
  readonly #maxVisitors: number;
  readonly #recent: AttemptRecord[] = [];
  readonly #breaks: AttemptRecord[] = [];
  readonly #byVerdict: Record<Verdict, number> = { caught: 0, legitimate: 0, break: 0 };
  readonly #byRoute = new Map<string, number>();
  readonly #byCheck = new Map<string, CheckCount>();
  readonly #visitors = new Map<string, Visitor>();
  #total = 0;
  #firstAt: string | null = null;
  #lastAt: string | null = null;
  #out: WriteStream | undefined;
  #fileBytes = 0;
  readonly #file: string | undefined;

  private constructor(o: AttemptLogOptions) {
    this.#keep = o.keep ?? 5000;
    this.#maxFileBytes = o.maxFileBytes ?? 256 * 1024 * 1024;
    this.#maxVisitors = o.maxVisitors ?? 20_000;
    this.#file = o.file;
  }

  static async open(o: AttemptLogOptions = {}): Promise<AttemptLog> {
    const log = new AttemptLog(o);
    if (o.file) {
      if (existsSync(o.file)) {
        log.#fileBytes = statSync(o.file).size;
        const lines = createInterface({ input: createReadStream(o.file, 'utf8'), crlfDelay: Infinity });
        for await (const line of lines) {
          if (line.length === 0) continue;
          try {
            const r = JSON.parse(line) as AttemptRecord;
            if (typeof r.id === 'string' && typeof r.at === 'string' && typeof r.verdict === 'string') log.#ingest(r);
          } catch {
            // A torn last line after a crash: skip it.
          }
        }
      }
      log.#out = createWriteStream(o.file, { flags: 'a' });
      log.#out.on('error', () => (log.#out = undefined));
    }
    return log;
  }

  get persisted(): boolean {
    return this.#out !== undefined && this.#fileBytes < this.#maxFileBytes;
  }

  add(r: AttemptRecord): void {
    this.#ingest(r);
    if (this.#out && this.#fileBytes < this.#maxFileBytes) {
      const line = `${JSON.stringify(r)}\n`;
      this.#fileBytes += Buffer.byteLength(line);
      this.#out.write(line);
    }
  }

  #ingest(r: AttemptRecord): void {
    this.#total += 1;
    this.#firstAt ??= r.at;
    this.#lastAt = r.at;
    this.#recent.push(r);
    if (this.#recent.length > this.#keep) this.#recent.splice(0, this.#recent.length - this.#keep);
    if (r.verdict in this.#byVerdict) this.#byVerdict[r.verdict] += 1;
    this.#byRoute.set(r.route, (this.#byRoute.get(r.route) ?? 0) + 1);
    if (r.verdict === 'break') {
      this.#breaks.push(r);
      if (this.#breaks.length > 100) this.#breaks.shift();
    }
    const checkKey = r.caughtBy ? `${r.caughtBy.layer}:${r.caughtBy.check}` : undefined;
    if (r.caughtBy && checkKey) {
      const c = this.#byCheck.get(checkKey);
      this.#byCheck.set(checkKey, { layer: r.caughtBy.layer, check: r.caughtBy.check, count: (c?.count ?? 0) + 1 });
    }
    let v = this.#visitors.get(r.who);
    if (!v) {
      if (this.#visitors.size >= this.#maxVisitors) this.#evictVisitor();
      v = { attempts: 0, checks: new Set(), breaks: 0, lastAt: r.at };
      this.#visitors.set(r.who, v);
    }
    v.attempts += 1;
    v.lastAt = r.at;
    if (checkKey) v.checks.add(checkKey);
    if (r.verdict === 'break') v.breaks += 1;
  }

  #evictVisitor(): void {
    let worst: string | undefined;
    let fewest = Infinity;
    for (const [who, v] of this.#visitors) {
      if (v.breaks === 0 && v.attempts < fewest) {
        fewest = v.attempts;
        worst = who;
      }
    }
    if (worst !== undefined) this.#visitors.delete(worst);
  }

  /** Most recent first. */
  list(q: ListQuery = {}): AttemptRecord[] {
    const limit = Math.min(Math.max(1, Math.floor(q.limit ?? 50)), 200);
    let end = this.#recent.length;
    if (q.before) {
      const i = this.#recent.findIndex((r) => r.id === q.before);
      if (i >= 0) end = i;
    }
    const out: AttemptRecord[] = [];
    for (let i = end - 1; i >= 0 && out.length < limit; i--) {
      const r = this.#recent[i]!;
      if (q.verdict && r.verdict !== q.verdict) continue;
      if (q.route && r.route !== q.route) continue;
      if (q.who && r.who !== q.who) continue;
      if (q.layer && r.caughtBy?.layer !== q.layer) continue;
      if (q.check && r.caughtBy?.check !== q.check) continue;
      out.push(r);
    }
    return out;
  }

  get(id: string): AttemptRecord | undefined {
    return this.#recent.find((r) => r.id === id) ?? this.#breaks.find((r) => r.id === id);
  }

  stats(): LogStats {
    return {
      total: this.#total,
      byVerdict: { ...this.#byVerdict },
      byRoute: Object.fromEntries(this.#byRoute),
      byCheck: [...this.#byCheck.values()].sort((a, b) => b.count - a.count || a.check.localeCompare(b.check)),
      breaks: [...this.#breaks].reverse(),
      firstAt: this.#firstAt,
      lastAt: this.#lastAt,
      persisted: this.persisted,
    };
  }

  /** Breaks first, then breadth of checks probed, then attempts. */
  leaderboard(limit = 50): LeaderboardRow[] {
    return [...this.#visitors]
      .map(([who, v]) => ({ who, attempts: v.attempts, distinctChecks: v.checks.size, breaks: v.breaks, lastAt: v.lastAt }))
      .sort((a, b) => b.breaks - a.breaks || b.distinctChecks - a.distinctChecks || b.attempts - a.attempts || a.who.localeCompare(b.who))
      .slice(0, limit);
  }

  async close(): Promise<void> {
    const out = this.#out;
    this.#out = undefined;
    if (out) await new Promise<void>((r) => out.end(r));
  }

  get file(): string | undefined {
    return this.#file;
  }
}
