import { USER_AGENT } from '../core/version.js';
import { LiveAbort, LiveRefusal, LiveRequestError } from './errors.js';
import { dnsResolver, resolvePublicAddress, type HostResolver, type ResolvedAddress } from './guard.js';
import { nodeTransport, type LiveResponse, type Transport } from './transport.js';

export type LiveMethod = 'GET' | 'HEAD' | 'POST';

export const DEFAULT_MAX_REQUESTS = 60;
/** No configuration can raise the budget above this. */
export const MAX_REQUESTS_CEILING = 100;
/** Minimum spacing between requests; configuration can only raise it. */
export const MIN_DELAY_MS = 250;
/** Spacing for the rate-limit probe, the only exception to MIN_DELAY_MS. */
export const PROBE_SPACING_MS = 100;
export const REQUEST_TIMEOUT_MS = 10_000;
export const MAX_CONSECUTIVE_5XX = 3;

export interface RateLimitProbe {
  path: string;
  method: 'GET' | 'POST';
}

export interface LiveClientOptions {
  origin: URL;
  maxRequests?: number;
  delayMs?: number;
  /** SHIPCHECK_ALLOW_LOCAL=1: allow IP literals and private addresses (tests only). */
  allowLocal?: boolean;
  /** The single non-GET/HEAD request allowed, and the only one that may use 100 ms spacing. */
  probe?: RateLimitProbe;
  resolve?: HostResolver;
  transport?: Transport;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

const realSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * The only way live checks reach the network. It enforces every safety rule in one place: same host
 * only, GET/HEAD only (plus the configured probe), no credentials, a hard request budget, one request
 * at a time with at least 250 ms between them, a 10 s timeout, a stop after 3 consecutive 5xx, and
 * refusal of private addresses.
 */
export class LiveClient {
  readonly origin: URL;
  readonly maxRequests: number;
  readonly delayMs: number;
  readonly probe: RateLimitProbe | undefined;
  readonly #allowLocal: boolean;
  readonly #resolve: HostResolver;
  readonly #transport: Transport;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #now: () => number;
  readonly #addresses = new Map<string, Promise<ResolvedAddress>>();
  #queue: Promise<unknown> = Promise.resolve();
  #sent = 0;
  #streak5xx = 0;
  #last: number | undefined;
  #aborted: string | undefined;

  constructor(options: LiveClientOptions) {
    this.origin = options.origin;
    this.maxRequests = Math.min(Math.max(1, Math.floor(options.maxRequests ?? DEFAULT_MAX_REQUESTS)), MAX_REQUESTS_CEILING);
    this.delayMs = Math.max(MIN_DELAY_MS, options.delayMs ?? MIN_DELAY_MS);
    this.probe = options.probe;
    this.#allowLocal = options.allowLocal ?? false;
    this.#resolve = options.resolve ?? dnsResolver;
    this.#transport = options.transport ?? nodeTransport;
    this.#sleep = options.sleep ?? realSleep;
    this.#now = options.now ?? Date.now;
  }

  /** Requests sent so far, including failed ones. */
  get sent(): number {
    return this.#sent;
  }

  get remaining(): number {
    return Math.max(0, this.maxRequests - this.#sent);
  }

  /** Why the client stopped sending, if it did. */
  get aborted(): string | undefined {
    return this.#aborted;
  }

  isProbe(method: LiveMethod, url: URL): boolean {
    return this.probe !== undefined && method === this.probe.method && url.pathname === this.probe.path;
  }

  /** Validates, then queues; requests run strictly one after another. Redirects are returned, never followed. */
  request(method: LiveMethod, target: string, options: { spacingMs?: number } = {}): Promise<LiveResponse> {
    let url: URL;
    try {
      url = this.#check(method, target);
    } catch (error) {
      return Promise.reject(error);
    }
    const run = this.#queue.then(() => this.#send(method, url, options));
    this.#queue = run.catch(() => undefined);
    return run;
  }

  #check(method: string, target: string): URL {
    const url = new URL(target, this.origin);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new LiveRefusal(`shipcheck only sends http and https requests; refusing ${url.protocol}`);
    if (url.hostname !== this.origin.hostname) throw new LiveRefusal(`shipcheck only requests ${this.origin.hostname}; refusing ${url.host}`);
    if (url.username || url.password) throw new LiveRefusal('shipcheck never sends credentials; refusing a URL with a user name or password');
    if (method !== 'GET' && method !== 'HEAD' && !this.isProbe(method as LiveMethod, url)) {
      throw new LiveRefusal(`shipcheck only sends GET and HEAD requests (plus the configured rate-limit probe); refusing ${method} ${url.pathname}`);
    }
    return url;
  }

  #address(hostname: string): Promise<ResolvedAddress> {
    let address = this.#addresses.get(hostname);
    if (!address) {
      address = resolvePublicAddress(hostname, { resolve: this.#resolve, allowLocal: this.#allowLocal });
      this.#addresses.set(hostname, address);
    }
    return address;
  }

  async #send(method: LiveMethod, url: URL, options: { spacingMs?: number }): Promise<LiveResponse> {
    if (this.#aborted) throw new LiveAbort(this.#aborted);
    if (this.#sent >= this.maxRequests) throw new LiveAbort(`the request budget of ${this.maxRequests} requests is used up`);
    const address = await this.#address(url.hostname);
    const spacing = options.spacingMs !== undefined && this.isProbe(method, url) ? Math.max(PROBE_SPACING_MS, options.spacingMs) : this.delayMs;
    if (this.#last !== undefined) {
      const wait = this.#last + spacing - this.#now();
      if (wait > 0) await this.#sleep(wait);
    }
    this.#sent++;
    let response: LiveResponse;
    try {
      // Only these two headers: no cookies, no Authorization, nothing user-supplied.
      response = await this.#transport({ method, url, headers: { 'user-agent': USER_AGENT, accept: '*/*' }, timeoutMs: REQUEST_TIMEOUT_MS, address });
    } catch (error) {
      throw new LiveRequestError(`${method} ${url.href} failed: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      this.#last = this.#now();
    }
    if (response.status >= 500) {
      this.#streak5xx++;
      if (this.#streak5xx >= MAX_CONSECUTIVE_5XX) this.#aborted = `stopped after ${MAX_CONSECUTIVE_5XX} consecutive 5xx responses`;
    } else {
      this.#streak5xx = 0;
    }
    return response;
  }
}
