import type { LiveConfig, RawFinding, Rule } from '../types.js';
import type { LiveClient, LiveMethod } from './client.js';
import type { LiveResponse } from './transport.js';

export interface LiveTarget {
  /** The site root, e.g. https://app.example.com/ */
  origin: URL;
  /** The same host over plain HTTP, for LIVE-002. */
  httpOrigin: URL;
  config: LiveConfig;
}

/** One line of the --dry-run plan. */
export interface PlannedStep {
  kind: 'http' | 'dns' | 'tls';
  method?: LiveMethod;
  target: string;
  purpose: string;
  /** The rate-limit probe repeats; everything else is sent once. */
  count?: number;
  /** Sent only when an earlier response calls for it. */
  conditional?: boolean;
}

export interface LiveContext extends LiveTarget {
  client: LiveClient;
  /** GET / , fetched once and shared by the checks that need it. */
  home(): Promise<LiveResponse>;
  now: Date;
  skip(check: string, reason: string): void;
}

/** A live check carries the same metadata as a static rule, so findings go through the same normalizer and scorer. */
export interface LiveCheck extends Omit<Rule, 'run'> {
  plan(target: LiveTarget): PlannedStep[];
  run(ctx: LiveContext): Promise<RawFinding[]>;
}

export const HOME_STEP = (target: LiveTarget, purpose: string): PlannedStep => ({ kind: 'http', method: 'GET', target: target.origin.href, purpose });

export function absolute(target: LiveTarget, path: string): string {
  return new URL(path, target.origin).href;
}
