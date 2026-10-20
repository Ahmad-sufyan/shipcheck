import { applyBaseline, baselineFor, today } from '../core/baseline.js';
import { normalizeFindings } from '../core/normalize.js';
import type { RuleRun } from '../core/runner.js';
import { computeScore } from '../core/scoring.js';
import { VERSION } from '../core/version.js';
import type { LiveConfig, Rule, ScanResult, ShipcheckConfig } from '../types.js';
import { LIVE_CHECKS } from './checks/index.js';
import { DEFAULT_MAX_REQUESTS, LiveClient, MAX_REQUESTS_CEILING, MIN_DELAY_MS, REQUEST_TIMEOUT_MS, MAX_CONSECUTIVE_5XX } from './client.js';
import type { LiveCheck, LiveContext, LiveTarget, PlannedStep } from './context.js';
import { LiveAbort, LiveRefusal, LiveRequestError } from './errors.js';
import type { HostResolver } from './guard.js';
import { loadSecret, parseTarget, verifyOwnership, WELL_KNOWN_PATH, type TxtResolver } from './ownership.js';
import type { LiveResponse, TlsProbe, Transport } from './transport.js';

export const ALLOW_LOCAL_ENV = 'SHIPCHECK_ALLOW_LOCAL';
export const LEGAL_WARNING = 'Warning: only run live checks against sites you own or are authorized to test. Probing sites you do not own may be illegal.';

export interface LiveRunOptions {
  /** The URL argument; falls back to live.url in the config. */
  url?: string;
  config: ShipcheckConfig;
  /** Directory holding .shipcheck/live-secret. */
  root: string;
  env?: Record<string, string | undefined>;
  /** A baseline file; false disables it. Default: <root>/.shipcheck-baseline.json when present. */
  baseline?: string | false;
  today?: string;
  /** Port of the plain-HTTP listener for LIVE-002; tests point it at the mock server. Default 80. */
  httpPort?: number;
  resolve?: HostResolver;
  resolveTxt?: TxtResolver;
  transport?: Transport;
  tlsProbe?: TlsProbe;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

export interface LiveRun {
  result: ScanResult;
  verifiedBy: 'well-known' | 'dns';
  requestsSent: number;
}

/** SHIPCHECK_ALLOW_LOCAL=1 lifts the private-address and IP-literal refusal; it exists for tests only. */
export function allowLocalTargets(env: Record<string, string | undefined>): boolean {
  return env[ALLOW_LOCAL_ENV] === '1';
}

export function liveTarget(options: Pick<LiveRunOptions, 'url' | 'config' | 'env' | 'httpPort'>): LiveTarget {
  const url = options.url ?? options.config.live?.url;
  if (!url) throw new LiveRefusal('No URL given: pass one (`shipcheck live https://app.example.com`) or set live.url in shipcheck.config.json.');
  const origin = parseTarget(url, { allowLocal: allowLocalTargets(options.env ?? process.env) });
  origin.pathname = '/';
  origin.search = '';
  origin.hash = '';
  const httpOrigin = new URL(origin);
  httpOrigin.protocol = 'http:';
  httpOrigin.port = options.httpPort ? String(options.httpPort) : '';
  const config: LiveConfig = { protectedPaths: [], cookiePaths: [], ...options.config.live, url: origin.href };
  return { origin, httpOrigin, config };
}

function enabledChecks(config: ShipcheckConfig): LiveCheck[] {
  return LIVE_CHECKS.filter((check) => config.rules[check.id] !== 'off');
}

/** Every request a run could send, in order, without sending anything (not even DNS lookups). */
export function planLive(target: LiveTarget, config: ShipcheckConfig): PlannedStep[] {
  const steps: PlannedStep[] = [
    { kind: 'http', method: 'GET', target: new URL(WELL_KNOWN_PATH, target.origin).href, purpose: 'ownership verification' },
    { kind: 'dns', target: `TXT _shipcheck.${target.origin.hostname}`, purpose: 'ownership verification, only if the file does not verify', conditional: true },
  ];
  const seen = new Set<string>();
  for (const check of enabledChecks(config)) {
    for (const step of check.plan(target)) {
      const key = `${step.kind} ${step.method ?? ''} ${step.target}`;
      if (seen.has(key)) continue;
      seen.add(key);
      steps.push(step);
    }
  }
  return steps;
}

export function formatPlan(target: LiveTarget, steps: readonly PlannedStep[]): string {
  const budget = Math.min(target.config.maxRequests ?? DEFAULT_MAX_REQUESTS, MAX_REQUESTS_CEILING);
  const delay = Math.max(MIN_DELAY_MS, target.config.delayMs ?? MIN_DELAY_MS);
  const lines = [
    `Live check plan for ${target.origin.href} (dry run: nothing is sent, not even the ownership check)`,
    `Budget: at most ${budget} requests (hard ceiling ${MAX_REQUESTS_CEILING}), one at a time, ${delay} ms apart, ${REQUEST_TIMEOUT_MS / 1000} s timeout, stop after ${MAX_CONSECUTIVE_5XX} consecutive 5xx.`,
    '',
  ];
  let number = 0;
  let maxRequests = 0;
  for (const step of steps) {
    const counted = step.kind !== 'dns';
    if (counted) maxRequests += step.count ?? 1;
    const label = step.kind === 'http' ? (step.method ?? 'GET') : step.kind.toUpperCase();
    const times = step.count && step.count > 1 ? ` (up to ${step.count} times)` : '';
    const prefix = counted ? `${String(++number).padStart(3)}.` : '    ';
    lines.push(`${prefix} ${label.padEnd(4)} ${step.target}${times}`);
    lines.push(`          ${step.purpose}${step.conditional ? ' (conditional)' : ''}`);
  }
  lines.push('');
  lines.push(`At most ${Math.min(maxRequests, budget)} requests${maxRequests > budget ? ` (the plan needs ${maxRequests}; checks past the budget are skipped)` : ''}.`);
  if (!target.config.rateLimitProbe) lines.push('LIVE-003 will be skipped: no live.rateLimitProbe configured.');
  if (!target.config.protectedPaths.length) lines.push('LIVE-004 will be skipped: no live.protectedPaths configured.');
  return `${lines.join('\n')}\n`;
}

/** Live checks reuse the static normalizer, which takes rules. */
function asRule(check: LiveCheck): Rule {
  return { ...check, run: () => [] };
}

/**
 * Verifies ownership, then runs the live checks in order through one guarded client. Refuses (LiveRefusal)
 * before sending anything when there is no secret or the target is not allowed; checks that hit the budget,
 * the 5xx stop or a network error become skipped entries.
 */
export async function runLive(options: LiveRunOptions): Promise<LiveRun> {
  const started = performance.now();
  const env = options.env ?? process.env;
  const target = liveTarget(options);
  const secret = loadSecret(options.root, env, target.origin.href);
  const now = options.now ?? Date.now;
  const client = new LiveClient({
    origin: target.origin,
    allowLocal: allowLocalTargets(env),
    ...(target.config.maxRequests === undefined ? {} : { maxRequests: target.config.maxRequests }),
    ...(target.config.delayMs === undefined ? {} : { delayMs: target.config.delayMs }),
    ...(target.config.rateLimitProbe ? { probe: { path: target.config.rateLimitProbe.path, method: target.config.rateLimitProbe.method } } : {}),
    ...(options.resolve ? { resolve: options.resolve } : {}),
    ...(options.transport ? { transport: options.transport } : {}),
    ...(options.tlsProbe ? { tlsProbe: options.tlsProbe } : {}),
    ...(options.sleep ? { sleep: options.sleep } : {}),
    now,
  });
  const { method: verifiedBy } = await verifyOwnership(client, secret, options.resolveTxt ? { resolveTxt: options.resolveTxt } : {});

  const skipped: ScanResult['skipped'] = [];
  const ruleErrors: ScanResult['ruleErrors'] = [];
  const runs: RuleRun[] = [];
  let home: Promise<LiveResponse> | undefined;
  const ctx: LiveContext = {
    ...target,
    client,
    home: () => (home ??= client.request('GET', target.origin.href)),
    now: new Date(now()),
    skip: (check, reason) => skipped.push({ check, reason }),
  };

  for (const check of LIVE_CHECKS) {
    const override = options.config.rules[check.id];
    if (override === 'off') {
      skipped.push({ check: check.id, reason: 'disabled in config' });
      continue;
    }
    try {
      const findings = await check.run(ctx);
      runs.push({ rule: asRule(check), findings: override ? findings.map((f) => ({ ...f, severity: override })) : findings });
    } catch (error) {
      if (error instanceof LiveAbort || error instanceof LiveRequestError) skipped.push({ check: check.id, reason: error.message });
      else ruleErrors.push({ ruleId: check.id, message: error instanceof Error ? error.message : String(error) });
    }
  }

  const normalized = normalizeFindings(runs);
  const accepted = applyBaseline(normalized.findings, baselineFor(options.root, options.baseline), options.today ?? today());
  const result: ScanResult = {
    schemaVersion: '1.0',
    tool: { name: 'shipcheck', version: VERSION },
    target: { path: target.origin.href },
    stack: [],
    score: computeScore(accepted.findings),
    findings: accepted.findings,
    suppressedCount: accepted.suppressed.length,
    suppressed: accepted.suppressed,
    warnings: accepted.warnings,
    skipped,
    ruleErrors: [...ruleErrors, ...normalized.ruleErrors],
    durationMs: Math.round(performance.now() - started),
  };
  return { result, verifiedBy, requestsSent: client.sent };
}

export { LIVE_CHECKS };
