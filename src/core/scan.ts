import { statSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { defaultExec, type ExecFn } from '../adapters/exec.js';
import { CLOUDFLARE_TOKEN_ENV, type FetchFn } from '../infra/cloudflare.js';
import { buildContext } from '../context/build-context.js';
import { compareStrings } from '../context/files.js';
import { loadUserConfig } from '../context/user-config.js';
import { defaultRegistry } from '../packs/index.js';
import { severityRank } from '../schema.js';
import type { Rule, ScanResult, Severity } from '../types.js';
import { ShipcheckError } from './errors.js';
import { VERSION } from './version.js';
import { normalizeFindings } from './normalize.js';
import { runRules } from './runner.js';
import { computeScore } from './scoring.js';

export { VERSION } from './version.js';

export interface ScanOptions {
  /** Path to a shipcheck.config.json; defaults to the one in the scan root, if any. */
  configFile?: string;
  /** Rules to run; defaults to every registered pack rule. */
  rules?: readonly Rule[];
  /** Per-rule timeout; defaults to 10 s (tool-backed rules get the 120 s tool timeout). */
  timeoutMs?: number;
  /** Skip checks that need the network (DEP-001 vulnerability database lookups). */
  offline?: boolean;
  /** How external tools are run; injected by tests to replay recorded output. */
  exec?: ExecFn;
  /** Let INFRA-001..003 read Cloudflare zone settings with CLOUDFLARE_API_TOKEN (network, GET only). */
  cloudflare?: boolean;
  /** Used for the Cloudflare API; injected by tests. */
  fetch?: FetchFn;
  /** Where CLOUDFLARE_API_TOKEN is read from; defaults to process.env. */
  env?: Record<string, string | undefined>;
}

/** The target as shown in reports: relative to the working directory when inside it, so reports carry no home paths. */
function displayPath(root: string): string {
  const rel = relative(process.cwd(), root);
  if (rel === '') return '.';
  if (rel.startsWith('..') || isAbsolute(rel)) return root.split(sep).join('/');
  return rel.split(sep).join('/');
}

/** Display filter: keeps findings at or above `minSeverity`. Score and counts are left untouched. */
export function filterFindings(result: ScanResult, minSeverity: Severity): ScanResult {
  if (minSeverity === 'info') return result;
  const limit = severityRank(minSeverity);
  return { ...result, findings: result.findings.filter((f) => severityRank(f.severity) <= limit) };
}

/** Whether any non-advisory finding is at or above `failOn` (the CLI then exits 1). */
export function hasBlockingFindings(result: ScanResult, failOn: Severity | 'none'): boolean {
  if (failOn === 'none') return false;
  const limit = severityRank(failOn);
  return result.findings.some((f) => !f.advisory && severityRank(f.severity) <= limit);
}

export async function scan(target: string, options: ScanOptions = {}): Promise<ScanResult> {
  const started = performance.now();
  const root = resolve(target);
  const stat = statSync(root, { throwIfNoEntry: false });
  if (!stat) throw new ShipcheckError(`Path does not exist: ${target}`);
  if (!stat.isDirectory()) throw new ShipcheckError(`Not a directory: ${target}`);

  const { config } = loadUserConfig(root, options.configFile);
  const env = options.env ?? process.env;
  const cloudflare = options.cloudflare ? { cloudflare: { token: env[CLOUDFLARE_TOKEN_ENV] || undefined, ...(options.fetch ? { fetch: options.fetch } : {}) } } : {};
  const { ctx, skipped } = await buildContext(root, config, { tools: { exec: options.exec ?? defaultExec, offline: options.offline ?? false, ...cloudflare } });
  const rules = options.rules ?? defaultRegistry().all();
  const outcome = await runRules(rules, ctx, options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs });
  const normalized = normalizeFindings(outcome.runs, { readText: ctx.readText });

  return {
    schemaVersion: '1.0',
    tool: { name: 'shipcheck', version: VERSION },
    target: { path: displayPath(root) },
    stack: [...ctx.stacks],
    score: computeScore(normalized.findings),
    findings: normalized.findings,
    suppressedCount: normalized.suppressedCount,
    // Rules report skips while running concurrently; sort so reports stay deterministic.
    skipped: [...skipped, ...outcome.skipped].sort((a, b) => compareStrings(a.check, b.check) || compareStrings(a.reason, b.reason)),
    ruleErrors: [...outcome.ruleErrors, ...normalized.ruleErrors],
    durationMs: Math.round(performance.now() - started),
  };
}
