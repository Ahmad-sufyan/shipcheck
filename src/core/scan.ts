import { statSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import pkg from '../../package.json' with { type: 'json' };
import { buildContext } from '../context/build-context.js';
import { loadUserConfig } from '../context/user-config.js';
import { defaultRegistry } from '../packs/index.js';
import type { Rule, ScanResult } from '../types.js';
import { ShipcheckError } from './errors.js';
import { normalizeFindings } from './normalize.js';
import { runRules } from './runner.js';
import { computeScore } from './scoring.js';

export const VERSION: string = pkg.version;

export interface ScanOptions {
  /** Path to a shipcheck.config.json; defaults to the one in the scan root, if any. */
  configFile?: string;
  /** Rules to run; defaults to every registered pack rule. */
  rules?: readonly Rule[];
  /** Per-rule timeout; defaults to 10 s. */
  timeoutMs?: number;
}

/** The target as shown in reports: relative to the working directory when inside it, so reports carry no home paths. */
function displayPath(root: string): string {
  const rel = relative(process.cwd(), root);
  if (rel === '') return '.';
  if (rel.startsWith('..') || isAbsolute(rel)) return root.split(sep).join('/');
  return rel.split(sep).join('/');
}

export async function scan(target: string, options: ScanOptions = {}): Promise<ScanResult> {
  const started = performance.now();
  const root = resolve(target);
  const stat = statSync(root, { throwIfNoEntry: false });
  if (!stat) throw new ShipcheckError(`Path does not exist: ${target}`);
  if (!stat.isDirectory()) throw new ShipcheckError(`Not a directory: ${target}`);

  const { config } = loadUserConfig(root, options.configFile);
  const { ctx, skipped } = await buildContext(root, config);
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
    skipped: [...skipped, ...outcome.skipped],
    ruleErrors: [...outcome.ruleErrors, ...normalized.ruleErrors],
    durationMs: Math.round(performance.now() - started),
  };
}
