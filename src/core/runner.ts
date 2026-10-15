import { compareStrings } from '../context/files.js';
import type { RawFinding, Rule, ScanContext, ScanResult } from '../types.js';

export const RULE_TIMEOUT_MS = 10_000;

export interface RuleRun {
  rule: Rule;
  findings: RawFinding[];
}

export interface RunOutcome {
  /** One entry per rule that ran successfully, in rule id order. */
  runs: RuleRun[];
  ruleErrors: ScanResult['ruleErrors'];
  skipped: ScanResult['skipped'];
}

class RuleTimeoutError extends Error {}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new RuleTimeoutError(`timed out after ${ms} ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * Runs every applicable rule concurrently. A rule applies when all its stacks are detected and the
 * config does not turn it off. A throw, rejection, bad return value or timeout becomes a rule error.
 * Note: the timeout cannot interrupt a rule that blocks the event loop synchronously.
 */
export async function runRules(rules: readonly Rule[], ctx: ScanContext, options: { timeoutMs?: number } = {}): Promise<RunOutcome> {
  const timeoutMs = options.timeoutMs ?? RULE_TIMEOUT_MS;
  const ordered = [...rules].sort((a, b) => compareStrings(a.id, b.id));
  const skipped: RunOutcome['skipped'] = [];
  const applicable: Rule[] = [];

  for (const rule of ordered) {
    const override = ctx.config.rules[rule.id];
    const missing = rule.stacks.filter((stack) => !ctx.stacks.has(stack));
    if (override === 'off') skipped.push({ check: rule.id, reason: 'disabled in config' });
    else if (missing.length) skipped.push({ check: rule.id, reason: `requires stack not detected: ${missing.join(', ')}` });
    else applicable.push(rule);
  }

  const settled = await Promise.allSettled(
    applicable.map((rule) => withTimeout(Promise.resolve().then(() => rule.run(ctx)), rule.timeoutMs ?? timeoutMs)),
  );

  const runs: RuleRun[] = [];
  const ruleErrors: RunOutcome['ruleErrors'] = [];
  settled.forEach((outcome, index) => {
    const rule = applicable[index]!;
    if (outcome.status === 'rejected') {
      const reason: unknown = outcome.reason;
      ruleErrors.push({ ruleId: rule.id, message: reason instanceof Error ? reason.message : String(reason) });
      return;
    }
    if (!Array.isArray(outcome.value)) {
      ruleErrors.push({ ruleId: rule.id, message: 'run() must return an array of findings' });
      return;
    }
    const override = ctx.config.rules[rule.id];
    const findings = override && override !== 'off' ? outcome.value.map((f) => ({ ...f, severity: override })) : outcome.value;
    runs.push({ rule, findings });
  });

  return { runs, ruleErrors, skipped };
}
