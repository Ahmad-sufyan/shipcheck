import { CATEGORIES } from '../schema.js';
import type { Category, Confidence, Finding, Grade, ScanResult, Severity } from '../types.js';

export const SEVERITY_WEIGHTS: Record<Severity, number> = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };
export const CONFIDENCE_MULTIPLIERS: Record<Confidence, number> = { high: 1, medium: 0.75, low: 0.5 };

export type ScorableFinding = Pick<Finding, 'ruleId' | 'category' | 'severity' | 'confidence' | 'advisory'>;

export function gradeFor(value: number): Grade {
  if (value >= 90) return 'A';
  if (value >= 80) return 'B';
  if (value >= 65) return 'C';
  if (value >= 50) return 'D';
  return 'F';
}

/**
 * Penalty for a set of findings: per rule, the sum of weight x confidence, capped at twice the rule's
 * weight. A rule's weight is the heaviest severity among its findings, so per-finding escalations count.
 */
function penalty(findings: readonly ScorableFinding[]): number {
  const byRule = new Map<string, { sum: number; maxWeight: number }>();
  for (const f of findings) {
    if (f.advisory) continue;
    const weight = SEVERITY_WEIGHTS[f.severity];
    const entry = byRule.get(f.ruleId) ?? { sum: 0, maxWeight: 0 };
    entry.sum += weight * CONFIDENCE_MULTIPLIERS[f.confidence];
    entry.maxWeight = Math.max(entry.maxWeight, weight);
    byRule.set(f.ruleId, entry);
  }
  let total = 0;
  for (const { sum, maxWeight } of byRule.values()) total += Math.min(sum, 2 * maxWeight);
  return total;
}

function toScore(total: number): number {
  return Math.max(0, Math.floor(100 - total));
}

export function computeScore(findings: readonly ScorableFinding[]): ScanResult['score'] {
  let value = toScore(penalty(findings));
  const blocking = findings.filter((f) => !f.advisory);
  if (blocking.some((f) => f.severity === 'critical')) value = Math.min(value, 49);
  else if (blocking.some((f) => f.severity === 'high')) value = Math.min(value, 79);

  const byCategory = {} as Record<Category, number>;
  for (const category of CATEGORIES) {
    byCategory[category] = toScore(penalty(findings.filter((f) => f.category === category)));
  }
  return { value, grade: gradeFor(value), byCategory };
}
