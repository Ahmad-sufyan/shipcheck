import { describe, expect, it } from 'vitest';
import { computeScore, gradeFor, type ScorableFinding } from '../../../src/core/scoring.js';
import { CATEGORIES } from '../../../src/schema.js';

function f(overrides: Partial<ScorableFinding> = {}): ScorableFinding {
  return { ruleId: 'R-001', category: 'http-config', severity: 'low', confidence: 'high', advisory: false, ...overrides };
}

describe('gradeFor', () => {
  it.each([
    [100, 'A'],
    [90, 'A'],
    [89, 'B'],
    [80, 'B'],
    [79, 'C'],
    [65, 'C'],
    [64, 'D'],
    [50, 'D'],
    [49, 'F'],
    [0, 'F'],
  ] as const)('%i -> %s', (value, grade) => {
    expect(gradeFor(value)).toBe(grade);
  });
});

describe('computeScore', () => {
  it('scores a clean project 100 / A with every category at 100', () => {
    const score = computeScore([]);
    expect(score.value).toBe(100);
    expect(score.grade).toBe('A');
    expect(Object.keys(score.byCategory).sort()).toEqual([...CATEGORIES].sort());
    expect(Object.values(score.byCategory).every((v) => v === 100)).toBe(true);
  });

  it('subtracts severity weight times confidence multiplier', () => {
    expect(computeScore([f()]).value).toBe(99);
    expect(computeScore([f({ severity: 'medium', confidence: 'medium' })]).value).toBe(97);
    expect(computeScore([f({ severity: 'info' })]).value).toBe(100);
  });

  it('floors fractional totals so any penalty drops below 100', () => {
    expect(computeScore([f({ confidence: 'low' })]).value).toBe(99);
  });

  it('caps the sum per rule at twice the rule weight', () => {
    const five = Array.from({ length: 5 }, () => f({ severity: 'medium' }));
    expect(computeScore(five).value).toBe(92);
    const twoRules = [...five, f({ ruleId: 'R-002', severity: 'medium' })];
    expect(computeScore(twoRules).value).toBe(88);
  });

  it('caps the score at 49 with a non-advisory critical and 79 with a non-advisory high', () => {
    expect(computeScore([f({ severity: 'critical', category: 'authorization' })]).value).toBe(49);
    expect(computeScore([f({ severity: 'critical' })]).grade).toBe('F');
    expect(computeScore([f({ severity: 'high' })]).value).toBe(79);
    expect(computeScore([f({ severity: 'high', confidence: 'low' })]).value).toBe(79);
  });

  it('gives advisory findings no weight and no cap', () => {
    const score = computeScore([f({ severity: 'critical', advisory: true })]);
    expect(score.value).toBe(100);
    expect(score.byCategory['http-config']).toBe(100);
  });

  it('never goes below zero', () => {
    const many = Array.from({ length: 6 }, (_, i) => f({ ruleId: `R-00${i}`, severity: 'critical' }));
    expect(computeScore(many).value).toBe(0);
  });

  it('computes byCategory with the same formula but without caps', () => {
    const score = computeScore([
      f({ severity: 'critical', category: 'authorization' }),
      f({ ruleId: 'R-002', severity: 'low', category: 'http-config' }),
    ]);
    expect(score.byCategory.authorization).toBe(75);
    expect(score.byCategory['http-config']).toBe(99);
    expect(score.byCategory.secrets).toBe(100);
    expect(score.value).toBe(49);
  });

  it('uses the heaviest finding of a rule for its cap when severities are mixed', () => {
    const mixed = [f({ severity: 'high' }), f({ severity: 'critical' }), f({ severity: 'critical' })];
    // 10 + 25 + 25 = 60, capped at 2 x 25 = 50
    expect(computeScore(mixed).byCategory['http-config']).toBe(50);
  });
});
