import { describe, expect, it } from 'vitest';
import { fingerprint } from '../../../src/core/fingerprint.js';
import { compareFindings, normalizeFindings } from '../../../src/core/normalize.js';
import type { RawFinding, Rule } from '../../../src/types.js';
import { testRule } from '../../helpers/rules.js';

function run(rule: Rule, findings: RawFinding[]) {
  return { rule, findings };
}

describe('normalizeFindings', () => {
  it('fills defaults from the rule and keeps per-finding overrides', () => {
    const rule = testRule({
      id: 'HTTP-006',
      title: 'X-Powered-By header enabled',
      category: 'http-config',
      severity: 'low',
      confidence: 'high',
      cwe: 'CWE-200',
      references: ['https://nextjs.org/docs/app/api-reference/config/next-config-js/poweredByHeader'],
    });
    const { findings } = normalizeFindings([
      run(rule, [
        { file: 'next.config.mjs', line: 2, evidence: 'const nextConfig = {' },
        { file: '.\\lib\\x.ts', line: 3, column: 5, endLine: 4, evidence: 'x', explanation: 'Custom.', fix: 'Do y.', severity: 'high', confidence: 'low' },
      ]),
    ]);
    expect(findings).toEqual([
      {
        id: fingerprint({ ruleId: 'HTTP-006', file: 'lib/x.ts', evidence: 'x' }),
        ruleId: 'HTTP-006',
        title: 'X-Powered-By header enabled',
        category: 'http-config',
        severity: 'high',
        confidence: 'low',
        advisory: false,
        source: 'static',
        file: 'lib/x.ts',
        line: 3,
        column: 5,
        endLine: 4,
        url: null,
        evidence: 'x',
        explanation: 'Custom.',
        fix: 'Do y.',
        cwe: 'CWE-200',
        references: ['https://nextjs.org/docs/app/api-reference/config/next-config-js/poweredByHeader'],
      },
      {
        id: fingerprint({ ruleId: 'HTTP-006', file: 'next.config.mjs', evidence: 'const nextConfig = {' }),
        ruleId: 'HTTP-006',
        title: 'X-Powered-By header enabled',
        category: 'http-config',
        severity: 'low',
        confidence: 'high',
        advisory: false,
        source: 'static',
        file: 'next.config.mjs',
        line: 2,
        column: null,
        endLine: null,
        url: null,
        evidence: 'const nextConfig = {',
        explanation: 'Default explanation.',
        fix: 'Default fix.',
        cwe: 'CWE-200',
        references: ['https://nextjs.org/docs/app/api-reference/config/next-config-js/poweredByHeader'],
      },
    ]);
  });

  it('copies advisory and source and omits cwe when the rule has none', () => {
    const { findings } = normalizeFindings([run(testRule({ advisory: true, source: 'live' }), [{ url: 'https://x.test/', evidence: 'x-powered-by: Next.js' }])]);
    expect(findings[0]).toMatchObject({ advisory: true, source: 'live', url: 'https://x.test/', file: null, references: [] });
    expect(findings[0]).not.toHaveProperty('cwe');
  });

  it('lets a raw finding override the rule advisory default', () => {
    const { findings } = normalizeFindings([
      run(testRule({ advisory: false }), [{ file: 'a.ts', line: 1, evidence: 'a', advisory: true }]),
      run(testRule({ id: 'TEST-002', advisory: true }), [{ file: 'b.ts', line: 1, evidence: 'b', advisory: false }, { file: 'c.ts', line: 1, evidence: 'c' }]),
    ]);
    expect(findings.map((f) => [f.file, f.advisory])).toEqual([
      ['a.ts', true],
      ['b.ts', false],
      ['c.ts', true],
    ]);
  });

  it('redacts and truncates evidence before fingerprinting', () => {
    const secret = ['sk', 'live', '51FakeKeyForTests0000000000'].join('_');
    const { findings } = normalizeFindings([run(testRule(), [{ file: 'a.ts', line: 1, evidence: `const k = '${secret}' ${'y'.repeat(300)}` }])]);
    expect(findings[0]?.evidence.startsWith("const k = 'sk_l****'")).toBe(true);
    expect(findings[0]?.evidence).toHaveLength(200);
    expect(findings[0]?.id).toBe(fingerprint({ ruleId: 'TEST-001', file: 'a.ts', evidence: findings[0]!.evidence }));
  });

  it('drops invalid raw findings and reports them as rule errors', () => {
    const { findings, ruleErrors } = normalizeFindings([run(testRule(), [{ file: 'a.ts', line: 0, evidence: 'x' }, { evidence: 'ok' }])]);
    expect(findings).toHaveLength(1);
    expect(ruleErrors).toEqual([{ ruleId: 'TEST-001', message: expect.stringMatching(/invalid finding.*line/) }]);
  });

  it('dedupes by fingerprint, keeping the first occurrence in sort order', () => {
    const { findings } = normalizeFindings([
      run(testRule(), [
        { file: 'a.ts', line: 9, evidence: 'same(a, b)' },
        { file: 'a.ts', line: 2, evidence: 'same(a,\n    b)' },
      ]),
    ]);
    expect(findings.map((f) => f.line)).toEqual([2]);
  });

  it('sorts by severity, file, line, then rule id', () => {
    const { findings } = normalizeFindings([
      run(testRule({ id: 'B-001', severity: 'low' }), [
        { file: 'b.ts', line: 1, evidence: '1' },
        { file: 'a.ts', line: 5, evidence: '2' },
        { file: 'a.ts', line: 1, evidence: '3' },
      ]),
      run(testRule({ id: 'A-001', severity: 'low' }), [{ file: 'a.ts', line: 5, evidence: '4' }]),
      run(testRule({ id: 'C-001', severity: 'critical' }), [{ file: 'z.ts', line: 1, evidence: '5' }]),
    ]);
    expect(findings.map((f) => `${f.severity} ${f.file}:${f.line} ${f.ruleId}`)).toEqual([
      'critical z.ts:1 C-001',
      'low a.ts:1 B-001',
      'low a.ts:5 A-001',
      'low a.ts:5 B-001',
      'low b.ts:1 B-001',
    ]);
    expect([...findings].sort(compareFindings)).toEqual(findings);
  });

  it('suppresses findings marked with a shipcheck-ignore comment on the line or the line above', () => {
    const files: Record<string, string> = {
      'a.ts': ['// shipcheck-ignore: TEST-001', 'bad()', 'bad2() // shipcheck-ignore: OTHER-001, TEST-001', 'bad3()'].join('\n'),
    };
    const { findings, suppressedCount } = normalizeFindings(
      [
        run(testRule(), [
          { file: 'a.ts', line: 2, evidence: 'bad()' },
          { file: 'a.ts', line: 3, evidence: 'bad2()' },
          { file: 'a.ts', line: 4, evidence: 'bad3()' },
        ]),
      ],
      { readText: (file) => files[file] ?? '' },
    );
    expect(findings.map((f) => f.line)).toEqual([4]);
    expect(suppressedCount).toBe(2);
  });
});
