import { computeScore } from '../../src/core/scoring.js';
import { fingerprint } from '../../src/core/fingerprint.js';
import type { Finding, ScanResult } from '../../src/types.js';

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  const base: Finding = {
    id: '',
    ruleId: 'SECRET-006',
    title: 'Production browser source maps enabled',
    category: 'secrets',
    severity: 'medium',
    confidence: 'high',
    advisory: false,
    source: 'static',
    file: 'next.config.mjs',
    line: 6,
    column: null,
    endLine: null,
    url: null,
    evidence: 'productionBrowserSourceMaps: true,',
    explanation: 'Anyone can download readable copies of your front-end code.',
    fix: 'Remove `productionBrowserSourceMaps`.',
    cwe: 'CWE-540',
    references: ['https://nextjs.org/docs/app/api-reference/config/next-config-js/productionBrowserSourceMaps'],
    ...overrides,
  };
  return { ...base, id: overrides.id ?? fingerprint(base) };
}

export function makeResult(findings: Finding[] = [], overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    schemaVersion: '1.0',
    tool: { name: 'shipcheck', version: '0.1.0' },
    target: { path: 'fixtures/demo-app' },
    stack: ['nextjs-app-router', 'supabase'],
    score: computeScore(findings),
    findings,
    suppressedCount: 0,
    suppressed: [],
    warnings: [],
    skipped: [],
    ruleErrors: [],
    durationMs: 42,
    ...overrides,
  };
}
