import { describe, expect, expectTypeOf, it } from 'vitest';
import type { z } from 'zod';
import {
  CATEGORIES,
  FindingSchema,
  RawFindingSchema,
  ScanResultSchema,
  SEVERITIES,
  ShipcheckConfigSchema,
  scanResultJsonSchema,
} from '../../src/schema.js';
import type { Finding, RawFinding, ScanResult, ShipcheckConfig } from '../../src/types.js';

const finding: Finding = {
  id: '0123456789abcdef',
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
  explanation: 'x',
  fix: 'y',
  cwe: 'CWE-200',
  references: [],
};

function result(overrides: Partial<ScanResult> = {}): ScanResult {
  const byCategory = Object.fromEntries(CATEGORIES.map((c) => [c, 100])) as ScanResult['score']['byCategory'];
  return {
    schemaVersion: '1.0',
    tool: { name: 'shipcheck', version: '0.1.0' },
    target: { path: '.' },
    stack: ['nextjs-app-router'],
    score: { value: 99, grade: 'A', byCategory },
    findings: [finding],
    suppressedCount: 0,
    suppressed: [],
    warnings: [],
    skipped: [],
    ruleErrors: [],
    durationMs: 12,
    ...overrides,
  };
}

describe('schema', () => {
  it('orders severities from most to least severe', () => {
    expect(SEVERITIES).toEqual(['critical', 'high', 'medium', 'low', 'info']);
  });

  it('lists every category', () => {
    expect(CATEGORIES).toHaveLength(11);
    expect(CATEGORIES).toContain('rate-limiting');
  });

  it('keeps zod inferred types in sync with the hand-written interfaces', () => {
    expectTypeOf<z.infer<typeof FindingSchema>>().toEqualTypeOf<Finding>();
    expectTypeOf<z.infer<typeof ScanResultSchema>>().toEqualTypeOf<ScanResult>();
    expectTypeOf<z.output<typeof ShipcheckConfigSchema>>().toEqualTypeOf<ShipcheckConfig>();
    expectTypeOf<z.infer<typeof RawFindingSchema>>().toEqualTypeOf<RawFinding>();
  });

  it('fills config defaults', () => {
    expect(ShipcheckConfigSchema.parse({})).toEqual({
      ignorePaths: [],
      authHelpers: [],
      rateLimitHelpers: [],
      publicPaths: [],
      webhookVerifiers: [],
      rules: {},
    });
  });

  it('accepts publicPaths globs', () => {
    expect(ShipcheckConfigSchema.parse({ publicPaths: ['/api/public/**'] }).publicPaths).toEqual(['/api/public/**']);
    expect(ShipcheckConfigSchema.safeParse({ publicPaths: '/api/**' }).success).toBe(false);
  });

  it('accepts a per-finding advisory flag', () => {
    expect(RawFindingSchema.parse({ evidence: 'x', advisory: true }).advisory).toBe(true);
    expect(RawFindingSchema.safeParse({ evidence: 'x', advisory: 'yes' }).success).toBe(false);
  });

  it('accepts a $schema key and rule overrides', () => {
    const cfg = ShipcheckConfigSchema.parse({ $schema: './x.json', rules: { 'HTTP-006': 'off', 'SECRET-006': 'high' } });
    expect(cfg.rules).toEqual({ 'HTTP-006': 'off', 'SECRET-006': 'high' });
  });

  it('rejects unknown config keys and bad overrides', () => {
    expect(ShipcheckConfigSchema.safeParse({ ignorePath: [] }).success).toBe(false);
    expect(ShipcheckConfigSchema.safeParse({ rules: { 'HTTP-006': 'severe' } }).success).toBe(false);
  });

  it('validates raw findings', () => {
    expect(RawFindingSchema.safeParse({ evidence: 'x', file: 'a.ts', line: 3 }).success).toBe(true);
    expect(RawFindingSchema.safeParse({ file: 'a.ts' }).success).toBe(false);
    expect(RawFindingSchema.safeParse({ evidence: 'x', line: 0 }).success).toBe(false);
    expect(RawFindingSchema.safeParse({ evidence: 'x', line: 1.5 }).success).toBe(false);
    expect(RawFindingSchema.safeParse({ evidence: 'x', severity: 'severe' }).success).toBe(false);
  });

  it('validates a complete scan result', () => {
    expect(ScanResultSchema.parse(result())).toEqual(result());
    expect(ScanResultSchema.safeParse(result({ schemaVersion: '2.0' as '1.0' })).success).toBe(false);
  });

  it('requires every category score', () => {
    const r = result();
    const { secrets: _omit, ...partial } = r.score.byCategory;
    expect(ScanResultSchema.safeParse({ ...r, score: { ...r.score, byCategory: partial } }).success).toBe(false);
  });

  it('exports a JSON Schema for the scan result', () => {
    const schema = scanResultJsonSchema() as { $schema: string; type: string; required: string[]; properties: Record<string, unknown> };
    expect(schema.$schema).toContain('json-schema.org');
    expect(schema.type).toBe('object');
    expect(schema.required).toContain('findings');
    expect(Object.keys(schema.properties)).toContain('score');
  });
});
