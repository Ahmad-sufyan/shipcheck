import { z } from 'zod';
import type { Category, Confidence, FindingSource, Severity, StackId } from './types.js';

/** Most severe first. Array order is the sort order. */
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const satisfies readonly Severity[];
export const CONFIDENCES = ['high', 'medium', 'low'] as const satisfies readonly Confidence[];
export const CATEGORIES = [
  'authentication',
  'authorization',
  'rate-limiting',
  'input-validation',
  'secrets',
  'dependencies',
  'http-config',
  'data-protection',
  'integrations',
  'infra',
  'live',
] as const satisfies readonly Category[];
export const FINDING_SOURCES = ['static', 'tool:gitleaks', 'tool:osv', 'tool:npm-audit', 'live'] as const satisfies readonly FindingSource[];
export const STACK_IDS = ['nextjs-app-router', 'supabase', 'vercel', 'cloudflare'] as const satisfies readonly StackId[];

/** 0 = critical ... 4 = info. */
export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity);
}

export const SeveritySchema = z.enum(SEVERITIES);
export const ConfidenceSchema = z.enum(CONFIDENCES);
export const CategorySchema = z.enum(CATEGORIES);
export const FindingSourceSchema = z.enum(FINDING_SOURCES);
export const StackIdSchema = z.enum(STACK_IDS);

const positiveInt = z.number().int().positive();

export const RawFindingSchema = z.object({
  file: z.string().min(1).optional(),
  line: positiveInt.optional(),
  column: positiveInt.optional(),
  endLine: positiveInt.optional(),
  url: z.string().min(1).optional(),
  evidence: z.string(),
  explanation: z.string().optional(),
  fix: z.string().optional(),
  severity: SeveritySchema.optional(),
  confidence: ConfidenceSchema.optional(),
  advisory: z.boolean().optional(),
});

export const FindingSchema = z.object({
  id: z.string().regex(/^[0-9a-f]{16}$/),
  ruleId: z.string(),
  title: z.string(),
  category: CategorySchema,
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  advisory: z.boolean(),
  source: FindingSourceSchema,
  file: z.string().nullable(),
  line: positiveInt.nullable(),
  column: positiveInt.nullable(),
  endLine: positiveInt.nullable(),
  url: z.string().nullable(),
  evidence: z.string(),
  explanation: z.string(),
  fix: z.string(),
  cwe: z.string().optional(),
  references: z.array(z.string()),
});

export const GradeSchema = z.enum(['A', 'B', 'C', 'D', 'F']);

export const ScanResultSchema = z
  .object({
    schemaVersion: z.literal('1.0'),
    tool: z.object({ name: z.literal('shipcheck'), version: z.string() }),
    target: z.object({ path: z.string() }),
    stack: z.array(StackIdSchema),
    score: z.object({
      value: z.number().min(0).max(100),
      grade: GradeSchema,
      byCategory: z.record(CategorySchema, z.number().min(0).max(100)),
    }),
    findings: z.array(FindingSchema),
    suppressedCount: z.number().int().min(0),
    skipped: z.array(z.object({ check: z.string(), reason: z.string() })),
    ruleErrors: z.array(z.object({ ruleId: z.string(), message: z.string() })),
    durationMs: z.number().min(0),
  })
  .meta({ title: 'shipcheck scan result', description: 'Output of `shipcheck scan --format json`.' });

export const RuleOverrideSchema = z.union([z.literal('off'), SeveritySchema]);

export const ShipcheckConfigSchema = z
  .strictObject({
    $schema: z.string().optional(),
    ignorePaths: z.array(z.string()).default([]),
    authHelpers: z.array(z.string()).default([]),
    rateLimitHelpers: z.array(z.string()).default([]),
    publicPaths: z.array(z.string()).default([]),
    rules: z.record(z.string(), RuleOverrideSchema).default({}),
  })
  .transform(({ $schema: _schema, ...config }) => config);

/** Static metadata every rule must carry; checked when a rule is registered. */
export const RuleMetaSchema = z.object({
  id: z.string().regex(/^[A-Z][A-Z0-9]*-\d{3}$/),
  title: z.string().min(1),
  category: CategorySchema,
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  advisory: z.boolean().optional(),
  stacks: z.array(StackIdSchema),
  source: FindingSourceSchema.optional(),
  description: z.string().min(1),
  explanation: z.string().min(1),
  fix: z.string().min(1),
  falsePositiveNote: z.string().min(1),
  cwe: z.string().regex(/^CWE-\d+$/).optional(),
  references: z.array(z.string()).optional(),
  run: z.custom<(...args: never[]) => unknown>((v) => typeof v === 'function', 'run must be a function'),
});

/** JSON Schema (draft 2020-12) for {@link ScanResultSchema}, for consumers outside TypeScript. */
export function scanResultJsonSchema(): Record<string, unknown> {
  return z.toJSONSchema(ScanResultSchema, { target: 'draft-2020-12' }) as Record<string, unknown>;
}
