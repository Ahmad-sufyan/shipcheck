import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { z } from 'zod';
import type { Finding, SuppressedFinding } from '../types.js';
import { ShipcheckError } from './errors.js';

export const BASELINE_FILE = '.shipcheck-baseline.json';

const IsoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'must be a date like 2026-12-31');

export const BaselineEntrySchema = z.strictObject({
  /** The finding id (fingerprint), stable across unrelated edits. */
  id: z.string().regex(/^[0-9a-f]{16}$/, 'must be a 16-character finding id'),
  ruleId: z.string().min(1),
  /** Null for project-level and live findings. */
  file: z.string().nullable(),
  reason: z.string().trim().min(1, 'a reason is required'),
  acceptedBy: z.string().min(1).optional(),
  createdAt: IsoDate,
  /** Last day the entry suppresses its finding. */
  expires: IsoDate.optional(),
});

export const BaselineSchema = z.strictObject({
  $schema: z.string().optional(),
  version: z.literal(1),
  entries: z.array(BaselineEntrySchema),
});

export type BaselineEntry = z.infer<typeof BaselineEntrySchema>;
export type Baseline = z.infer<typeof BaselineSchema>;

/** Today as YYYY-MM-DD (UTC), the format baseline dates use. */
export function today(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

export function loadBaseline(file: string): Baseline {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, 'utf8').replace(/^﻿/, ''));
  } catch (error) {
    throw new ShipcheckError(`${file} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  const parsed = BaselineSchema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((issue) => `  - ${issue.path.map(String).join('.') || '(root)'}: ${issue.message}`);
    throw new ShipcheckError(`Invalid baseline in ${file}:\n${issues.join('\n')}`);
  }
  return parsed.data;
}

/** The baseline at `file`, or an empty one when the file does not exist. */
export function loadBaselineIfPresent(file: string): Baseline | undefined {
  return existsSync(file) ? loadBaseline(file) : undefined;
}

export function writeBaseline(file: string, baseline: Baseline): void {
  const entries = [...baseline.entries].sort((x, y) => x.ruleId.localeCompare(y.ruleId) || (x.file ?? '').localeCompare(y.file ?? '') || x.id.localeCompare(y.id));
  writeFileSync(file, `${JSON.stringify({ version: 1, entries }, null, 2)}\n`);
}

export function baselineEntry(finding: Finding, options: { reason: string; today: string; acceptedBy?: string; expires?: string }): BaselineEntry {
  const reason = options.reason.trim();
  if (!reason) throw new ShipcheckError('A baseline entry needs a reason (--reason "<why this finding is accepted>").');
  return {
    id: finding.id,
    ruleId: finding.ruleId,
    file: finding.file,
    reason,
    ...(options.acceptedBy ? { acceptedBy: options.acceptedBy } : {}),
    createdAt: options.today,
    ...(options.expires ? { expires: options.expires } : {}),
  };
}

/**
 * Hides findings listed in the baseline. Expired entries (expires < today) stop suppressing and produce a
 * warning, so accepted risk does not stay accepted forever by accident.
 */
export function applyBaseline(findings: readonly Finding[], baseline: Baseline | undefined, date: string): { findings: Finding[]; suppressed: SuppressedFinding[]; warnings: string[] } {
  if (!baseline) return { findings: [...findings], suppressed: [], warnings: [] };
  const active = new Map<string, BaselineEntry>();
  const warnings: string[] = [];
  for (const entry of baseline.entries) {
    if (entry.expires && entry.expires < date) warnings.push(`baseline entry ${entry.id} (${entry.ruleId}) expired on ${entry.expires} and no longer suppresses its finding`);
    else active.set(entry.id, entry);
  }
  const kept: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  for (const finding of findings) {
    const entry = active.get(finding.id);
    if (entry) suppressed.push({ id: finding.id, ruleId: finding.ruleId, reason: entry.reason });
    else kept.push(finding);
  }
  return { findings: kept, suppressed, warnings };
}

/** Drops entries that match none of the current findings. */
export function pruneBaseline(baseline: Baseline, findings: readonly Finding[]): { baseline: Baseline; removed: number } {
  const ids = new Set(findings.map((f) => f.id));
  const entries = baseline.entries.filter((entry) => ids.has(entry.id));
  return { baseline: { version: 1, entries }, removed: baseline.entries.length - entries.length };
}

/**
 * The baseline a scan uses: `false` disables it, a path must exist, and by default
 * <root>/.shipcheck-baseline.json is used when present.
 */
export function baselineFor(root: string, option: string | false | undefined): Baseline | undefined {
  if (option === false) return undefined;
  if (option === undefined) return loadBaselineIfPresent(join(root, BASELINE_FILE));
  const file = resolve(option);
  if (!existsSync(file)) throw new ShipcheckError(`Baseline file not found: ${option}`);
  return loadBaseline(file);
}
