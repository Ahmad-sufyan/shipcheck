import { createContext, type ContextOptions } from '../../src/context/build-context.js';
import { createMemorySource } from '../../src/context/files.js';
import { ShipcheckConfigSchema } from '../../src/schema.js';
import type { RawFinding, Rule, ScanContext, ShipcheckConfig } from '../../src/types.js';

/** A full ScanContext built from an in-memory file map; nothing touches the disk. */
export function memoryContext(files: Record<string, string>, config: Partial<ShipcheckConfig> = {}, options: ContextOptions = {}): ScanContext {
  return createContext(createMemorySource(files), ShipcheckConfigSchema.parse(config), options).ctx;
}

/** Runs one rule against an in-memory project and returns its raw findings. */
export async function runRule(rule: Rule, files: Record<string, string>, config: Partial<ShipcheckConfig> = {}, options: ContextOptions = {}): Promise<RawFinding[]> {
  return await rule.run(memoryContext(files, config, options));
}

/** Shorthand for asserting locations: `file:line` for each finding. */
export function locations(findings: readonly RawFinding[]): string[] {
  return findings.map((f) => `${f.file ?? '(project)'}:${f.line ?? '-'}`);
}

/** 1-based line of the first line containing `needle`; throws when absent so tests fail loudly. */
export function lineOf(text: string, needle: string): number {
  const index = text.split('\n').findIndex((line) => line.includes(needle));
  if (index === -1) throw new Error(`"${needle}" not found`);
  return index + 1;
}

/** Joins lines with \n; keeps multi-line fixtures readable in tests. */
export function code(...lines: string[]): string {
  return lines.join('\n');
}

/** Minimal Next.js + Supabase package.json for stack-sensitive tests. */
export const NEXT_SUPABASE_PACKAGE = JSON.stringify({ dependencies: { next: '16.4.1', '@supabase/ssr': '0.12.7', '@supabase/supabase-js': '2.117.3' } });
