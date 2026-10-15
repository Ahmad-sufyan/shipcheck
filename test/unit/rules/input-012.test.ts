import { describe, expect, it } from 'vitest';
import { input012 as rule } from '../../../src/packs/nextjs-supabase/rules/input-012-prototype-pollution.js';
import { code, locations, runRule } from '../../helpers/memory-context.js';

const unsafeMerge = code(
  'export function deepMerge(target: Record<string, any>, source: Record<string, any>) {',
  '  for (const key in source) {',
  "    if (typeof source[key] === 'object') target[key] = deepMerge(target[key] ?? {}, source[key])",
  '    else target[key] = source[key]',
  '  }',
  '  return target',
  '}',
);
const route = (call: string) => code("import { deepMerge } from '@/lib/merge'", 'export async function POST(request: Request) {', '  const body = await request.json()', `  const merged = ${call}`, '}');

describe('INPUT-012 Prototype pollution', () => {
  it('reports an unguarded recursive merge and the call that feeds it request data', async () => {
    const findings = await runRule(rule, { 'lib/merge.ts': unsafeMerge, 'app/api/settings/route.ts': route('deepMerge({}, body)') });
    expect(locations(findings)).toEqual(['lib/merge.ts:2', 'app/api/settings/route.ts:4']);
  });

  it('reports assignment through a request-controlled key and lodash merge of request data', async () => {
    const text = code("import _ from 'lodash'", 'export async function POST(request: Request) {', '  const { key, value } = await request.json()', '  const config: Record<string, unknown> = {}', '  config[key] = value', '  _.merge(config, await request.json())', '}');
    expect(locations(await runRule(rule, { 'app/api/config/route.ts': text }))).toEqual(['app/api/config/route.ts:5', 'app/api/config/route.ts:6']);
  });

  it('ignores merges that guard __proto__ (directly or through a constant)', async () => {
    const guarded = code("const BLOCKED = new Set(['__proto__', 'constructor', 'prototype'])", unsafeMerge.replace('  for (const key in source) {', '  for (const key in source) {\n    if (BLOCKED.has(key)) continue'));
    expect(await runRule(rule, { 'lib/merge.ts': guarded, 'app/api/settings/route.ts': route('deepMerge({}, body)') })).toEqual([]);
  });

  it('ignores unguarded merges that never receive request data', async () => {
    expect(await runRule(rule, { 'lib/merge.ts': unsafeMerge, 'app/api/settings/route.ts': route('deepMerge({}, Schema.parse(body))') })).toEqual([]);
  });
});
