import { describe, expect, it } from 'vitest';
import { input011 as rule } from '../../../src/packs/nextjs-supabase/rules/input-011-redos.js';
import { code, runRule } from '../../helpers/memory-context.js';

describe('INPUT-011 ReDoS-prone regex', () => {
  it('reports a literal with nested quantifiers with low confidence', async () => {
    const text = code('const EMAIL = /^([a-zA-Z0-9_.+-]+)+@example\\.com$/', 'export const isValid = (v: string) => EMAIL.test(v)');
    expect(await runRule(rule, { 'lib/validate.ts': text })).toEqual([{ file: 'lib/validate.ts', line: 1, evidence: 'const EMAIL = /^([a-zA-Z0-9_.+-]+)+@example\\.com$/', confidence: 'low' }]);
  });

  it('reports new RegExp() with a literal pattern', async () => {
    expect(await runRule(rule, { 'lib/a.ts': "export const re = new RegExp('(a|aa)*(b+)+$')" })).toHaveLength(1);
  });

  it('raises confidence when the regex is applied to request input', async () => {
    const text = code('export async function GET(request: NextRequest) {', "  const q = request.nextUrl.searchParams.get('q') ?? ''", '  return Response.json({ ok: /^(\\w+\\s?)*$/.test(q) })', '}');
    expect(await runRule(rule, { 'app/api/check/route.ts': text })).toEqual([expect.objectContaining({ line: 3, confidence: 'high' })]);
  });

  it('ignores simple patterns and dynamic RegExp sources', async () => {
    expect(await runRule(rule, { 'lib/a.ts': code('export const email = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/', 'export const make = (s: string) => new RegExp(s)') })).toEqual([]);
  });
});
