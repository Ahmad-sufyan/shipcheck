import { describe, expect, it } from 'vitest';
import { auth011 as rule } from '../../../src/packs/nextjs-supabase/rules/auth-011-reset-enumeration.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/password-reset/route.ts';
const post = (...body: string[]) => code('export async function POST(request: Request) {', ...body.map((l) => `  ${l}`), "  return NextResponse.json({ ok: true })", '}');

describe('AUTH-011 Password reset account enumeration', () => {
  it('reports a 404 for unknown accounts', async () => {
    expect(await runRule(rule, { [ROUTE]: post("if (!user) return NextResponse.json({ error: 'Not found' }, { status: 404 })") })).toEqual([
      { file: ROUTE, line: 2, evidence: "if (!user) return NextResponse.json({ error: 'Not found' }, { status: 404 })" },
    ]);
  });

  it('reports a message that reveals the account does not exist', async () => {
    expect(await runRule(rule, { [ROUTE]: post("if (!user) return NextResponse.json({ error: 'No account with that email' }, { status: 400 })") })).toHaveLength(1);
    expect(await runRule(rule, { [ROUTE]: post("if (!user) return NextResponse.json({ message: 'This email is not registered' })") })).toHaveLength(1);
  });

  it('ignores a constant response', async () => {
    expect(await runRule(rule, { [ROUTE]: post("return NextResponse.json({ message: 'If an account exists, a link is on its way.' })") })).toEqual([]);
  });

  it('ignores handlers that are not password resets', async () => {
    expect(await runRule(rule, { 'app/api/posts/route.ts': post("if (!post) return NextResponse.json({ error: 'Not found' }, { status: 404 })") })).toEqual([]);
  });
});
