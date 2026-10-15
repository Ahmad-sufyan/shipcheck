import { describe, expect, it } from 'vitest';
import { auth003 as rule } from '../../../src/packs/nextjs-supabase/rules/auth-003-login-enumeration.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/login/route.ts';
const login = (...body: string[]) => code('export async function POST(request: Request) {', ...body.map((l) => `  ${l}`), '}');

describe('AUTH-003 Account enumeration on login', () => {
  it('reports a distinct "no such user" message', async () => {
    const text = login(
      'const user = await findUser(email)',
      "if (!user) return NextResponse.json({ error: 'No user with that email' }, { status: 401 })",
      "if (!(await bcrypt.compare(password, user.hash))) return NextResponse.json({ error: 'Wrong password' }, { status: 401 })",
    );
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([{ file: ROUTE, line: 3, evidence: "if (!user) return NextResponse.json({ error: 'No user with that email' }, { status: 401 })" }]);
  });

  it('recognises thrown errors in server actions', async () => {
    const text = code("'use server'", 'export async function signIn(email: string, password: string) {', '  const user = await findUser(email)', "  if (!user) throw new Error('User not found')", "  if (!(await bcrypt.compare(password, user.hash))) throw new Error('Incorrect password')", '}');
    expect(await runRule(rule, { 'app/login/actions.ts': text })).toEqual([expect.objectContaining({ line: 4 })]);
  });

  it('ignores a single generic message reused for every failure', async () => {
    const text = code("const INVALID = 'Invalid email or password'", login('if (!user) return NextResponse.json({ error: INVALID }, { status: 401 })', "if (!ok) return NextResponse.json({ error: INVALID }, { status: 401 })", "return NextResponse.json({ error: 'Too many attempts' }, { status: 429 })"));
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([]);
  });

  it('ignores handlers that are not logins', async () => {
    const text = code('export async function GET() {', "  if (!post) return NextResponse.json({ error: 'Post not found' }, { status: 404 })", "  return NextResponse.json({ error: 'Other' })", '}');
    expect(await runRule(rule, { 'app/api/posts/route.ts': text })).toEqual([]);
  });
});
