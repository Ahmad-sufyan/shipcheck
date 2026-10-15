import { describe, expect, it } from 'vitest';
import { auth010 as rule } from '../../../src/packs/nextjs-supabase/rules/auth-010-weak-reset-token.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/password-reset/route.ts';
const post = (...body: string[]) => code('export async function POST(request: Request) {', ...body.map((l) => `  ${l}`), '}');
const store = "await pool.query('insert into password_resets (token, expires_at) values ($1, $2)', [token, expiresAt])";

describe('AUTH-010 Weak reset token', () => {
  it('reports a Math.random() reset token', async () => {
    expect(await runRule(rule, { [ROUTE]: post('const token = Math.random().toString(36).slice(2)', 'const expiresAt = new Date(Date.now() + 1800000)', store) })).toEqual([
      { file: ROUTE, line: 2, evidence: 'const token = Math.random().toString(36).slice(2)' },
    ]);
  });

  it('reports short randomBytes and uuid v1 tokens', async () => {
    expect(await runRule(rule, { [ROUTE]: post("const token = randomBytes(8).toString('hex')", 'const expiresAt = 1', store) })).toHaveLength(1);
    expect(await runRule(rule, { [ROUTE]: code("import { v1 as uuidv1 } from 'uuid'", post('const resetToken = uuidv1()', 'const expiresAt = 1', store)) })).toHaveLength(1);
  });

  it('adds an advisory finding when the token never expires or is never consumed', async () => {
    const findings = await runRule(rule, { [ROUTE]: post("const token = randomBytes(32).toString('hex')", "await pool.query('insert into password_resets (token) values ($1)', [token])") });
    expect(findings).toEqual([expect.objectContaining({ line: 1, advisory: true })]);
  });

  it('ignores strong tokens with an expiry', async () => {
    expect(await runRule(rule, { [ROUTE]: post("const token = randomBytes(32).toString('base64url')", 'const expiresAt = new Date(Date.now() + 1800000)', store) })).toEqual([]);
  });

  it('ignores Supabase-managed resets and non-reset handlers', async () => {
    expect(await runRule(rule, { [ROUTE]: post('await supabase.auth.resetPasswordForEmail(email)') })).toEqual([]);
    expect(await runRule(rule, { 'app/api/posts/route.ts': post('const token = Math.random().toString(36)') })).toEqual([]);
  });
});
