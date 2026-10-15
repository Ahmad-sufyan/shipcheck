import { describe, expect, it } from 'vitest';
import { data004 as rule } from '../../../src/packs/nextjs-supabase/rules/data-004-auth-audit-log.js';
import { code, runRule } from '../../helpers/memory-context.js';

const login = (...body: string[]) => code('export async function POST(request: Request) {', '  await supabase.auth.signInWithPassword(await request.json())', ...body.map((l) => `  ${l}`), '}');

describe('DATA-004 No auth audit logging', () => {
  it('reports once, without a file, when auth handlers record nothing', async () => {
    const findings = await runRule(rule, { 'app/api/login/route.ts': login(), 'app/api/logout/route.ts': 'export async function POST() { await supabase.auth.signOut() }' });
    expect(findings).toHaveLength(1);
    expect(findings[0]).not.toHaveProperty('file');
  });

  it.each([
    ['an audit helper', "await recordAuditEvent({ action: 'login' })"],
    ['an audit table insert', "await supabase.from('audit_log').insert({ action: 'login' })"],
    ['SQL into an auth events table', "await pool.query('insert into auth_events (kind) values ($1)', ['login'])"],
  ])('is satisfied by %s', async (_name, line) => {
    expect(await runRule(rule, { 'app/api/login/route.ts': login(line) })).toEqual([]);
  });

  it('ignores projects without login, logout or reset handlers', async () => {
    expect(await runRule(rule, { 'app/api/posts/route.ts': 'export async function GET() { return Response.json([]) }' })).toEqual([]);
  });
});
