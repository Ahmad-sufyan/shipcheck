import { describe, expect, it } from 'vitest';
import { integ002 as rule } from '../../../src/packs/nextjs-supabase/rules/integ-002-cron-secret.js';
import { code, runRule } from '../../helpers/memory-context.js';

const get = (...body: string[]) => code('export async function GET(request: Request) {', ...body.map((l) => `  ${l}`), "  await pool.query('delete from sessions where expires_at < now()')", '  return Response.json({ ok: true })', '}');

describe('INTEG-002 Cron/internal endpoint without secret', () => {
  it('reports a cron route without an authorization check', async () => {
    expect(await runRule(rule, { 'app/api/cron/cleanup/route.ts': get() })).toEqual([
      { file: 'app/api/cron/cleanup/route.ts', line: 1, evidence: 'export async function GET(request: Request) {' },
    ]);
  });

  it('reports routes listed in vercel.json crons and internal job routes', async () => {
    const vercel = JSON.stringify({ crons: [{ path: '/api/maintenance', schedule: '0 * * * *' }] });
    expect(await runRule(rule, { 'app/api/maintenance/route.ts': get(), 'vercel.json': vercel })).toHaveLength(1);
    expect(await runRule(rule, { 'app/api/internal/reindex/route.ts': get() })).toHaveLength(1);
    expect(await runRule(rule, { 'app/api/jobs/route.ts': get() })).toHaveLength(1);
  });

  it('accepts a Bearer CRON_SECRET check', async () => {
    const check = "if (request.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) return new Response(null, { status: 401 })";
    expect(await runRule(rule, { 'app/api/cron/cleanup/route.ts': get(check) })).toEqual([]);
  });

  it('accepts QStash signature verification and signed-in users', async () => {
    const qstash = code("import { verifySignatureAppRouter } from '@upstash/qstash/nextjs'", 'export const POST = verifySignatureAppRouter(async () => Response.json({ ok: true }))');
    expect(await runRule(rule, { 'app/api/jobs/route.ts': qstash })).toEqual([]);
    expect(await runRule(rule, { 'app/api/internal/stats/route.ts': get('const { data } = await supabase.auth.getUser()') })).toEqual([]);
  });

  it('ignores ordinary routes', async () => {
    expect(await runRule(rule, { 'app/api/posts/route.ts': get() })).toEqual([]);
  });
});
