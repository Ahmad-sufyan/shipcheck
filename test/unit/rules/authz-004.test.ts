import { describe, expect, it } from 'vitest';
import { authz004 as rule } from '../../../src/packs/nextjs-supabase/rules/authz-004-client-role-check.js';
import { code, locations, runRule } from '../../helpers/memory-context.js';

const panel = code(
  "'use client'",
  'export function AdminPanel({ role }: { role: string }) {',
  "  const isAdmin = role === 'admin'",
  "  useEffect(() => { if (isAdmin) fetch('/api/admin/stats').then((r) => r.json()) }, [isAdmin])",
  '  return isAdmin ? <Stats /> : null',
  '}',
);
const unprotected = code('export async function GET() {', '  const { data: { user } } = await supabase.auth.getUser()', "  if (!user) return new Response(null, { status: 401 })", "  return Response.json(await supabase.from('invoices').select('*'))", '}');

describe('AUTHZ-004 Role check only on client', () => {
  it('reports the client role check and the API route that never checks the role', async () => {
    const findings = await runRule(rule, { 'components/admin-panel.tsx': panel, 'app/api/admin/stats/route.ts': unprotected });
    expect(locations(findings)).toEqual(['components/admin-panel.tsx:3', 'app/api/admin/stats/route.ts:1']);
  });

  it('matches dynamic route segments', async () => {
    const dynamicPanel = panel.replace("'/api/admin/stats'", "'/api/admin/users/42'");
    expect(await runRule(rule, { 'components/admin-panel.tsx': dynamicPanel, 'app/api/admin/users/[id]/route.ts': unprotected })).toHaveLength(2);
  });

  it('ignores routes that check the role on the server', async () => {
    const checked = unprotected.replace("if (!user) return new Response(null, { status: 401 })", "if (user?.app_metadata.role !== 'admin') return new Response(null, { status: 403 })");
    expect(await runRule(rule, { 'components/admin-panel.tsx': panel, 'app/api/admin/stats/route.ts': checked })).toEqual([]);
  });

  it('ignores server components and client files that fetch nothing', async () => {
    expect(await runRule(rule, { 'components/admin-panel.tsx': panel.replace("'use client'\n", ''), 'app/api/admin/stats/route.ts': unprotected })).toEqual([]);
    const noFetch = code("'use client'", 'export const Badge = ({ role }: { role: string }) => (role === "admin" ? <b>Admin</b> : null)');
    expect(await runRule(rule, { 'components/badge.tsx': noFetch })).toEqual([]);
  });
});
