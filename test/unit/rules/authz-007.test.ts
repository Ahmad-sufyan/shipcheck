import { describe, expect, it } from 'vitest';
import { authz007 as rule } from '../../../src/packs/nextjs-supabase/rules/authz-007-service-role-client.js';
import { code, runRule } from '../../helpers/memory-context.js';

/** A fake, unsigned JWT with the given role, built at runtime so no key-shaped literal is committed. */
function fakeJwt(role: string): string {
  const part = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return [part({ alg: 'HS256', typ: 'JWT' }), part({ iss: 'supabase', role, exp: 2000000000 }), 'c2lnbmF0dXJl'].join('.');
}

describe('AUTHZ-007 service_role key in client code', () => {
  it('reports a client file that reads a SERVICE_ROLE env var', async () => {
    const text = code("'use client'", "import { createClient } from '@supabase/supabase-js'", 'const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!)');
    expect(await runRule(rule, { 'components/admin.tsx': text })).toEqual([expect.objectContaining({ file: 'components/admin.tsx', line: 3 })]);
  });

  it('reports a literal service_role JWT in a client file', async () => {
    const text = code("'use client'", `const key = '${fakeJwt('service_role')}'`);
    expect(await runRule(rule, { 'components/key.ts': text })).toEqual([expect.objectContaining({ line: 2 })]);
  });

  it('reports NEXT_PUBLIC_*SERVICE_ROLE* anywhere, including env files', async () => {
    expect(await runRule(rule, { 'lib/admin.ts': 'export const key = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY' })).toHaveLength(1);
    expect(await runRule(rule, { '.env.local': 'NEXT_PUBLIC_SUPABASE_URL=http://x\nNEXT_PUBLIC_SERVICE_ROLE_KEY=abc' })).toEqual([expect.objectContaining({ file: '.env.local', line: 2 })]);
  });

  it('ignores server-only use of the service role key', async () => {
    expect(await runRule(rule, { 'lib/supabase/admin.ts': "import 'server-only'\nexport const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)" })).toEqual([]);
  });

  it('ignores the anon key in client files', async () => {
    const text = code("'use client'", `const anon = '${fakeJwt('anon')}'`, 'const url = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY');
    expect(await runRule(rule, { 'components/client.ts': text })).toEqual([]);
  });
});
