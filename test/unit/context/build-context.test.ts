import { describe, expect, it } from 'vitest';
import { buildContext, createContext } from '../../../src/context/build-context.js';
import { createMemorySource } from '../../../src/context/files.js';
import { ShipcheckConfigSchema } from '../../../src/schema.js';
import { tmpProject } from '../../helpers/context.js';

const config = ShipcheckConfigSchema.parse({ ignorePaths: ['legacy/**'] });

describe('buildContext', () => {
  it('builds a full context from a project on disk', async () => {
    const root = tmpProject({
      'package.json': JSON.stringify({ dependencies: { next: '16.4.1', '@supabase/ssr': '1.0.0' } }),
      'pnpm-lock.yaml': '',
      '.env.local': 'NEXT_PUBLIC_SUPABASE_URL=http://localhost:54321',
      '.gitignore': '.env*.local',
      'next.config.ts': 'export default { poweredByHeader: false }',
      'app/api/users/route.ts': 'export async function GET() {}',
      'app/actions.ts': "'use server'\nexport async function save() {}",
      'components/x.tsx': "'use client'\nexport function X() {}",
      'proxy.ts': "export function proxy() {}\nexport const config = { matcher: ['/dashboard/:path*'] }",
      'supabase/migrations/0001.sql': 'create table a();',
      'legacy/old.ts': 'ignored',
      'wrangler.toml': 'name = "x"',
    });
    const { ctx, skipped } = await buildContext(root, config);
    expect(ctx.root).toBe(root);
    expect(ctx.files).not.toContain('legacy/old.ts');
    expect([...ctx.stacks].sort()).toEqual(['cloudflare', 'nextjs-app-router', 'supabase']);
    expect(ctx.packageJson?.file).toBe('package.json');
    expect(ctx.lockfile).toEqual({ kind: 'pnpm', file: 'pnpm-lock.yaml' });
    expect(ctx.envFiles).toEqual([{ file: '.env.local', entries: [{ key: 'NEXT_PUBLIC_SUPABASE_URL', value: 'http://localhost:54321', line: 1 }] }]);
    expect(ctx.sqlMigrations.map((m) => m.file)).toEqual(['supabase/migrations/0001.sql']);
    expect(ctx.nextConfig?.options.poweredByHeader?.value).toBe(false);
    expect(ctx.gitignore?.patterns).toEqual(['.env*.local']);
    expect(ctx.wranglerToml?.data).toEqual({ name: 'x' });
    expect(ctx.vercelJson).toBeNull();
    expect(ctx.config).toBe(config);
    expect(skipped).toEqual([]);

    expect(ctx.next.routeHandlers().map((h) => `${h.method} ${h.routePath}`)).toEqual(['GET /api/users']);
    expect(ctx.next.serverActions().map((a) => a.name)).toEqual(['save']);
    expect(ctx.next.middleware()).toEqual({ file: 'proxy.ts', matchers: ['/dashboard/:path*'] });
    expect(ctx.next.isClientFile('components/x.tsx')).toBe(true);
    expect(ctx.next.isClientFile('app/actions.ts')).toBe(false);
  });
});

describe('createContext', () => {
  it('memoizes the Next.js helpers and source files', () => {
    const { ctx } = createContext(createMemorySource({ 'app/api/a/route.ts': 'export function GET() {}' }), config);
    expect(ctx.next.routeHandlers()).toBe(ctx.next.routeHandlers());
    expect(ctx.getSourceFile('app/api/a/route.ts')).toBe(ctx.getSourceFile('app/api/a/route.ts'));
  });
});
