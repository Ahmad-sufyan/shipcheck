import { Node } from 'ts-morph';
import { describe, expect, it } from 'vitest';
import { findRouteHandlers, routePathFromFile } from '../../../../src/stacks/nextjs/routes.js';
import { memoryContext } from '../../../helpers/context.js';

describe('routePathFromFile', () => {
  it.each([
    ['app/route.ts', '/'],
    ['app/api/users/route.ts', '/api/users'],
    ['app/api/users/route.js', '/api/users'],
    ['src/app/api/invoices/[id]/route.ts', '/api/invoices/[id]'],
    ['app/(marketing)/api/subscribe/route.ts', '/api/subscribe'],
    ['app/(admin)/(nested)/api/x/route.tsx', '/api/x'],
    ['app/@modal/feed/route.ts', '/feed'],
    ['app/blog/[...slug]/route.ts', '/blog/[...slug]'],
    ['app/docs/[[...slug]]/route.ts', '/docs/[[...slug]]'],
  ])('%s -> %s', (file, routePath) => {
    expect(routePathFromFile(file)).toBe(routePath);
  });

  it.each([
    'app/_lib/route.ts',
    'app/api/users/page.tsx',
    'lib/route.ts',
    'app/api/route.test.ts',
    'pages/api/route.ts',
    'packages/app/api/route.ts',
  ])('%s is not a route handler', (file) => {
    expect(routePathFromFile(file)).toBeNull();
  });
});

describe('findRouteHandlers', () => {
  it('lists exported HTTP methods in every supported export style', () => {
    const ctx = memoryContext({
      'app/api/items/[id]/route.ts': [
        "import { withAuth } from '@/lib/auth'",
        'export const dynamic = "force-dynamic"',
        'export async function GET(request: Request) { return Response.json({}) }',
        'export function HEAD() { return new Response(null) }',
        'export const POST = async (request: Request) => Response.json({})',
        'export const PUT = function (request: Request) { return Response.json({}) }',
        'export const DELETE = withAuth(async () => Response.json({}))',
        'async function patchHandler() { return Response.json({}) }',
        'export { patchHandler as PATCH }',
        'export function helper() {}',
        "export { OPTIONS } from './shared'",
      ].join('\n'),
    });
    const handlers = findRouteHandlers(ctx);
    expect(handlers.map((h) => [h.method, h.node.getKindName(), h.node.getStartLineNumber()])).toEqual([
      ['GET', 'FunctionDeclaration', 3],
      ['POST', 'ArrowFunction', 5],
      ['PUT', 'FunctionExpression', 6],
      ['PATCH', 'FunctionDeclaration', 8],
      ['DELETE', 'CallExpression', 7],
      ['HEAD', 'FunctionDeclaration', 4],
    ]);
    expect(handlers.every((h) => h.file === 'app/api/items/[id]/route.ts' && h.routePath === '/api/items/[id]')).toBe(true);
  });

  it('sorts by file, then by method order', () => {
    const ctx = memoryContext({
      'app/b/route.ts': 'export function POST() {}\nexport function GET() {}',
      'app/a/route.ts': 'export function DELETE() {}',
      'app/a/page.tsx': 'export function GET() {}',
    });
    expect(findRouteHandlers(ctx).map((h) => `${h.file} ${h.method}`)).toEqual([
      'app/a/route.ts DELETE',
      'app/b/route.ts GET',
      'app/b/route.ts POST',
    ]);
  });

  it('returns AST nodes rules can inspect', () => {
    const ctx = memoryContext({ 'app/api/x/route.ts': 'export async function GET() {\n  const user = await getUser()\n}' });
    const [handler] = findRouteHandlers(ctx);
    expect(handler && Node.isFunctionDeclaration(handler.node)).toBe(true);
    expect(handler?.node.getText()).toContain('getUser()');
  });
});
