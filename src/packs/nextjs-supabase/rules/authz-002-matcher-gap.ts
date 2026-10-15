import { Node } from 'ts-morph';
import type { Rule } from '../../../types.js';
import { findingAt } from '../analysis/ast-utils.js';
import { hasAuthCheck, isIntentionallyPublic, middlewareChecksAuth } from '../analysis/auth-check.js';
import { entries, pages } from '../analysis/entries.js';
import { isCoveredByMatchers } from '../analysis/route-match.js';

const SENSITIVE_PREFIX = /^\/(?:api|admin|dashboard|account|settings)(?:\/|$)/;
const MAX_LISTED = 8;

export const authz002: Rule = {
  id: 'AUTHZ-002',
  title: 'Middleware matcher gap',
  category: 'authorization',
  severity: 'medium',
  confidence: 'medium',
  stacks: ['nextjs-app-router'],
  description:
    'When proxy.ts/middleware.ts checks auth but limits itself with config.matcher, routes under /api, /admin, /dashboard, ' +
    '/account or /settings that the matchers miss get no protection from it. The rule compiles matchers the way Next.js ' +
    'does (path-to-regexp 6.3.0) and reports once, at the matcher, listing uncovered routes that also lack their own auth ' +
    'check. Sign-in flows, webhooks and config.publicPaths are excluded. Limitations: has/missing conditions on matcher ' +
    'objects are ignored.',
  explanation:
    'Your proxy protects only the paths in its matcher. The routes listed here sit outside it and do not check the session ' +
    'themselves, so they are reachable without signing in.',
  fix: 'Extend config.matcher to cover these routes (for example add `/api/:path*`), or check the session inside each route handler.',
  falsePositiveNote: 'Routes that are deliberately public should be listed in config.publicPaths.',
  cwe: 'CWE-862',
  references: ['https://nextjs.org/docs/app/api-reference/file-conventions/proxy#matcher', 'https://nextjs.org/docs/app/guides/data-security'],
  run(ctx) {
    const middleware = ctx.next.middleware();
    if (!middleware || middleware.matchers === null || !middlewareChecksAuth(ctx)) return [];
    const matchers = middleware.matchers;

    const uncovered = new Set<string>();
    const consider = (routePath: string, node: Node | undefined) => {
      if (!SENSITIVE_PREFIX.test(routePath) || isIntentionallyPublic(routePath, ctx) || isCoveredByMatchers(routePath, matchers)) return;
      if (node && hasAuthCheck(node, ctx)) return;
      uncovered.add(routePath);
    };
    for (const entry of entries(ctx)) if (entry.kind === 'route' && entry.routePath) consider(entry.routePath, entry.node);
    for (const page of pages(ctx)) consider(page.routePath, page.fn);
    if (!uncovered.size) return [];

    const config = ctx.getSourceFile(middleware.file).getVariableDeclaration('config')?.getInitializer();
    const matcher = config && Node.isObjectLiteralExpression(config) ? config.getProperty('matcher') : undefined;
    const anchor = matcher ?? config;
    if (!anchor) return [];

    const routes = [...uncovered].sort();
    const listed = routes.slice(0, MAX_LISTED).join(', ') + (routes.length > MAX_LISTED ? ` and ${routes.length - MAX_LISTED} more` : '');
    return [
      findingAt(anchor, {
        explanation: `Your proxy protects only the paths in its matcher. These routes sit outside it and do not check the session themselves, so they are reachable without signing in: ${listed}.`,
      }),
    ];
  },
};
