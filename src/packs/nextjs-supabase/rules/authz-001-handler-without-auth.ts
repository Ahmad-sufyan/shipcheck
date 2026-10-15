import type { RawFinding, Rule } from '../../../types.js';
import { findingAt } from '../analysis/ast-utils.js';
import { hasAuthCheck, isIntentionallyPublic, middlewareAuthCovers, usesOnlyGetSession } from '../analysis/auth-check.js';
import { touchesData } from '../analysis/db-write.js';
import { entries, MUTATING_METHODS } from '../analysis/entries.js';

/** Path segments that suggest per-user or privileged data even on read-only endpoints. */
const PRIVATE_SEGMENT = /^(?:admin|dashboard|account|accounts|settings|billing|me|profile|profiles|user|users|invoices|orders|private|internal|team|teams)$/i;

export const authz001: Rule = {
  id: 'AUTHZ-001',
  title: 'Handler without auth check',
  category: 'authorization',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports route handlers and server actions that can be called without a session. A finding needs: a mutating method ' +
    '(POST, PUT, PATCH, DELETE), a server action that touches data, or a GET on a private-looking path (admin, account, ' +
    'settings, users, ...) that touches the database, filesystem or network; no auth call in the handler or a same-file helper ' +
    '(supabase.auth.getUser/getClaims, Auth.js auth(), getServerSession, Clerk, or config.authHelpers); no auth-checking ' +
    'proxy covering the path; and a path that is not a sign-in flow, webhook, cron or health route and not in ' +
    'config.publicPaths. Database writes raise it to critical. Limitations: helpers imported from other files only count when ' +
    'listed in authHelpers, and supabase.auth.getSession() is not accepted because Supabase says it must not be trusted on the server.',
  explanation:
    'Anyone on the internet can call this endpoint directly, without signing in, and it reads or changes data. Route ' +
    'handlers and server actions are public URLs even when no page links to them.',
  fix:
    'Verify the user at the top of the handler, for example `const { data: { user } } = await supabase.auth.getUser()` and ' +
    'return 401 when there is no user. Add a role check for admin endpoints. If the endpoint is meant to be public, add its ' +
    'path to publicPaths in shipcheck.config.json.',
  falsePositiveNote:
    'Intentionally public endpoints should be listed in config.publicPaths; auth done by a helper imported from another file ' +
    'should be listed in config.authHelpers.',
  cwe: 'CWE-306',
  references: ['https://nextjs.org/docs/app/guides/data-security', 'https://supabase.com/docs/guides/auth/server-side/nextjs'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      if (entry.kind === 'route' && entry.routePath !== undefined) {
        if (isIntentionallyPublic(entry.routePath, ctx) || middlewareAuthCovers(entry.routePath, ctx)) continue;
      }
      if (hasAuthCheck(entry.node, ctx)) continue;

      const access = touchesData(entry.node);
      const touchesAnything = access.db || access.fs || access.fetch;
      const extra: Partial<RawFinding> = {};
      if (entry.kind === 'action') {
        if (!touchesAnything) continue;
      } else if (!MUTATING_METHODS.has(entry.method ?? '')) {
        const privatePath = (entry.routePath ?? '').split('/').some((segment) => PRIVATE_SEGMENT.test(segment));
        if (!touchesAnything || !privatePath) continue;
        extra.confidence = 'medium';
      }
      if (access.write) extra.severity = 'critical';
      if (usesOnlyGetSession(entry.node, ctx)) {
        extra.explanation =
          'This endpoint only calls supabase.auth.getSession(). Supabase documents that the session it returns comes from the ' +
          'cookie and must not be trusted in server code, so anyone can forge it. Use getClaims() or getUser() instead.';
      }
      findings.push(findingAt(entry.node, extra));
    }
    return findings;
  },
};
