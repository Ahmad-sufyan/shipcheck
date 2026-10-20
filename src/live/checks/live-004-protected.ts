import type { RawFinding } from '../../types.js';
import type { LiveCheck } from '../context.js';
import { absolute } from '../context.js';

export const live004: LiveCheck = {
  id: 'LIVE-004',
  title: 'Protected endpoint open',
  category: 'live',
  severity: 'high',
  confidence: 'high',
  stacks: [],
  source: 'live',
  description:
    'Requests each live.protectedPaths entry without cookies or credentials. 401, 403 and redirects to a login path pass; ' +
    'a 2xx response with a non-empty body is reported. Other statuses (404, redirects elsewhere) are not reported.',
  explanation: 'A page or API that should require sign-in answered an anonymous request with content.',
  fix: 'Check the session on the server for every protected route (route handler, server component or middleware with a matcher that covers it) and answer 401/403 or redirect to the login page.',
  falsePositiveNote: 'Some protected pages serve a public shell and load data client-side after sign-in; the shell alone is not a leak.',
  cwe: 'CWE-306',
  references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
  plan: (target) => target.config.protectedPaths.map((p) => ({ kind: 'http', method: p.method ?? 'GET', target: absolute(target, p.path), purpose: 'LIVE-004 must refuse anonymous access' })),
  async run(ctx) {
    if (!ctx.config.protectedPaths.length) {
      ctx.skip('LIVE-004', 'no live.protectedPaths configured');
      return [];
    }
    const findings: RawFinding[] = [];
    for (const { path, method = 'GET' } of ctx.config.protectedPaths) {
      const response = await ctx.client.request(method, path);
      if (response.status < 200 || response.status >= 300) continue;
      const length = method === 'HEAD' ? Number(response.headers['content-length'] ?? 0) : response.text.trim() ? response.body.length : 0;
      if (length > 0) findings.push({ url: response.url, evidence: `${method} ${path} without credentials → HTTP ${response.status} with a ${length}-byte body` });
    }
    return findings;
  },
};

