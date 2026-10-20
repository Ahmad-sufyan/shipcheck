import type { LiveCheck } from '../context.js';
import { HOME_STEP } from '../context.js';

type Headers = Record<string, string>;

const META_CSP = /<meta[^>]+http-equiv=["']?content-security-policy/i;

const EXPECTED: readonly [string, (headers: Headers, body: string) => boolean][] = [
  ['CSP', (h, body) => Boolean(h['content-security-policy']) || META_CSP.test(body)],
  ['HSTS', (h) => Boolean(h['strict-transport-security'])],
  ['X-Content-Type-Options', (h) => /nosniff/i.test(h['x-content-type-options'] ?? '')],
  ['X-Frame-Options/frame-ancestors', (h) => /frame-ancestors/i.test(h['content-security-policy'] ?? '') || Boolean(h['x-frame-options'])],
  ['Referrer-Policy', (h) => Boolean(h['referrer-policy'])],
  ['Permissions-Policy', (h) => Boolean(h['permissions-policy'])],
];

export const live001: LiveCheck = {
  id: 'LIVE-001',
  title: 'Security headers not served',
  category: 'live',
  severity: 'medium',
  confidence: 'high',
  stacks: [],
  source: 'live',
  description:
    'Fetches / from the deployed site and reports, in one finding, which of Content-Security-Policy, ' +
    'Strict-Transport-Security, X-Content-Type-Options, frame-ancestors (or X-Frame-Options), Referrer-Policy and ' +
    'Permissions-Policy are missing, and whether X-Powered-By or a Server header with a version number is sent. Unlike ' +
    'HTTP-001/HTTP-002 this sees headers added or removed by the platform and CDN.',
  explanation:
    'The live site does not send the headers browsers use to block script injection, clickjacking, MIME sniffing and ' +
    'downgrade attacks, or it advertises the exact server software, which helps attackers pick exploits.',
  fix: 'Set the headers for every route (next.config headers() with source "/:path*", middleware, or the CDN), remove X-Powered-By (poweredByHeader: false) and hide server versions.',
  falsePositiveNote: 'Headers set only on some paths are reported when / lacks them; check that / is representative.',
  cwe: 'CWE-693',
  references: ['https://owasp.org/www-project-secure-headers/', 'https://nextjs.org/docs/app/api-reference/config/next-config-js/headers'],
  plan: (target) => [HOME_STEP(target, 'LIVE-001 headers, LIVE-002 HSTS, LIVE-005 first script, LIVE-006 cookies')],
  async run(ctx) {
    const home = await ctx.home();
    if (home.status >= 500) {
      ctx.skip('LIVE-001', `GET / returned HTTP ${home.status}; error pages are not representative`);
      return [];
    }
    const missing = EXPECTED.filter(([, present]) => !present(home.headers, home.text)).map(([name]) => name);
    const exposed: string[] = [];
    // Short names keep the evidence under the 200-character cap.
    if (home.headers['x-powered-by']) exposed.push(`X-Powered-By: ${home.headers['x-powered-by']}`);
    if (/\d/.test(home.headers.server ?? '')) exposed.push(`Server: ${home.headers.server}`);
    if (!missing.length && !exposed.length) return [];
    const parts = [missing.length ? `missing ${missing.join(', ')}` : '', exposed.length ? `exposes ${exposed.join(', ')}` : ''].filter(Boolean);
    return [{ url: home.url, evidence: `GET / (HTTP ${home.status}): ${parts.join('; ')}` }];
  },
};
