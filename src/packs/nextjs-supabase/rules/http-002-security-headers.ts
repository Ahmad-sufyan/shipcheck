import type { Rule } from '../../../types.js';
import { collectHeaders, headersAnchor } from '../analysis/headers-config.js';

export const http002: Rule = {
  id: 'HTTP-002',
  title: 'Missing security headers',
  category: 'http-config',
  severity: 'low',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports, in one finding, which of Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options (or CSP ' +
    'frame-ancestors), Referrer-Policy and Permissions-Policy are not set in next.config headers(), proxy/middleware, ' +
    'vercel.json or public/_headers. On Vercel, which sends HSTS by default, a finding about HSTS alone has low confidence.',
  explanation:
    'These headers switch on browser protections against clickjacking, MIME sniffing, protocol downgrade and leaking ' +
    'URLs to other sites; without them those protections stay off.',
  fix: "Return them from headers() in next.config for '/:path*', for example X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin, Permissions-Policy: camera=(), microphone=(), and frame-ancestors 'none' in the CSP.",
  falsePositiveNote: 'Headers added by the hosting platform or a CDN are not visible to this rule.',
  cwe: 'CWE-693',
  references: ['https://nextjs.org/docs/app/api-reference/config/next-config-js/headers', 'https://owasp.org/www-project-secure-headers/'],
  run(ctx) {
    const headers = collectHeaders(ctx);
    const keys = new Set(headers.map((h) => h.key));
    const frameAncestors = headers.some((h) => h.key === 'content-security-policy' && /frame-ancestors/i.test(h.value ?? ''));
    const missing = [
      keys.has('strict-transport-security') ? null : 'Strict-Transport-Security',
      keys.has('x-content-type-options') ? null : 'X-Content-Type-Options',
      keys.has('x-frame-options') || frameAncestors ? null : "X-Frame-Options (or CSP frame-ancestors)",
      keys.has('referrer-policy') ? null : 'Referrer-Policy',
      keys.has('permissions-policy') ? null : 'Permissions-Policy',
    ].filter((h): h is string => h !== null);
    if (!missing.length) return [];
    const onlyPlatformHsts = ctx.stacks.has('vercel') && missing.length === 1 && missing[0] === 'Strict-Transport-Security';
    return [
      {
        ...headersAnchor(ctx),
        explanation: `These security headers are not set: ${missing.join(', ')}. ${http002.explanation}`,
        ...(onlyPlatformHsts ? { confidence: 'low' as const } : {}),
      },
    ];
  },
};
