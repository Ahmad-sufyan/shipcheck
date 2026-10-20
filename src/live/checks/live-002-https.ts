import type { RawFinding } from '../../types.js';
import type { LiveCheck } from '../context.js';
import { LiveRequestError } from '../errors.js';

/** Six months, the minimum HSTS max-age browsers' preload lists accept. */
export const MIN_HSTS_MAX_AGE = 15_552_000;
const CERT_WARNING_DAYS = 14;
const DAY_MS = 86_400_000;

export const live002: LiveCheck = {
  id: 'LIVE-002',
  title: 'HTTPS not enforced',
  category: 'live',
  severity: 'high',
  confidence: 'high',
  stacks: [],
  source: 'live',
  description:
    'Requests http://<host>/ and reports (high) when it does not answer with a 301 or 308 redirect to https:// on the ' +
    'same host. Also reports (medium) a Strict-Transport-Security max-age below 15552000 seconds on / and, for https ' +
    'sites, a TLS certificate that expires within 14 days. A host that does not listen on port 80 at all passes.',
  explanation:
    'Visitors who type the domain or follow an http:// link reach the site unencrypted first, where anyone on the network ' +
    'can read or rewrite the traffic, and a short or missing HSTS policy lets that happen again on later visits.',
  fix: 'Redirect all HTTP traffic with a 301/308 to https://, send `Strict-Transport-Security: max-age=63072000; includeSubDomains`, and let the platform renew certificates automatically.',
  falsePositiveNote: 'Staging hosts sometimes skip HTTPS enforcement on purpose; point live checks at production.',
  cwe: 'CWE-319',
  references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security', 'https://hstspreload.org/'],
  plan: (target) => [
    { kind: 'http', method: 'GET', target: target.httpOrigin.href, purpose: 'LIVE-002 HTTP to HTTPS redirect' },
    ...(target.origin.protocol === 'https:' ? [{ kind: 'tls' as const, target: `${target.origin.hostname}:443`, purpose: 'LIVE-002 certificate expiry (TLS handshake only; counts toward the budget)' }] : []),
  ],
  async run(ctx) {
    const findings: RawFinding[] = [];
    try {
      const response = await ctx.client.request('GET', ctx.httpOrigin.href);
      if (response.status >= 500) throw new LiveRequestError(`GET ${ctx.httpOrigin.href} returned HTTP ${response.status}`);
      const location = response.headers.location;
      const next = location ? new URL(location, ctx.httpOrigin) : undefined;
      const redirectsToHttps = (response.status === 301 || response.status === 308) && next?.protocol === 'https:' && next.hostname === ctx.origin.hostname;
      if (!redirectsToHttps) {
        findings.push({
          url: ctx.httpOrigin.href,
          evidence: `GET ${ctx.httpOrigin.href} → HTTP ${response.status}${location ? ` (Location: ${location})` : ''}`,
          explanation:
            response.status >= 300 && response.status < 400
              ? 'Plain HTTP redirects, but not with a permanent 301/308 to https:// on the same host, so browsers do not remember it and HSTS preloading is not possible.'
              : 'The site answers over plain HTTP instead of redirecting to HTTPS.',
        });
      }
    } catch (error) {
      if (!(error instanceof LiveRequestError)) throw error;
      // Nothing listens on port 80: there is no plaintext entry point to enforce.
    }

    const home = await ctx.home();
    const hsts = home.headers['strict-transport-security'];
    const maxAge = hsts ? Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts)?.[1] ?? 0) : undefined;
    if (maxAge !== undefined && maxAge < MIN_HSTS_MAX_AGE) {
      findings.push({
        url: home.url,
        evidence: `Strict-Transport-Security: ${hsts}`,
        severity: 'medium',
        explanation: `The HSTS max-age of ${maxAge} seconds is below six months (${MIN_HSTS_MAX_AGE}), so browsers forget to insist on HTTPS too soon.`,
      });
    }

    if (ctx.origin.protocol === 'https:') {
      try {
        const { validTo } = await ctx.client.certificate();
        const days = Math.floor((validTo.getTime() - ctx.now.getTime()) / DAY_MS);
        if (days < CERT_WARNING_DAYS) {
          findings.push({
            url: ctx.origin.href,
            evidence: `TLS certificate for ${ctx.origin.hostname} ${days < 0 ? 'expired' : 'expires'} on ${validTo.toISOString().slice(0, 10)}`,
            severity: 'medium',
            explanation: `The certificate ${days < 0 ? 'has expired' : `expires in ${days} day${days === 1 ? '' : 's'}`}; when it does, browsers block the site with a full-page warning.`,
            fix: 'Renew the certificate now and check that automatic renewal works (Vercel and Cloudflare renew managed certificates themselves).',
          });
        }
      } catch (error) {
        if (!(error instanceof LiveRequestError)) throw error;
        ctx.skip('LIVE-002', `certificate expiry not checked: ${error.message}`);
      }
    }
    return findings;
  },
};
