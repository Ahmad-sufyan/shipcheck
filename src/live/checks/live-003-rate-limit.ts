import type { LiveCheck } from '../context.js';
import { absolute } from '../context.js';

/** Hard cap on the probe, whatever the config says. */
export const MAX_PROBE_REQUESTS = 30;
export const PROBE_SPACING_MS = 100;

export const live003: LiveCheck = {
  id: 'LIVE-003',
  title: 'Rate limit does not trigger',
  category: 'live',
  severity: 'medium',
  confidence: 'medium',
  stacks: [],
  source: 'live',
  description:
    'Sends the configured live.rateLimitProbe request (no body, no credentials) up to its maxRequests times, never more ' +
    'than 30, 100 ms apart, and stops at the first 429 (or 403 with Retry-After). Reports when no response signals a ' +
    'limit. Skipped when no probe is configured or the remaining request budget is too small.',
  explanation: 'Repeated requests to this endpoint were all accepted, so attackers can brute-force or spam it at full speed.',
  fix: 'Put a per-IP and per-account limiter (Upstash, Vercel KV, Cloudflare rate limiting rules) in front of the endpoint and answer 429 with Retry-After.',
  falsePositiveNote: 'Endpoints with intentionally high limits will not trigger within 30 requests; lower the threshold on auth endpoints anyway.',
  cwe: 'CWE-307',
  references: ['https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks'],
  plan(target) {
    const probe = target.config.rateLimitProbe;
    if (!probe) return [];
    return [{ kind: 'http', method: probe.method, target: absolute(target, probe.path), count: Math.min(probe.maxRequests, MAX_PROBE_REQUESTS), purpose: 'LIVE-003 rate limit probe, 100 ms apart, stops at the first 429' }];
  },
  async run(ctx) {
    const probe = ctx.config.rateLimitProbe;
    if (!probe) {
      ctx.skip('LIVE-003', 'no live.rateLimitProbe configured');
      return [];
    }
    const wanted = Math.min(probe.maxRequests, MAX_PROBE_REQUESTS);
    if (ctx.client.remaining < wanted) {
      ctx.skip('LIVE-003', `needs ${wanted} requests but only ${ctx.client.remaining} remain in the budget`);
      return [];
    }
    let last = 0;
    for (let i = 0; i < wanted; i++) {
      const response = await ctx.client.request(probe.method, probe.path, { spacingMs: PROBE_SPACING_MS });
      last = response.status;
      if (response.status === 429 || (response.status === 403 && response.headers['retry-after'])) return [];
    }
    const url = absolute(ctx, probe.path);
    return [{ url, evidence: `${wanted} × ${probe.method} ${probe.path} in about ${(wanted * PROBE_SPACING_MS) / 1000} s: no 429 (last status ${last})` }];
  },
};
