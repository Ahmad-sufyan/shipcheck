import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeText, calls, findingAt } from '../analysis/ast-utils.js';
import { entries } from '../analysis/entries.js';
import { hasRateLimit } from '../analysis/rate-limit.js';

const LOGIN_PATH = /(?:^|\/)(?:login|log-in|signin|sign-in)(?:\/|$)/i;
const PASSWORD_CHECKS = /(?:^|\.)(?:compare|compareSync|verify)$/;

export const auth002: Rule = {
  id: 'AUTH-002',
  title: 'Login without brute-force protection',
  category: 'rate-limiting',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports login handlers (route handlers under a /login or /signin path that accept POST, or any handler or server action ' +
    'that calls signInWithPassword, bcrypt.compare or argon2.verify) with no rate limiting: no @upstash/ratelimit .limit(), ' +
    'no rateLimit-style helper or config.rateLimitHelpers entry, and no covering proxy that limits. Handlers that only ' +
    'forward to Supabase Auth get low confidence because Supabase applies its own auth rate limits.',
  explanation:
    'Nothing limits how many passwords a caller can try, so an attacker can guess passwords or replay leaked credentials ' +
    'from other sites at full speed.',
  fix:
    'Rate limit login attempts per IP and per email, for example with @upstash/ratelimit (`await ratelimit.limit(`login:${ip}:${email}`)`), ' +
    'and return 429 when the limit is hit.',
  falsePositiveNote: 'Limits enforced by a WAF or edge provider (Vercel Firewall, Cloudflare) are invisible to this rule.',
  cwe: 'CWE-307',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#protect-against-automated-attacks', 'https://supabase.com/docs/guides/auth/rate-limits'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      const callNames = calls(entry.node).map((call) => ({ name: calleeName(call), text: calleeText(call) }));
      const supabaseSignIn = callNames.some((c) => c.name === 'signInWithPassword');
      const verifiesPassword = callNames.some((c) => /bcrypt|argon|scrypt|verifyPassword|comparePassword/i.test(c.text) && (PASSWORD_CHECKS.test(c.text) || /verifyPassword|comparePassword/.test(c.name)));
      const loginPath = entry.kind === 'route' && entry.method !== 'GET' && LOGIN_PATH.test(entry.routePath ?? '');
      if (!loginPath && !supabaseSignIn && !verifiesPassword) continue;
      if (hasRateLimit(entry.node, ctx, entry.routePath)) continue;
      findings.push(findingAt(entry.node, supabaseSignIn && !verifiesPassword ? { confidence: 'low' } : {}));
    }
    return findings;
  },
};
