import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeText, calls, findingAt } from '../analysis/ast-utils.js';
import { isDbWrite } from '../analysis/db-write.js';
import { entries, type Entry } from '../analysis/entries.js';
import { isResetEntry, loginSignals } from '../analysis/flows.js';
import { hasRateLimit } from '../analysis/rate-limit.js';

const SIGNUP_PATH = /(?:^|\/)(?:signup|sign-up|register)(?:\/|$)/i;
const OTP_PATH = /(?:^|\/)(?:otp|magic-link|magiclink|passwordless)(?:\/|$)/i;
const CONTACT_PATH = /(?:^|\/)(?:contact|feedback|support)(?:\/|$)/i;
const SUPABASE_AUTH_FLOWS = new Set(['signUp', 'signInWithOtp', 'verifyOtp', 'resetPasswordForEmail', 'resend']);
/** Resend, Nodemailer, SendGrid, Postmark, AWS SES. */
const SENDS_EMAIL = /(?:^|\.)(?:emails\.send|sendMail|sendEmail|sendEmailWithTemplate)$|^sgMail\.send$|(?:^|\.)SendEmailCommand$/;

type Kind = 'signup' | 'otp' | 'reset' | 'contact';

function classify(entry: Entry): { kinds: Set<Kind>; supabaseOnly: boolean } {
  const found = calls(entry.node);
  const names = new Set(found.map(calleeName));
  const path = entry.routePath ?? '';
  const kinds = new Set<Kind>();
  if (names.has('signUp') || SIGNUP_PATH.test(path)) kinds.add('signup');
  if (names.has('signInWithOtp') || names.has('verifyOtp') || OTP_PATH.test(path)) kinds.add('otp');
  if (isResetEntry(entry) || names.has('resetPasswordForEmail')) kinds.add('reset');
  const sendsEmail = found.some((call) => SENDS_EMAIL.test(calleeText(call)));
  if (sendsEmail || CONTACT_PATH.test(path)) kinds.add('contact');
  const usesSupabaseAuth = [...names].some((name) => SUPABASE_AUTH_FLOWS.has(name));
  const ownWork = sendsEmail || found.some((call) => isDbWrite(call));
  return { kinds, supabaseOnly: usesSupabaseAuth && !ownWork };
}

export const rate001: Rule = {
  id: 'RATE-001',
  title: 'Sensitive endpoint without rate limit',
  category: 'rate-limiting',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports sign-up (supabase.auth.signUp, /signup or /register), OTP and magic-link (signInWithOtp, verifyOtp), password ' +
    'reset, and contact/feedback handlers (or any handler that sends email through Resend, Nodemailer, SendGrid, Postmark ' +
    'or SES) that have no rate limiter. Contact-only endpoints are medium. Handlers that only forward to Supabase Auth get ' +
    'low confidence because Supabase applies its own auth rate limits. Logins are AUTH-002.',
  explanation:
    'Nothing limits how often this endpoint can be called, so bots can create fake accounts, brute-force one-time codes, ' +
    'flood inboxes with reset or contact emails, and burn through your email quota and sender reputation.',
  fix: 'Add a limiter keyed by IP plus the target identifier (email, phone), for example @upstash/ratelimit, and return 429 when it trips.',
  falsePositiveNote: 'Supabase Auth applies built-in rate limits to its own sign-up, OTP and reset emails; those findings are low confidence.',
  cwe: 'CWE-770',
  references: ['https://supabase.com/docs/guides/auth/rate-limits', 'https://upstash.com/docs/redis/sdks/ratelimit-ts/overview'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      const { kinds, supabaseOnly } = classify(entry);
      if (!kinds.size || hasRateLimit(entry.node, ctx, entry.routePath)) continue;
      if (loginSignals(entry).login && !kinds.has('signup') && !kinds.has('otp')) continue;
      const contactOnly = kinds.size === 1 && kinds.has('contact');
      findings.push(findingAt(entry.node, { ...(contactOnly ? { severity: 'medium' as const } : {}), ...(supabaseOnly ? { confidence: 'low' as const } : {}) }));
    }
    return findings;
  },
};
