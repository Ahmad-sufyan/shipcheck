import type { RawFinding } from '../../types.js';
import type { LiveCheck } from '../context.js';
import { absolute } from '../context.js';
import type { LiveResponse } from '../transport.js';

const SESSION_LIKE = /sess|sid|auth|token|jwt|login|remember|user|account|csrf|xsrf|^sb-|supabase|^__(?:secure|host)-/i;
const ANALYTICS = /^(?:_ga|_gid|_gat|_gcl|_fbp|_fbc|_hj|_clck|_clsk|ajs_|amplitude|mp_|_pk_|__cf_bm|_cfuvid|cf_clearance|__stripe_mid|__stripe_sid|_uetsid|_uetvid|ph_)/i;
/** @supabase/ssr auth cookies must be readable by the browser client, so they are set without HttpOnly by design. */
const SUPABASE_AUTH = /^sb-.+-auth-token(?:\.\d+)?$/;

export interface ParsedCookie {
  name: string;
  attributes: Set<string>;
}

export function parseSetCookie(header: string): ParsedCookie {
  const [pair = '', ...rest] = header.split(';');
  const name = pair.slice(0, pair.includes('=') ? pair.indexOf('=') : pair.length).trim();
  return { name, attributes: new Set(rest.map((part) => part.split('=')[0]!.trim().toLowerCase()).filter(Boolean)) };
}

function missingFlags(cookie: ParsedCookie): string[] {
  const missing: string[] = [];
  if (!cookie.attributes.has('httponly') && !SUPABASE_AUTH.test(cookie.name)) missing.push('HttpOnly');
  if (!cookie.attributes.has('secure')) missing.push('Secure');
  if (!cookie.attributes.has('samesite')) missing.push('SameSite');
  return missing;
}

export const live006: LiveCheck = {
  id: 'LIVE-006',
  title: 'Insecure cookies served',
  category: 'live',
  severity: 'medium',
  confidence: 'medium',
  stacks: [],
  source: 'live',
  description:
    'Reads Set-Cookie headers from / and each live.cookiePaths entry and reports session-like cookies (names containing ' +
    'session, sid, auth, token, jwt, csrf, sb-, ...) that lack HttpOnly, Secure or SameSite. Analytics cookies (_ga, _fbp, ' +
    '__cf_bm, ...) are ignored, and @supabase/ssr auth cookies are not required to be HttpOnly. Cookie values never appear ' +
    'in findings.',
  explanation: 'A session cookie without these flags can be stolen by injected scripts (HttpOnly), sent over plain HTTP (Secure) or attached to cross-site requests (SameSite).',
  fix: 'Set HttpOnly, Secure and SameSite=Lax (or Strict) when the server creates the cookie, e.g. cookies().set(name, value, { httpOnly: true, secure: true, sameSite: "lax" }).',
  falsePositiveNote: 'Cookies are judged by name; a session-like name that holds a harmless preference can be dismissed.',
  cwe: 'CWE-614',
  references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security', 'https://owasp.org/www-community/HttpOnly'],
  plan: (target) => target.config.cookiePaths.map((path) => ({ kind: 'http', method: 'GET', target: absolute(target, path), purpose: 'LIVE-006 cookie flags' })),
  async run(ctx) {
    const responses: LiveResponse[] = [await ctx.home()];
    for (const path of ctx.config.cookiePaths) {
      if (path !== '/') responses.push(await ctx.client.request('GET', path));
    }
    const findings: RawFinding[] = [];
    const seen = new Set<string>();
    for (const response of responses) {
      for (const header of response.setCookie) {
        const cookie = parseSetCookie(header);
        if (!cookie.name || seen.has(cookie.name) || ANALYTICS.test(cookie.name) || !SESSION_LIKE.test(cookie.name)) continue;
        seen.add(cookie.name);
        const missing = missingFlags(cookie);
        if (!missing.length) continue;
        const flags = [...cookie.attributes].join(', ') || 'no attributes';
        findings.push({ url: response.url, evidence: `Set-Cookie: ${cookie.name}=<redacted> (${flags}) is missing ${missing.join(', ')}` });
      }
    }
    return findings;
  },
};
