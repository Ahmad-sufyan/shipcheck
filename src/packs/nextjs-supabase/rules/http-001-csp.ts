import type { RawFinding, Rule } from '../../../types.js';
import { collectHeaders, headersAnchor } from '../analysis/headers-config.js';

/** `script-src 'self' x; default-src y` -> { 'script-src': ["'self'", 'x'], 'default-src': ['y'] } */
function directives(policy: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const part of policy.split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name) map.set(name.toLowerCase(), sources);
  }
  return map;
}

function weaknesses(policy: string): string[] {
  const parsed = directives(policy);
  const found: string[] = [];
  if ([...parsed.values()].some((sources) => sources.includes("'unsafe-eval'"))) found.push("'unsafe-eval'");
  const scripts = parsed.get('script-src') ?? parsed.get('default-src') ?? [];
  const pinned = scripts.some((s) => /^'(?:nonce-|sha256-|sha384-|sha512-)/.test(s));
  if (scripts.includes("'unsafe-inline'") && !pinned) found.push("script 'unsafe-inline' without a nonce or hash");
  return found;
}

export const http001: Rule = {
  id: 'HTTP-001',
  title: 'Content-Security-Policy missing or unsafe',
  category: 'http-config',
  severity: 'medium',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Collects response headers from next.config headers(), proxy/middleware, vercel.json and public/_headers. Reports a ' +
    "missing Content-Security-Policy (medium, at the next.config object), and CSPs that allow 'unsafe-eval' or script " +
    "'unsafe-inline' without a nonce or hash (low). Limitations: CSPs set by a CDN or by <meta> tags are not seen; values " +
    'built at runtime are not inspected.',
  explanation:
    'Without a strict Content-Security-Policy, any XSS bug lets injected script run with full access to the page and the ' +
    'user’s session.',
  fix: "Set a CSP, ideally nonce-based from proxy/middleware as the Next.js docs show (`script-src 'self' 'nonce-…' 'strict-dynamic'`), and avoid 'unsafe-eval'.",
  falsePositiveNote: 'A CSP added by a CDN or reverse proxy in front of the app is invisible here; LIVE checks confirm production headers.',
  cwe: 'CWE-1021',
  references: ['https://nextjs.org/docs/app/guides/content-security-policy', 'https://developer.mozilla.org/docs/Web/HTTP/Guides/CSP'],
  run(ctx) {
    const policies = collectHeaders(ctx).filter((h) => h.key === 'content-security-policy');
    if (!policies.length) return [headersAnchor(ctx)];
    const findings: RawFinding[] = [];
    for (const policy of policies) {
      const found = policy.value ? weaknesses(policy.value) : [];
      if (!found.length) continue;
      findings.push({
        file: policy.file,
        line: policy.line,
        evidence: `Content-Security-Policy: ${policy.value}`,
        severity: 'low',
        explanation: `The Content-Security-Policy allows ${found.join(' and ')}, which lets injected script run and defeats most of its protection.`,
      });
    }
    return findings;
  },
};
