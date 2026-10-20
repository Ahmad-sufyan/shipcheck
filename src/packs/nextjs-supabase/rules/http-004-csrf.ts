import { Node } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calls, findingAt, receiverOf } from '../analysis/ast-utils.js';
import { hasAuthCheck, localFunctionTarget } from '../analysis/auth-check.js';
import { entries, MUTATING_METHODS } from '../analysis/entries.js';

const ORIGIN_CHECK = /\.get\(\s*['"`](?:origin|referer)['"`]\s*\)|csrf|xsrf/i;
const BEARER = /\.get\(\s*['"`]authorization['"`]\s*\)/i;
const BODY_READERS = new Set(['json', 'formData', 'text', 'arrayBuffer', 'blob']);

/** Origin/Referer/CSRF-token checks in the handler or a same-file helper it calls. */
function checksOrigin(node: Node, depth = 0): boolean {
  if (ORIGIN_CHECK.test(node.getText())) return true;
  if (depth >= 2) return false;
  return calls(node).some((call) => {
    const target = localFunctionTarget(call);
    return target !== undefined && checksOrigin(target, depth + 1);
  });
}

export const http004: Rule = {
  id: 'HTTP-004',
  title: 'CSRF on a cookie-authenticated handler',
  category: 'http-config',
  severity: 'medium',
  confidence: 'low',
  stacks: ['nextjs-app-router'],
  description:
    'Reports mutating route handlers that authenticate with the session cookie (an auth check and no Authorization ' +
    'header), accept form-encoded, text or empty bodies, and never check Origin/Referer or a CSRF token. JSON-only ' +
    'handlers are skipped because cross-site forms cannot send JSON without a CORS preflight; Server Actions are skipped ' +
    'because Next.js compares their Origin with the Host. Low confidence: SameSite=Lax session cookies already block ' +
    'most cross-site POSTs.',
  explanation:
    'Another website can submit a form to this endpoint in the background while a user is signed in, and the browser ' +
    'attaches their session cookie, so the action runs as them.',
  fix: "Reject requests whose Origin header does not match your site (`request.headers.get('origin') === new URL(request.url).origin`), or use a CSRF token, and keep session cookies SameSite=Lax or Strict.",
  falsePositiveNote: 'Handlers whose session cookie is SameSite=Strict, or that are only called with JSON, are not exploitable this way.',
  cwe: 'CWE-352',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html', 'https://nextjs.org/docs/app/guides/data-security#built-in-server-actions-security-features'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      if (entry.kind !== 'route' || !MUTATING_METHODS.has(entry.method ?? '') || !hasAuthCheck(entry.node, ctx)) continue;
      const text = entry.node.getText();
      if (BEARER.test(text)) continue;
      const reads = calls(entry.node).filter((call) => {
        const receiver = receiverOf(call);
        return BODY_READERS.has(calleeName(call)) && receiver !== undefined && /^(?:req|request)$/i.test(receiver.getText());
      });
      if (reads.length && reads.every((call) => calleeName(call) === 'json')) continue;
      if (checksOrigin(entry.node)) continue;
      findings.push(findingAt(entry.node));
    }
    return findings;
  },
};
