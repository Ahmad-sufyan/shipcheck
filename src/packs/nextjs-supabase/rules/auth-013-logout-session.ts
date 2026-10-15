import { Node, type CallExpression } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calls, findingAt, numericValue, objectProperty, receiverOf, resolveExpression, stringLiteral } from '../analysis/ast-utils.js';
import { isDbWrite } from '../analysis/db-write.js';
import { entries } from '../analysis/entries.js';
import { isLogoutEntry } from '../analysis/flows.js';

/** cookies() store, request/response .cookies, or a variable holding one. */
function isCookieStore(receiver: Node | undefined): boolean {
  if (!receiver) return false;
  let target = unwrapExpression(receiver);
  if (Node.isAwaitExpression(target)) target = unwrapExpression(target.getExpression());
  if (Node.isPropertyAccessExpression(target) && target.getName() === 'cookies') return true;
  if (Node.isIdentifier(target)) {
    target = resolveExpression(target);
    if (Node.isAwaitExpression(target)) target = unwrapExpression(target.getExpression());
  }
  return Node.isCallExpression(target) && calleeName(target) === 'cookies';
}

/** cookies().delete(name), or cookies().set(name, '') / set(..., { maxAge: 0 }). */
function clearsCookie(call: CallExpression): boolean {
  const name = calleeName(call);
  if (!isCookieStore(receiverOf(call))) return false;
  if (name === 'delete') return true;
  if (name !== 'set') return false;
  const [, value, options] = call.getArguments();
  return stringLiteral(value) === '' || numericValue(objectProperty(options, 'maxAge')) === 0;
}

/** Server-side invalidation: auth.signOut(), a session delete/revoke/destroy, or a DB delete. */
function invalidatesSession(fn: Node): boolean {
  return calls(fn).some((call) => {
    const name = calleeName(call);
    if (name === 'signOut' || /^(?:destroy|revoke|invalidate)/i.test(name)) return true;
    return isDbWrite(call) && /delete/i.test(call.getText());
  });
}

export const auth013: Rule = {
  id: 'AUTH-013',
  title: 'Logout leaves the session valid',
  category: 'authentication',
  severity: 'medium',
  confidence: 'medium',
  advisory: true,
  stacks: ['nextjs-app-router'],
  description:
    'Reports logout route handlers and server actions that clear a cookie (delete, empty value or maxAge 0) but never call ' +
    'auth.signOut() or delete/revoke the server-side session. Advisory: short-lived stateless tokens may make this acceptable.',
  explanation:
    'Logging out only removes the cookie from this browser. A copy of the session token that was stolen earlier keeps ' +
    'working until it expires.',
  fix: 'Call `supabase.auth.signOut()` (or delete the session row) on the server before clearing the cookie.',
  falsePositiveNote: 'Stateless JWTs with a very short lifetime and no refresh token cannot be revoked and are reported anyway.',
  cwe: 'CWE-613',
  references: ['https://supabase.com/docs/reference/javascript/auth-signout', 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#manual-session-expiration'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      if (!isLogoutEntry(entry) || invalidatesSession(entry.node)) continue;
      const clear = calls(entry.node).find(clearsCookie);
      if (clear) findings.push(findingAt(clear));
    }
    return findings;
  },
};
