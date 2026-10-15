import { Node, type CallExpression } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calls, findingAt, importBindings, importedCallName, numericValue, objectHasSpread, objectProperty, receiverOf, resolveExpression, sourceFiles, stringLiteral } from '../analysis/ast-utils.js';

const SENSITIVE_NAME = /session|token|auth|sid|jwt/i;
const MAX_AGE_SECONDS = 30 * 24 * 60 * 60;
const SUPABASE_CLIENT_FACTORY = /^create(?:Server|Browser|Middleware|RouteHandler|ServerComponent|ServerAction)Client$/;

/** cookies().set(), (await cookies()).set(), cookieStore.set(), res.cookies.set(), request.cookies.set(). */
function isCookieSetCall(call: CallExpression): boolean {
  if (calleeName(call) !== 'set') return false;
  const receiver = receiverOf(call);
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

function insideSupabaseAdapter(call: CallExpression): boolean {
  return call.getAncestors().some((a) => Node.isCallExpression(a) && SUPABASE_CLIENT_FACTORY.test(calleeName(a)));
}

/** Problems with a cookie's options, or undefined when they cannot be read statically. */
function cookieProblems(options: Node | undefined): string[] | undefined {
  if (!options) return ['httpOnly', 'secure', 'sameSite'];
  const object = resolveExpression(options);
  if (!Node.isObjectLiteralExpression(object) || objectHasSpread(object)) return undefined;
  const problems: string[] = [];
  const flag = (name: string) => objectProperty(object, name);
  if (flag('httpOnly')?.getText() !== 'true') problems.push('httpOnly');
  const secure = flag('secure');
  if (!secure || secure.getText() === 'false') problems.push('secure');
  if (!flag('sameSite') || flag('sameSite')?.getText() === 'false') problems.push('sameSite');
  const maxAge = numericValue(flag('maxAge'));
  if (maxAge !== undefined && maxAge > MAX_AGE_SECONDS) problems.push('maxAge over 30 days');
  return problems;
}

export const auth004: Rule = {
  id: 'AUTH-004',
  title: 'Insecure session cookie',
  category: 'authentication',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports cookies().set(), response.cookies.set() and cookie.serialize() calls for cookies named like session, token, ' +
    'auth, sid or jwt whose options are missing httpOnly, secure or sameSite, or set maxAge above 30 days. Options held in ' +
    'a local variable are followed; options built elsewhere or with spreads are skipped. Calls inside the @supabase/ssr ' +
    'cookie adapter are skipped because Supabase supplies those options.',
  explanation:
    'The session cookie is readable by page scripts, sent over plain HTTP, sent on cross-site requests, or kept for too ' +
    'long, which makes stealing or riding a session easier.',
  fix: "Set `{ httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 60 * 60 * 8 }` (or a similarly short lifetime) on session cookies.",
  falsePositiveNote: 'Cookies whose names contain token or auth but hold nothing secret (for example a CSRF double-submit token meant for scripts) may be reported.',
  cwe: 'CWE-1004',
  references: ['https://nextjs.org/docs/app/api-reference/functions/cookies', 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => text.includes('cookies') || text.includes('serialize'))) {
      const sourceFile = ctx.getSourceFile(file);
      const cookieModule = importBindings(sourceFile, ['cookie']);
      for (const call of calls(sourceFile)) {
        const serialize = importedCallName(call, cookieModule) === 'serialize';
        if ((!serialize && !isCookieSetCall(call)) || insideSupabaseAdapter(call)) continue;
        const [first, , third] = call.getArguments();
        const objectForm = !serialize && first !== undefined && Node.isObjectLiteralExpression(unwrapExpression(first));
        const name = objectForm ? stringLiteral(objectProperty(first, 'name')) : stringLiteral(first);
        if (!name || !SENSITIVE_NAME.test(name)) continue;
        // set(name, value, options) / serialize(name, value, options) / set({ name, value, ...options })
        const problems = cookieProblems(objectForm ? first : third);
        if (!problems?.length) continue;
        findings.push(findingAt(call, { explanation: `The "${name}" cookie is missing: ${problems.join(', ')}. ${auth004.explanation}` }));
      }
    }
    return findings;
  },
};
