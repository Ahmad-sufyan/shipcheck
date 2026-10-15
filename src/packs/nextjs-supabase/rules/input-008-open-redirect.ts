import { Node } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeNameNode, calleeText, calls, findingAt, relativeFile, sourceFiles, type FunctionNode } from '../analysis/ast-utils.js';
import { entryFunctionOf, isUserInput } from '../analysis/taint.js';
import { routePathFromFile } from '../../../stacks/nextjs/routes.js';

const REDIRECT_FUNCTIONS = new Set(['redirect', 'permanentRedirect']);
const REDIRECT_METHODS = new Set(['NextResponse.redirect', 'Response.redirect']);

export function isRedirectCall(call: Node): boolean {
  if (!Node.isCallExpression(call)) return false;
  return (Node.isIdentifier(unwrapExpression(call.getExpression())) && REDIRECT_FUNCTIONS.has(calleeName(call))) || REDIRECT_METHODS.has(calleeText(call));
}

/** Same-origin checks: comparing .origin, or rejecting protocol-relative `//` paths. */
export function hasSameOriginCheck(fn: FunctionNode | undefined): boolean {
  if (!fn) return false;
  const text = fn.getText();
  return /\.origin\s*[!=]==|[!=]==\s*[\w.]+\.origin\b/.test(text) || /startsWith\(\s*['"`]\/\/['"`]\s*\)/.test(text);
}

/** Auth callback routes are AUTH-009's territory. */
export function isAuthCallback(file: string, fn: FunctionNode | undefined): boolean {
  const routePath = routePathFromFile(file) ?? '';
  return /\/callback(?:\/|$)|\/auth\/confirm(?:\/|$)/.test(routePath) || /exchangeCodeForSession|verifyOtp/.test(fn?.getText() ?? '');
}

export const input008: Rule = {
  id: 'INPUT-008',
  title: 'Open redirect',
  category: 'input-validation',
  severity: 'medium',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports redirect(), permanentRedirect(), NextResponse.redirect() and Response.redirect() whose target comes from the ' +
    'request, in functions without a same-origin check (comparing URL origins or rejecting `//`). Allowlist lookups such as ' +
    'DESTINATIONS[key] are not request data. Auth callback routes are left to AUTH-009.',
  explanation:
    'The app redirects to an address supplied in the request, so attackers can craft links on your domain that bounce ' +
    'visitors to a phishing site.',
  fix: "Redirect only to relative paths (`next.startsWith('/') && !next.startsWith('//')`), compare origins, or map keys to an allowlist of destinations.",
  falsePositiveNote: 'Targets validated by a helper in another file are still reported.',
  cwe: 'CWE-601',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html', 'https://nextjs.org/docs/app/api-reference/functions/redirect'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => /redirect/i.test(text))) {
      for (const call of calls(ctx.getSourceFile(file))) {
        if (!isRedirectCall(call)) continue;
        const fn = entryFunctionOf(call);
        const [target] = call.getArguments();
        if (!target || !isUserInput(target, fn) || hasSameOriginCheck(fn) || isAuthCallback(relativeFile(call), fn)) continue;
        findings.push(findingAt(calleeNameNode(call)));
      }
    }
    return findings;
  },
};
