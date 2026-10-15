import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeNameNode, calls, findingAt, objectProperty, relativeFile, sourceFiles } from '../analysis/ast-utils.js';
import { entryFunctionOf, isUserInput } from '../analysis/taint.js';
import { hasSameOriginCheck, isAuthCallback, isRedirectCall } from './input-008-open-redirect.js';

export const auth009: Rule = {
  id: 'AUTH-009',
  title: 'OAuth redirect from user input',
  category: 'authentication',
  severity: 'medium',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports supabase.auth.signInWithOAuth calls whose options.redirectTo comes from the request, and auth callback routes ' +
    '(/callback paths, or code that calls exchangeCodeForSession/verifyOtp) that redirect to a request-controlled target ' +
    'without comparing origins or rejecting `//`. Generic open redirects elsewhere are INPUT-008.',
  explanation:
    'After signing in, the user is sent to an address taken from the link they clicked, so an attacker can send a real ' +
    'login link that lands the freshly signed-in user on a phishing page, or leaks tokens to another site.',
  fix: "Accept only relative paths (`next.startsWith('/') && !next.startsWith('//')`) or compare `new URL(next, origin).origin` with your origin before redirecting.",
  falsePositiveNote: 'Targets validated by a helper in another module are still reported.',
  cwe: 'CWE-601',
  references: ['https://supabase.com/docs/guides/auth/redirect-urls', 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => /signInWithOAuth|redirect/i.test(text))) {
      for (const call of calls(ctx.getSourceFile(file))) {
        const fn = entryFunctionOf(call);
        if (calleeName(call) === 'signInWithOAuth') {
          const redirectTo = objectProperty(objectProperty(call.getArguments()[0], 'options'), 'redirectTo');
          if (redirectTo && isUserInput(redirectTo, fn)) findings.push(findingAt(calleeNameNode(call)));
          continue;
        }
        if (!isRedirectCall(call) || !isAuthCallback(relativeFile(call), fn)) continue;
        const [target] = call.getArguments();
        if (target && isUserInput(target, fn) && !hasSameOriginCheck(fn)) findings.push(findingAt(calleeNameNode(call)));
      }
    }
    return findings;
  },
};
