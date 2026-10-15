import type { RawFinding, Rule } from '../../../types.js';
import { calleeNameNode, calls, findingAt, objectProperty, sourceFiles, type FunctionNode } from '../analysis/ast-utils.js';
import { isHttpCall } from '../analysis/db-write.js';
import { entryFunctionOf, isUserInput } from '../analysis/taint.js';

/** A comparison of a parsed URL's host against something: includes/has/===/startsWith/endsWith on .hostname/.host/.origin. */
function hasHostAllowlist(fn: FunctionNode | undefined): boolean {
  if (!fn) return false;
  const text = fn.getText();
  return /\.(?:hostname|host|origin)\b/.test(text) && /(?:\.includes\(|\.has\(|[!=]==|\.startsWith\(|\.endsWith\(|\.test\()/.test(text);
}

export const input007: Rule = {
  id: 'INPUT-007',
  title: 'Server-side request forgery (SSRF)',
  category: 'input-validation',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports fetch, axios, got, ky and undici requests whose URL (or host part of it) comes from the request, in functions ' +
    'that never compare the parsed hostname, host or origin against an allowlist. Limitations: allowlists checked in other ' +
    'modules are not recognised, and private-IP blocking is not verified.',
  explanation:
    'Your server fetches a URL chosen by the caller, so it can be pointed at internal services, cloud metadata endpoints ' +
    '(169.254.169.254) or other hosts only your server can reach.',
  fix:
    "Parse the URL with new URL(), require https, compare url.hostname with an allowlist (`ALLOWED.has(url.hostname)`), and " +
    'reject private and link-local addresses.',
  falsePositiveNote: 'A URL validated by a helper in another file is still reported.',
  cwe: 'CWE-918',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => /fetch\(|axios|got\(|\bky\b|undici/.test(text))) {
      for (const call of calls(ctx.getSourceFile(file))) {
        if (!isHttpCall(call)) continue;
        const [first] = call.getArguments();
        const target = objectProperty(first, 'url') ?? first;
        const fn = entryFunctionOf(call);
        if (!target || !isUserInput(target, fn) || hasHostAllowlist(fn)) continue;
        findings.push(findingAt(calleeNameNode(call)));
      }
    }
    return findings;
  },
};
