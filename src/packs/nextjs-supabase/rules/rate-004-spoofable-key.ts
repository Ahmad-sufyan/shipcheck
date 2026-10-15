import { Node } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calls, findingAt, outermostFunction, sourceFiles, stringLiteral } from '../analysis/ast-utils.js';

const SPOOFABLE = /^(?:x-forwarded-for|x-real-ip|true-client-ip|forwarded)$/i;
const LIMITER_NAME = /rate[-_]?limit|limiter|throttl/i;
const LIMITER_METHODS = new Set(['limit', 'consume', 'check', 'hit', 'take']);

function functionName(fn: Node): string {
  if (Node.isFunctionDeclaration(fn) || Node.isFunctionExpression(fn) || Node.isMethodDeclaration(fn)) return fn.getName() ?? '';
  const parent = fn.getParent();
  return parent && Node.isVariableDeclaration(parent) ? parent.getName() : '';
}

/** The function is a limiter itself, or calls one. */
function rateLimits(fn: Node): boolean {
  if (LIMITER_NAME.test(functionName(fn))) return true;
  return calls(fn).some((call) => {
    const name = calleeName(call);
    if (LIMITER_NAME.test(name)) return true;
    const receiver = call.getExpression();
    return LIMITER_METHODS.has(name) && Node.isPropertyAccessExpression(receiver) && LIMITER_NAME.test(receiver.getExpression().getText());
  });
}

export const rate004: Rule = {
  id: 'RATE-004',
  title: 'Rate limiter keyed on a spoofable header',
  category: 'rate-limiting',
  severity: 'medium',
  confidence: 'medium',
  stacks: ['nextjs-app-router'],
  description:
    'Reports raw reads of x-forwarded-for, x-real-ip, true-client-ip or forwarded inside a function that rate limits (or ' +
    'is a limiter). Clients can set these headers themselves unless the platform overwrites them, so each request can ' +
    'claim a new IP and dodge the limit. Limitations: limiters keyed on IP only for signed-in users are not reported.',
  explanation:
    'The limiter trusts an IP address the client can make up, so an attacker can send a different fake address with ' +
    'every request and never hit the limit.',
  fix: 'Use the platform’s client IP helper (`ipAddress(request)` from @vercel/functions, or the CF-Connecting-IP header on Cloudflare) and key limits for signed-in users on their user id.',
  falsePositiveNote: 'Some platforms overwrite these headers at the edge; if yours guarantees the value, the risk is lower.',
  cwe: 'CWE-290',
  references: ['https://vercel.com/docs/functions/functions-api-reference/vercel-functions-package#ipaddress', 'https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-connecting-ip'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => /x-forwarded-for|x-real-ip|true-client-ip|['"]forwarded['"]/i.test(text))) {
      for (const call of calls(ctx.getSourceFile(file))) {
        if (calleeName(call) !== 'get' || !SPOOFABLE.test(stringLiteral(call.getArguments()[0]) ?? '')) continue;
        const fn = outermostFunction(call);
        if (fn && rateLimits(fn)) findings.push(findingAt(call));
      }
    }
    return findings;
  },
};
