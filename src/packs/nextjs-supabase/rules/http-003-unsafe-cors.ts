import { Node, SyntaxKind } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, findingAt, outermostFunction, sourceFiles, staticText, stringLiteral } from '../analysis/ast-utils.js';
import { collectHeaders } from '../analysis/headers-config.js';
import { entryFunctionOf, isUserInput } from '../analysis/taint.js';

const ALLOW_ORIGIN = /^access-control-allow-origin$/i;
const CREDENTIALS_TRUE = /access-control-allow-credentials['"`]?\s*\]?\s*[:,=]\s*['"`]?true/i;
const ALLOWLIST = /\.(?:has|includes)\(\s*origin\b|\borigin\s*[!=]==|[!=]==\s*origin\b|allow(?:ed)?_?origins|allowlist|whitelist/i;

/** Every place code sets Access-Control-Allow-Origin, with the value expression. */
function allowOriginSites(node: Node): { site: Node; value: Node }[] {
  const sites: { site: Node; value: Node }[] = [];
  for (const property of node.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
    const name = property.getNameNode();
    const key = Node.isStringLiteral(name) || Node.isIdentifier(name) ? name.getText().replace(/^['"]|['"]$/g, '') : '';
    const value = property.getInitializer();
    if (ALLOW_ORIGIN.test(key) && value) sites.push({ site: property, value });
  }
  for (const call of node.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const [key, value] = call.getArguments();
    if (['set', 'append'].includes(calleeName(call)) && ALLOW_ORIGIN.test(stringLiteral(key) ?? '') && value) sites.push({ site: call, value });
  }
  for (const assignment of node.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
    const left = assignment.getLeft();
    if (assignment.getOperatorToken().getKind() === SyntaxKind.EqualsToken && Node.isElementAccessExpression(left) && ALLOW_ORIGIN.test(stringLiteral(left.getArgumentExpression()) ?? '')) {
      sites.push({ site: assignment, value: assignment.getRight() });
    }
  }
  return sites;
}

export const http003: Rule = {
  id: 'HTTP-003',
  title: 'Unsafe CORS configuration',
  category: 'http-config',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports Access-Control-Allow-Origin set to * or to the request’s own Origin (without an allowlist check in the same ' +
    'function) when Access-Control-Allow-Credentials: true is also sent, in route handlers, proxy/middleware, next.config, ' +
    'vercel.json and public/_headers. Credential-less public APIs are not reported.',
  explanation:
    'Any website can make logged-in requests to this API from a visitor’s browser and read the responses, so a malicious ' +
    'page can pull your users’ data while they browse it.',
  fix: 'Compare the Origin header against an explicit allowlist and only then echo it back (with Vary: Origin); never combine * or a reflected origin with Allow-Credentials: true.',
  falsePositiveNote: 'An allowlist enforced by a helper in another module is not recognised.',
  cwe: 'CWE-942',
  references: ['https://developer.mozilla.org/docs/Web/HTTP/Guides/CORS', 'https://portswigger.net/web-security/cors'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => /access-control-allow-origin/i.test(text))) {
      for (const { site, value } of allowOriginSites(ctx.getSourceFile(file))) {
        const fn = outermostFunction(site);
        const scopeText = (fn ?? site.getSourceFile()).getText();
        if (!CREDENTIALS_TRUE.test(scopeText)) continue;
        const wildcard = staticText(value) === '*';
        const reflected = !wildcard && isUserInput(value, entryFunctionOf(site)) && !ALLOWLIST.test(scopeText);
        if (wildcard || reflected) findings.push(findingAt(site));
      }
    }
    const configured = collectHeaders(ctx).filter((h) => h.source !== 'middleware');
    for (const header of configured) {
      if (header.key !== 'access-control-allow-origin' || header.value !== '*') continue;
      const credentials = configured.some((h) => h.file === header.file && h.key === 'access-control-allow-credentials' && h.value === 'true');
      if (credentials) findings.push({ file: header.file, line: header.line, evidence: `Access-Control-Allow-Origin: ${header.value}` });
    }
    return findings;
  },
};
