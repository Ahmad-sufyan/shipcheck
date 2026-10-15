import { Node, SyntaxKind } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calls, findingAt, outermostFunction, sourceFiles } from '../analysis/ast-utils.js';

/** Text of string-ish nodes: literals, template pieces and object keys. */
function textOf(node: Node): string | undefined {
  if (Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node)) return node.getLiteralValue();
  if (Node.isTemplateHead(node) || Node.isTemplateMiddle(node) || Node.isTemplateTail(node)) return node.getLiteralText();
  if (Node.isPropertyAssignment(node) || Node.isShorthandPropertyAssignment(node)) return node.getName();
  return undefined;
}

const STATE = /(?:^|[?&])state(?:=|$)|^state$/;
const PKCE = /code_challenge/;

export const auth008: Rule = {
  id: 'AUTH-008',
  title: 'Custom OAuth flow without state or PKCE',
  category: 'authentication',
  severity: 'medium',
  confidence: 'medium',
  advisory: true,
  stacks: ['nextjs-app-router'],
  description:
    'Reports functions that build an OAuth authorize request by hand (response_type=code, or client_id together with ' +
    'redirect_uri, in strings, templates or object keys) without any state parameter or PKCE code_challenge. Functions ' +
    'that use supabase.auth.signInWithOAuth are exempt because Supabase handles state and PKCE. Advisory: a library may ' +
    'add state outside the function.',
  explanation:
    'Without a state value or PKCE, an attacker can make a victim’s browser finish an OAuth login with the attacker’s ' +
    'authorization code (login CSRF) or reuse an intercepted code.',
  fix: 'Use the provider’s SDK or Supabase signInWithOAuth, or generate a random state and a PKCE code_verifier, store them in an httpOnly cookie and verify them in the callback.',
  falsePositiveNote: 'An SDK or helper that appends state and PKCE elsewhere is not visible to this rule.',
  cwe: 'CWE-352',
  references: ['https://datatracker.ietf.org/doc/html/rfc9700', 'https://supabase.com/docs/guides/auth/social-login'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => /client_id|response_type/.test(text))) {
      const checked = new Set<Node>();
      for (const node of ctx.getSourceFile(file).getDescendants()) {
        const text = textOf(node);
        if (text === undefined || !/client_id|response_type=code/.test(text)) continue;
        const fn = outermostFunction(node);
        if (!fn || checked.has(fn)) continue;
        checked.add(fn);
        if (calls(fn).some((call) => calleeName(call) === 'signInWithOAuth')) continue;
        const texts = fn.getDescendants().map(textOf).filter((t): t is string => t !== undefined);
        const joined = texts.join('\n');
        const codeFlow = /response_type=code/.test(joined) || (texts.some((t) => /response_type/.test(t)) && texts.includes('code')) || (/client_id/.test(joined) && /redirect_uri/.test(joined));
        if (!codeFlow || texts.some((t) => STATE.test(t)) || PKCE.test(joined)) continue;
        const anchor = node.getFirstAncestor((a) => Node.isStatement(a) || Node.isVariableDeclaration(a)) ?? node;
        findings.push(findingAt(anchor.getKind() === SyntaxKind.VariableDeclaration ? anchor : node));
      }
    }
    return findings;
  },
};
