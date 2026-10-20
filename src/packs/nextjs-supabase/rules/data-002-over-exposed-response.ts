import { Node, SyntaxKind } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeText, declarationOf, findingAt, objectProperty, stringLiteral } from '../analysis/ast-utils.js';
import { chainCalls } from '../analysis/db-write.js';
import { entries } from '../analysis/entries.js';

const RESPONSE_CALL = /^(?:NextResponse|Response)\.json$/;
const SECRET_KEY = /pass(?:word)?|hash|token|secret|salt/i;
const AUTH_USER = /\.auth\.(?:getUser|getSession|getClaims)\(|\bcurrentUser\(|\bauth\(\)/;

/** A Supabase query in this expression selects every column: select('*') without head: true. */
function selectsAll(expression: Node): boolean {
  const calls = Node.isCallExpression(expression) ? [expression, ...expression.getDescendantsOfKind(SyntaxKind.CallExpression)] : expression.getDescendantsOfKind(SyntaxKind.CallExpression);
  return calls.some((call) =>
    chainCalls(call).some((c) => calleeName(c) === 'select' && stringLiteral(c.getArguments()[0]) === '*' && objectProperty(c.getArguments()[1], 'head')?.getText() !== 'true'),
  );
}

/** Why a response payload over-exposes data, if it does. */
function overExposure(payload: Node): string | undefined {
  const node = unwrapExpression(payload);
  if (Node.isObjectLiteralExpression(node)) {
    const key = node.getProperties().find((p) => (Node.isPropertyAssignment(p) || Node.isShorthandPropertyAssignment(p)) && SECRET_KEY.test(p.getName()));
    return key && (Node.isPropertyAssignment(key) || Node.isShorthandPropertyAssignment(key)) ? `a field named ${key.getName()}` : undefined;
  }
  if (Node.isAwaitExpression(node) || Node.isCallExpression(node)) return selectsAll(node) ? "every column of a select('*') query" : undefined;
  if (!Node.isIdentifier(node)) return undefined;
  const declaration = declarationOf(node);
  const variable = declaration && (Node.isVariableDeclaration(declaration) ? declaration : declaration.getFirstAncestorByKind(SyntaxKind.VariableDeclaration));
  const initializer = variable?.getInitializer();
  if (!initializer) return undefined;
  if (selectsAll(initializer)) return "every column of a select('*') query";
  if (AUTH_USER.test(initializer.getText()) && /user/i.test(node.getText())) return 'the full auth user object';
  return undefined;
}

export const data002: Rule = {
  id: 'DATA-002',
  title: 'Over-exposed API response',
  category: 'data-protection',
  severity: 'medium',
  confidence: 'low',
  stacks: ['nextjs-app-router'],
  description:
    "Reports route handler responses (NextResponse.json / Response.json) that return the result of a Supabase select('*') " +
    'query, the full auth user object from getUser()/getSession(), or an object with a password, hash, token, secret or ' +
    'salt field. Head-only count queries are ignored. Low confidence: the client may genuinely need every column.',
  explanation:
    'The response sends every column of the row, including fields the page never shows, such as internal flags, emails ' +
    'or tokens. Anyone can read them in the browser’s network tab.',
  fix: "Select and return only the fields the client needs, for example `.select('id, display_name, avatar_url')`.",
  falsePositiveNote: 'If the UI really needs every column and the table holds nothing sensitive, this is fine.',
  cwe: 'CWE-213',
  references: ['https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      if (entry.kind !== 'route') continue;
      for (const call of entry.node.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        if (!RESPONSE_CALL.test(calleeText(call))) continue;
        const [payload] = call.getArguments();
        const reason = payload ? overExposure(payload) : undefined;
        if (reason) findings.push(findingAt(call, { explanation: `This response returns ${reason}. ${data002.explanation}` }));
      }
    }
    return findings;
  },
};
