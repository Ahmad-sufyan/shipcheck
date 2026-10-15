import { Node, SyntaxKind, type CallExpression } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeNameNode, calls, findingAt, importBindings, importedCallName, objectProperty, sourceFiles } from '../analysis/ast-utils.js';

/** Whether the value of `call` decides a branch: used directly in a condition, or stored and later tested. */
function usedInCondition(call: CallExpression): boolean {
  for (let current: Node | undefined = call.getParent(); current && !Node.isStatement(current); current = current.getParent()) {
    if (Node.isConditionalExpression(current) || (Node.isBinaryExpression(current) && /&&|\|\||[!=]==?/.test(current.getOperatorToken().getText()))) return true;
  }
  const statement = call.getFirstAncestor((a) => Node.isStatement(a));
  if (statement && Node.isIfStatement(statement) && statement.getExpression().getText().includes(call.getText())) return true;
  const variable = call.getFirstAncestorByKind(SyntaxKind.VariableDeclaration);
  const name = variable?.getName();
  const scope = variable?.getFirstAncestor((a) => Node.isBlock(a) || Node.isSourceFile(a));
  if (!name || !scope) return false;
  const pattern = new RegExp(`\\b${name}\\b`);
  return scope.getDescendantsOfKind(SyntaxKind.IfStatement).some((s) => pattern.test(s.getExpression().getText())) ||
    scope.getDescendantsOfKind(SyntaxKind.ConditionalExpression).some((c) => pattern.test(c.getCondition().getText()));
}

/** Methods chained onto a `new SignJWT(...)` expression. */
function signJwtChain(expression: Node): string[] {
  const methods: string[] = [];
  let current: Node | undefined = expression.getParent();
  while (current && Node.isPropertyAccessExpression(current)) {
    methods.push(current.getName());
    const call = current.getParent();
    current = call && Node.isCallExpression(call) ? call.getParent() : undefined;
  }
  return methods;
}

export const auth005: Rule = {
  id: 'AUTH-005',
  title: 'JWT verification not pinned',
  category: 'authentication',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    "Reports jsonwebtoken verify() without an algorithms option (medium confidence: jsonwebtoken 9 already limits the " +
    "default to the key's type) or with 'none' in algorithms; sign() without expiresIn and without an exp claim; decode() " +
    '(or jose decodeJwt) results used in a condition; and jose SignJWT chains without setExpirationTime. Limitations: calls ' +
    'through wrapper libraries are not recognised.',
  explanation:
    'Tokens are not verified with a fixed algorithm, never expire, or are trusted without checking their signature, so a ' +
    'forged, downgraded or stolen token keeps working.',
  fix: "Pin algorithms on verify (`{ algorithms: ['HS256'] }`), always set expiresIn when signing, and never base decisions on jwt.decode().",
  falsePositiveNote: 'A shared wrapper that pins algorithms elsewhere is not recognised.',
  cwe: 'CWE-347',
  references: ['https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback', 'https://github.com/panva/jose/blob/main/docs/jwt/verify/functions/jwtVerify.md'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => text.includes('jsonwebtoken') || text.includes('jose'))) {
      const sourceFile = ctx.getSourceFile(file);
      const jwt = importBindings(sourceFile, ['jsonwebtoken']);
      const jose = importBindings(sourceFile, ['jose']);
      for (const call of calls(sourceFile)) {
        const fn = importedCallName(call, jwt);
        const [payload, , options] = call.getArguments();
        if (fn === 'verify') {
          const algorithms = objectProperty(options, 'algorithms');
          if (!algorithms) findings.push(findingAt(calleeNameNode(call), { confidence: 'medium' }));
          else if (/['"`]none['"`]/i.test(algorithms.getText())) findings.push(findingAt(calleeNameNode(call)));
        } else if (fn === 'sign') {
          if (!objectProperty(options, 'expiresIn') && !objectProperty(payload, 'exp')) findings.push(findingAt(calleeNameNode(call)));
        } else if ((fn === 'decode' || importedCallName(call, jose) === 'decodeJwt') && usedInCondition(call)) {
          findings.push(findingAt(calleeNameNode(call)));
        }
      }
      for (const expression of sourceFile.getDescendantsOfKind(SyntaxKind.NewExpression)) {
        const callee = expression.getExpression();
        if (!Node.isIdentifier(callee) || jose.named.get(callee.getText()) !== 'SignJWT') continue;
        const methods = signJwtChain(expression);
        if (methods.includes('sign') && !methods.includes('setExpirationTime')) findings.push(findingAt(expression));
      }
    }
    return findings;
  },
};
