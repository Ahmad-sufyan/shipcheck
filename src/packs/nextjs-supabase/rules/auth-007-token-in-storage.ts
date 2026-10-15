import { Node, SyntaxKind } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, findingAt, receiverOf, resolveExpression, sourceFiles, stringLiteral } from '../analysis/ast-utils.js';

const STORAGE = /(?:^|\.)(?:localStorage|sessionStorage)$/;
const SENSITIVE_KEY = /token|jwt|session|auth/i;

export const auth007: Rule = {
  id: 'AUTH-007',
  title: 'Token stored in Web Storage',
  category: 'authentication',
  severity: 'medium',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports localStorage/sessionStorage.setItem() and direct property writes whose key (literal or local constant) ' +
    'contains token, jwt, session or auth. Limitations: keys computed at runtime are skipped.',
  explanation:
    'Anything in localStorage or sessionStorage can be read by any script on the page, so a single XSS bug or compromised ' +
    'third-party script can steal the token and impersonate the user.',
  fix: 'Keep session tokens in httpOnly, secure cookies (Supabase SSR does this for you) and avoid copying them into Web Storage.',
  falsePositiveNote: 'Keys that merely contain these words but hold nothing secret (for example "authProvider") may be reported.',
  cwe: 'CWE-922',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => /localStorage|sessionStorage/.test(text))) {
      const sourceFile = ctx.getSourceFile(file);
      for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        const receiver = receiverOf(call);
        if (calleeName(call) !== 'setItem' || !receiver || !STORAGE.test(receiver.getText())) continue;
        const [key] = call.getArguments();
        const name = key ? stringLiteral(resolveExpression(key)) : undefined;
        if (name && SENSITIVE_KEY.test(name)) findings.push(findingAt(call));
      }
      for (const assignment of sourceFile.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
        if (assignment.getOperatorToken().getKind() !== SyntaxKind.EqualsToken) continue;
        const left = assignment.getLeft();
        const target = Node.isPropertyAccessExpression(left) ? left.getName() : Node.isElementAccessExpression(left) ? stringLiteral(left.getArgumentExpression()) : undefined;
        const storage = Node.isPropertyAccessExpression(left) || Node.isElementAccessExpression(left) ? left.getExpression().getText() : '';
        if (target && STORAGE.test(storage) && SENSITIVE_KEY.test(target)) findings.push(findingAt(assignment));
      }
    }
    return findings;
  },
};
