import { Node, SyntaxKind } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { findingAt, numericValue, resolveExpression, stringLiteral } from '../analysis/ast-utils.js';
import { entries } from '../analysis/entries.js';
import { isResetEntry } from '../analysis/flows.js';

const UNKNOWN_ACCOUNT = /no (?:such )?(?:account|user)|not registered|user not found|account not found|does not exist|doesn't exist/i;

export const auth011: Rule = {
  id: 'AUTH-011',
  title: 'Account enumeration on password reset',
  category: 'authentication',
  severity: 'medium',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'In password reset handlers, reports responses with status 404 and messages saying the account does not exist or is ' +
    'not registered (string literals, including local constants). One finding per line.',
  explanation:
    'The reset form tells callers whether an email address has an account, which lets anyone build a list of your users.',
  fix: "Always answer with the same message and status, for example 'If an account exists, a reset link is on its way.'",
  falsePositiveNote: 'Admin-only tools that are allowed to reveal account existence may be reported.',
  cwe: 'CWE-204',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      if (!isResetEntry(entry)) continue;
      const lines = new Set<number>();
      const report = (node: Node) => {
        const finding = findingAt(node.getFirstAncestor((a) => Node.isStatement(a)) ?? node);
        if (!lines.has(finding.line!)) findings.push(finding);
        lines.add(finding.line!);
      };
      for (const property of entry.node.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
        const initializer = property.getInitializer();
        if (!initializer) continue;
        if (property.getName() === 'status' && numericValue(initializer) === 404) report(property);
        const text = stringLiteral(resolveExpression(initializer));
        if (text !== undefined && UNKNOWN_ACCOUNT.test(text)) report(property);
      }
    }
    return findings;
  },
};
