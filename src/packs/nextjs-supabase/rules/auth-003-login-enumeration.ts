import { Node, SyntaxKind } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { findingAt, resolveExpression, stringLiteral } from '../analysis/ast-utils.js';
import { entries } from '../analysis/entries.js';
import { loginSignals } from '../analysis/flows.js';

const MESSAGE_KEYS = new Set(['error', 'message', 'msg', 'detail', 'reason']);
const UNKNOWN_ACCOUNT = /no (?:such )?user|not found|unknown (?:user|email|account)|user does not exist|no account/i;

/** Error/message literals a handler can send back, each with the node that holds it. */
function messages(fn: Node): { text: string; node: Node }[] {
  const found: { text: string; node: Node }[] = [];
  const add = (value: Node | undefined) => {
    if (!value) return;
    const resolved = resolveExpression(value);
    const text = stringLiteral(resolved);
    if (text !== undefined) found.push({ text, node: value });
  };
  for (const property of fn.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
    if (MESSAGE_KEYS.has(property.getName())) add(property.getInitializer());
  }
  for (const expression of fn.getDescendantsOfKind(SyntaxKind.NewExpression)) {
    if (/^(?:Error|Response)$/.test(expression.getExpression().getText())) add(expression.getArguments()[0]);
  }
  return found;
}

export const auth003: Rule = {
  id: 'AUTH-003',
  title: 'Account enumeration on login',
  category: 'authentication',
  severity: 'medium',
  confidence: 'low',
  stacks: ['nextjs-app-router'],
  description:
    'In login handlers, collects the error and message strings the handler can return or throw. When there are at least ' +
    'two distinct messages and one says the user or email does not exist, it reports that message. Messages held in local ' +
    'constants are resolved. Limitations: different status codes or timing with identical messages are not detected.',
  explanation:
    'The login form answers differently for unknown accounts, so anyone can check which email addresses have an account ' +
    'and then target them with password guessing or phishing.',
  fix: "Return the same generic message for every failure, for example 'Invalid email or password', with the same status code.",
  falsePositiveNote: 'Distinct messages for unrelated failures (rate limiting, server errors) are fine and are not reported on their own.',
  cwe: 'CWE-204',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-and-error-messages'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      if (!loginSignals(entry).login) continue;
      const found = messages(entry.node);
      if (new Set(found.map((m) => m.text)).size < 2) continue;
      const leak = found.find((m) => UNKNOWN_ACCOUNT.test(m.text));
      if (leak) findings.push(findingAt(leak.node));
    }
    return findings;
  },
};
