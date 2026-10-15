import { Node, SyntaxKind } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeText, calls, findingAt, importBindings, importedCallName, numericValue } from '../analysis/ast-utils.js';
import { entries, type Entry } from '../analysis/entries.js';

const RESET_PATH = /reset|forgot|recover/i;
const RESET_TEXT = /password[_-]?resets?|reset[_-]?password|forgot[_-]?password/i;
const TOKEN_NAME = /token|code|otp|secret|key/i;
const NOT_TOKEN_NAME = /expir|ttl|until/i;
const LIFECYCLE = /expir|ttl|valid_?until|used_?at|consumed|single[_-]?use|\bdelete\b|\.delete\(/i;
const MIN_BYTES = 16;

function isResetHandler(entry: Entry): boolean {
  const text = entry.node.getText();
  return (entry.kind === 'route' && RESET_PATH.test(entry.routePath ?? '')) || RESET_TEXT.test(text) || RESET_PATH.test(entry.name);
}

/** Why an expression is a weak token source, if it is one. */
function weakSource(expression: Node, uuidV1: (call: Node) => boolean): boolean {
  return [expression, ...expression.getDescendants()].some((node) => {
    if (!Node.isCallExpression(node)) return false;
    const text = calleeText(node);
    if (text === 'Math.random' || text === 'Date.now' || uuidV1(node)) return true;
    if (calleeName(node) === 'randomBytes') {
      const size = numericValue(node.getArguments()[0]);
      return size !== undefined && size < MIN_BYTES;
    }
    return false;
  });
}

export const auth010: Rule = {
  id: 'AUTH-010',
  title: 'Weak password reset token',
  category: 'authentication',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'In password reset handlers (reset/forgot/recover paths, or code mentioning password resets), reports token-like ' +
    'variables or properties built from Math.random(), Date.now(), uuid v1 or randomBytes() with fewer than 16 bytes. A ' +
    'separate advisory finding is raised at the handler when the handler never writes an expiry or single-use marker. ' +
    'Handlers that delegate to supabase.auth.resetPasswordForEmail are skipped because Supabase issues the token.',
  explanation:
    'Reset tokens built this way are predictable, so an attacker can guess a valid link and take over any account that ' +
    'requested a reset.',
  fix: "Use `randomBytes(32).toString('base64url')`, store only its hash with an expiry of 15 to 60 minutes, and delete it when used.",
  falsePositiveNote: 'Projects that use Supabase Auth password resets do not create their own tokens and are skipped.',
  cwe: 'CWE-330',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      if (!isResetHandler(entry) || calls(entry.node).some((call) => calleeName(call) === 'resetPasswordForEmail')) continue;
      const uuid = importBindings(entry.node.getSourceFile(), ['uuid']);
      const uuidV1 = (call: Node) => Node.isCallExpression(call) && importedCallName(call, uuid) === 'v1';

      let createsToken = false;
      for (const node of entry.node.getDescendants()) {
        const isVariable = Node.isVariableDeclaration(node);
        const isProperty = Node.isPropertyAssignment(node);
        if (!isVariable && !isProperty) continue;
        const name = node.getName();
        const initializer = node.getInitializer();
        if (!initializer || !TOKEN_NAME.test(name) || NOT_TOKEN_NAME.test(name)) continue;
        if (initializer.getKind() === SyntaxKind.CallExpression || initializer.getDescendantsOfKind(SyntaxKind.CallExpression).length) createsToken = true;
        if (weakSource(initializer, uuidV1)) findings.push(findingAt(node));
      }
      if (createsToken && !LIFECYCLE.test(entry.node.getText())) {
        findings.push(
          findingAt(entry.node, {
            advisory: true,
            explanation: 'This reset handler creates a token but never stores an expiry or marks it as used, so a leaked reset link stays valid indefinitely.',
          }),
        );
      }
    }
    return findings;
  },
};
