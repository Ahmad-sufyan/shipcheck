import { Node, SyntaxKind, type CallExpression } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeText, findingAt, receiverOf, resolveExpression, sourceFiles, stringLiteral } from '../analysis/ast-utils.js';

const CONSOLE = /^console\.(?:log|info|warn|error|debug|trace)$/;
const LOGGER_METHODS = new Set(['info', 'warn', 'error', 'debug', 'trace', 'fatal', 'log']);
const LOGGER_NAME = /^(?:logger|log|pino|winston|logtail|axiom|bunyan)$/i;
const SENSITIVE_WORDS = new Set(['password', 'passwd', 'pwd', 'secret', 'token', 'authorization', 'cookie', 'cookies', 'cvv', 'cvc', 'ssn', 'apikey', 'cardnumber']);
const SENSITIVE_PAIRS = [['api', 'key'], ['card', 'number'], ['private', 'key'], ['access', 'token'], ['refresh', 'token']];

/** `accessToken` -> ['access', 'token'], `password_hash` -> ['password', 'hash']. */
function words(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((w) => w.toLowerCase());
}

function sensitiveName(name: string): boolean {
  const parts = words(name);
  if (parts.some((w) => SENSITIVE_WORDS.has(w))) return true;
  return SENSITIVE_PAIRS.some(([a, b]) => parts.some((w, i) => w === a && parts[i + 1] === b));
}

function isLogCall(call: CallExpression): boolean {
  if (CONSOLE.test(calleeText(call))) return true;
  const receiver = receiverOf(call);
  if (!receiver || !LOGGER_METHODS.has(calleeName(call)) || !Node.isIdentifier(receiver)) return false;
  if (!LOGGER_NAME.test(receiver.getText())) return false;
  // Loggers configured with redaction (pino `redact`, winston format) are trusted to scrub fields.
  return !/redact/i.test(resolveExpression(receiver).getText());
}

/** A whole request body or header bag: `await request.json()`, `request.headers`, `headers()`, or a variable holding one. */
function wholeRequestObject(arg: Node): boolean {
  let node: Node = unwrapExpression(arg);
  if (Node.isIdentifier(node)) node = resolveExpression(node);
  if (Node.isAwaitExpression(node)) node = unwrapExpression(node.getExpression());
  if (Node.isPropertyAccessExpression(node)) return /^(?:headers|cookies|body)$/.test(node.getName()) && /^(?:req|request)$/i.test(node.getExpression().getText());
  if (!Node.isCallExpression(node)) return false;
  const name = calleeName(node);
  const receiver = receiverOf(node);
  return (['json', 'formData'].includes(name) && receiver !== undefined && /^(?:req|request)$/i.test(receiver.getText())) || (Node.isIdentifier(node.getExpression()) && ['headers', 'cookies'].includes(name));
}

function mentionsSecret(arg: Node): boolean {
  for (const node of [arg, ...arg.getDescendants()]) {
    if (Node.isIdentifier(node) && sensitiveName(node.getText())) return true;
    if ((Node.isPropertyAssignment(node) || Node.isShorthandPropertyAssignment(node)) && sensitiveName(node.getName())) return true;
    if (Node.isCallExpression(node) && calleeName(node) === 'get' && sensitiveName(stringLiteral(node.getArguments()[0]) ?? '')) return true;
  }
  return false;
}

export const data001: Rule = {
  id: 'DATA-001',
  title: 'Sensitive data in logs',
  category: 'data-protection',
  severity: 'medium',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports console.* calls and logger.* calls (logger, pino, winston, ...) whose arguments name a password, secret, ' +
    'token, authorization header, cookie, card number or API key, or that log a whole request body, header bag or cookie ' +
    'store. Loggers created with a redact option are skipped. Limitations: logger instances imported from other modules ' +
    'are not inspected for redaction.',
  explanation:
    'Secrets and personal data end up in log files and logging services, where many more people and tools can read ' +
    'them, and they are kept long after the request.',
  fix: 'Log identifiers (user id, request id) instead of values, and configure redaction in your logger (for example pino `redact: [\'password\', \'req.headers.authorization\']`).',
  falsePositiveNote: 'Loggers that redact centrally (configured in another module) still get findings at the call site.',
  cwe: 'CWE-532',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => /console\.|logger|pino|winston|logtail|bunyan/.test(text))) {
      for (const call of ctx.getSourceFile(file).getDescendantsOfKind(SyntaxKind.CallExpression)) {
        if (!isLogCall(call)) continue;
        if (call.getArguments().some((arg) => mentionsSecret(arg) || wholeRequestObject(arg))) findings.push(findingAt(call));
      }
    }
    return findings;
  },
};
