import { Node, SyntaxKind } from 'ts-morph';
import safeRegex from 'safe-regex2';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, findingAt, receiverOf, sourceFiles, stringLiteral } from '../analysis/ast-utils.js';
import { entryFunctionOf, isUserInput } from '../analysis/taint.js';

const APPLY_METHODS = new Set(['test', 'exec']);
const STRING_METHODS = new Set(['match', 'matchAll', 'replace', 'replaceAll', 'search', 'split']);

/** Whether the regex at `node` (or the variable holding it) is applied to request input. */
function appliedToInput(node: Node): boolean {
  const holder = node.getParent();
  const name = holder && Node.isVariableDeclaration(holder) ? holder.getName() : undefined;
  const scope = node.getSourceFile();
  return scope.getDescendantsOfKind(SyntaxKind.CallExpression).some((call) => {
    const method = calleeName(call);
    const receiver = receiverOf(call);
    const isThisRegex = (candidate: Node | undefined) => candidate !== undefined && (candidate === node || (name !== undefined && candidate.getText() === name));
    if (APPLY_METHODS.has(method) && isThisRegex(receiver)) return call.getArguments().some((arg) => isUserInput(arg, entryFunctionOf(call), { regexSanitizes: false }));
    if (STRING_METHODS.has(method) && isThisRegex(call.getArguments()[0]) && receiver) return isUserInput(receiver, entryFunctionOf(call), { regexSanitizes: false });
    return false;
  });
}

export const input011: Rule = {
  id: 'INPUT-011',
  title: 'ReDoS-prone regular expression',
  category: 'input-validation',
  severity: 'low',
  confidence: 'low',
  stacks: ['nextjs-app-router'],
  description:
    'Runs safe-regex2 (star height and repetition limit) on regex literals and on new RegExp() with a literal pattern. ' +
    'Confidence is high when the same regex is applied to request input in the project (test/exec, or match/replace/split ' +
    'on a tainted string), low otherwise. Limitations: safe-regex2 has false positives and negatives; overlapping ' +
    'alternations are not detected.',
  explanation:
    'This regular expression can take exponential time on crafted input, so a single request with a long string can tie ' +
    'up the server’s event loop and make the app unresponsive.',
  fix: 'Rewrite the pattern without nested quantifiers (for example `^[^\\s@]+@[^\\s@]+$` instead of `^([\\w.]+)+@...`), cap the input length first, or use a linear-time engine such as RE2.',
  falsePositiveNote: 'A regex that never sees user-controlled input is harmless; those findings carry low confidence.',
  cwe: 'CWE-1333',
  references: ['https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS', 'https://github.com/fastify/safe-regex2'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx)) {
      const sourceFile = ctx.getSourceFile(file);
      const candidates: { node: Node; source: string }[] = [];
      for (const literal of sourceFile.getDescendantsOfKind(SyntaxKind.RegularExpressionLiteral)) {
        const text = literal.getText();
        candidates.push({ node: literal, source: text.slice(1, text.lastIndexOf('/')) });
      }
      for (const expression of sourceFile.getDescendantsOfKind(SyntaxKind.NewExpression)) {
        const pattern = expression.getExpression().getText() === 'RegExp' ? stringLiteral(expression.getArguments()[0]) : undefined;
        if (pattern !== undefined) candidates.push({ node: expression, source: pattern });
      }
      for (const { node, source } of candidates) {
        if (safeRegex(source)) continue;
        findings.push(findingAt(node, { confidence: appliedToInput(node) ? 'high' : 'low' }));
      }
    }
    return findings;
  },
};
