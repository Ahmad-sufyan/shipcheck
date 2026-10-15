import { Node, SyntaxKind, type CallExpression } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calls, declarationOf, findingAt, receiverOf, type FunctionNode } from '../analysis/ast-utils.js';
import { entries } from '../analysis/entries.js';
import { isSchemaValidationCall } from '../analysis/sanitizers.js';

const BODY_READERS = new Set(['json', 'formData', 'text']);
const REQUEST_NAME = /^(?:req|request)$/i;

function bodyReads(fn: FunctionNode): CallExpression[] {
  const [first] = fn.getParameters();
  const requestName = first && Node.isParameterDeclaration(first) ? first.getName() : undefined;
  return calls(fn).filter((call) => {
    const receiver = receiverOf(call);
    if (!BODY_READERS.has(calleeName(call)) || !receiver || !Node.isIdentifier(receiver)) return false;
    return REQUEST_NAME.test(receiver.getText()) || receiver.getText() === requestName;
  });
}

/** True when every field read from the form data is treated as a File (cast or instanceof check). */
function onlyFileFields(read: CallExpression, fn: FunctionNode): boolean {
  let holder: Node = read;
  while (holder.getParent() && (Node.isAwaitExpression(holder.getParent()!) || Node.isParenthesizedExpression(holder.getParent()!))) holder = holder.getParent()!;
  const declaration = holder.getParent();
  if (!declaration || !Node.isVariableDeclaration(declaration)) return false;
  const formName = declaration.getName();
  const gets = calls(fn).filter((call) => {
    const receiver = receiverOf(call);
    return ['get', 'getAll'].includes(calleeName(call)) && receiver !== undefined && Node.isIdentifier(receiver) && receiver.getText() === formName && declarationOf(receiver) === declaration;
  });
  if (!gets.length) return false;
  const text = fn.getText();
  return gets.every((get) => {
    const parent = get.getParent();
    if (parent && Node.isAsExpression(parent) && /^(?:File|Blob)$/.test(parent.getTypeNode()?.getText() ?? '')) return true;
    const variable = get.getFirstAncestorByKind(SyntaxKind.VariableDeclaration);
    return variable !== undefined && new RegExp(`\\b${variable.getName()}\\s+instanceof\\s+(?:File|Blob)\\b`).test(text);
  });
}

export const input010: Rule = {
  id: 'INPUT-010',
  title: 'No schema validation of request input',
  category: 'input-validation',
  severity: 'medium',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports route handlers that read request.json(), request.formData() or request.text(), and server actions that take ' +
    'arguments, when the function never calls a schema validator (zod parse/safeParse, valibot parse, yup validate, ' +
    'arktype assert). Form reads whose fields are only used as File objects are left to INPUT-009. Limitations: validation ' +
    'in a wrapper or another module is not recognised.',
  explanation:
    'Request data is used without checking its shape, so callers can send unexpected types, extra fields or huge values ' +
    'that later code trusts.',
  fix: 'Parse input with a schema before using it, for example `const input = Schema.parse(await request.json())` with zod.',
  falsePositiveNote: 'Validation done in a wrapper (for example a safe-action client) or in another module is not recognised; suppress those findings with a shipcheck-ignore comment.',
  cwe: 'CWE-20',
  references: ['https://nextjs.org/docs/app/guides/forms#form-validation', 'https://zod.dev/'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      const fn = entry.fn;
      if (!fn || calls(fn).some(isSchemaValidationCall)) continue;
      if (entry.kind === 'route') {
        const reads = bodyReads(fn).filter((read) => !(calleeName(read) === 'formData' && onlyFileFields(read, fn)));
        if (reads[0]) findings.push(findingAt(reads[0]));
      } else if (fn.getParameters().length > 0) {
        findings.push(findingAt(unwrapExpression(entry.node)));
      }
    }
    return findings;
  },
};
