import { Node, SyntaxKind, type SourceFile } from 'ts-morph';
import type { RawFinding, Rule, ScanContext } from '../../../types.js';
import { calleeName, calleeNameNode, calls, declarationOf, findingAt, importBindings, importedCallName, isFunctionNode, sourceFiles, type FunctionNode } from '../analysis/ast-utils.js';
import { entryFunctionOf, isUserInput } from '../analysis/taint.js';

const LODASH = ['lodash', 'lodash-es', 'lodash/merge', 'lodash.merge', 'lodash/set', 'lodash.set', 'lodash/defaultsDeep', 'lodash/mergeWith'];
const LODASH_SINKS = /^(?:merge|mergeWith|defaultsDeep|set|setWith)$/;
const GUARD = /__proto__|['"`]constructor['"`]|Object\.create\(\s*null\s*\)/;

interface MergeFunction {
  name: string;
  fn: FunctionNode;
  /** The key-iteration statement, where the finding is reported. */
  loop: Node;
}

function functionName(fn: FunctionNode): string | undefined {
  if (Node.isFunctionDeclaration(fn)) return fn.getName();
  const parent = fn.getParent();
  return parent && Node.isVariableDeclaration(parent) ? parent.getName() : undefined;
}

/** The statement that walks a parameter's keys: for-in, or for-of / forEach over Object.keys/entries. */
function keyLoop(fn: FunctionNode): Node | undefined {
  for (const node of fn.getDescendants()) {
    if (Node.isForInStatement(node)) return node;
    if (Node.isForOfStatement(node) && /Object\.(?:keys|entries)\(/.test(node.getExpression().getText())) return node;
    if (Node.isCallExpression(node) && calleeName(node) === 'forEach' && /Object\.(?:keys|entries)\(/.test(node.getExpression().getText())) return node;
  }
  return undefined;
}

/** A guard mentioned in the function itself or in a module constant it references. */
function isGuarded(fn: FunctionNode): boolean {
  if (GUARD.test(fn.getText())) return true;
  return fn.getDescendantsOfKind(SyntaxKind.Identifier).some((identifier) => {
    const declaration = declarationOf(identifier);
    return declaration !== undefined && Node.isVariableDeclaration(declaration) && !declaration.getAncestors().includes(fn) && GUARD.test(declaration.getInitializer()?.getText() ?? '');
  });
}

/** Recursive key-copying merges without a __proto__/constructor guard. */
function unsafeMerges(sourceFile: SourceFile): MergeFunction[] {
  const result: MergeFunction[] = [];
  for (const node of sourceFile.getDescendants()) {
    if (!isFunctionNode(node)) continue;
    const name = functionName(node);
    const loop = keyLoop(node);
    if (!name || !loop) continue;
    const recursive = calls(node).some((call) => call.getExpression().getText() === name);
    const writesByKey = node.getDescendantsOfKind(SyntaxKind.BinaryExpression).some((b) => b.getOperatorToken().getKind() === SyntaxKind.EqualsToken && Node.isElementAccessExpression(b.getLeft()));
    if (recursive && writesByKey && !isGuarded(node)) result.push({ name, fn: node, loop });
  }
  return result;
}

/** Calls to `name` anywhere in the project that pass request data. */
function taintedCalls(ctx: ScanContext, files: string[], name: string): Node[] {
  return files.flatMap((file) =>
    calls(ctx.getSourceFile(file)).filter((call) => call.getExpression().getText() === name && call.getArguments().some((arg) => isUserInput(arg, entryFunctionOf(call)))),
  );
}

export const input012: Rule = {
  id: 'INPUT-012',
  title: 'Prototype pollution',
  category: 'input-validation',
  severity: 'medium',
  confidence: 'low',
  stacks: ['nextjs-app-router'],
  description:
    'Reports recursive merge functions that copy keys (for-in, Object.keys/entries) without a __proto__/constructor guard ' +
    'when some call in the project passes them request data (at the loop and at each such call), assignments ' +
    'obj[key] = value with a request-controlled key, and lodash merge/set/defaultsDeep on request data. Limitations: merges ' +
    'are matched by name across files; guards in helper functions are not recognised.',
  explanation:
    'Request data is merged key by key into an object, so a body such as {"__proto__": {"isAdmin": true}} can change the ' +
    'behaviour of every object in the server process.',
  fix: "Skip '__proto__', 'constructor' and 'prototype' keys (or use Object.create(null) targets and Object.hasOwn checks), validate input with a schema first, and avoid deep-merging request bodies.",
  falsePositiveNote: 'Merges whose input keys are fixed by a strict schema are safe but may still be reported.',
  cwe: 'CWE-1321',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html'],
  run(ctx) {
    const findings: RawFinding[] = [];
    const files = sourceFiles(ctx);

    for (const file of files) {
      for (const merge of unsafeMerges(ctx.getSourceFile(file))) {
        const sites = taintedCalls(ctx, files, merge.name);
        if (!sites.length) continue;
        findings.push(findingAt(merge.loop));
        for (const site of sites) findings.push(findingAt(site));
      }
    }

    for (const file of files) {
      const sourceFile = ctx.getSourceFile(file);
      for (const assignment of sourceFile.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
        const left = assignment.getLeft();
        if (assignment.getOperatorToken().getKind() !== SyntaxKind.EqualsToken || !Node.isElementAccessExpression(left)) continue;
        const key = left.getArgumentExpression();
        if (key && isUserInput(key, entryFunctionOf(assignment))) findings.push(findingAt(assignment));
      }
      const lodash = importBindings(sourceFile, LODASH);
      for (const call of calls(sourceFile)) {
        const callee = call.getExpression();
        // A default import of a per-method package (`import merge from 'lodash.merge'`) is called directly.
        const name = importedCallName(call, lodash) ?? (Node.isIdentifier(callee) && lodash.namespaces.has(callee.getText()) ? callee.getText() : undefined);
        if (!name || !LODASH_SINKS.test(name)) continue;
        if (call.getArguments().slice(1).some((arg) => isUserInput(arg, entryFunctionOf(call)))) findings.push(findingAt(calleeNameNode(call)));
      }
    }
    return findings;
  },
};
