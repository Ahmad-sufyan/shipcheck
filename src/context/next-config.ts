import { Node, SyntaxKind, type ObjectLiteralExpression, type SourceFile } from 'ts-morph';
import type { NextConfigInfo, NextConfigOption } from '../types.js';
import { literalValue, staticPropertyName, unwrapExpression } from './ast.js';
import type { Skipped } from './configs.js';
import type { ProjectSource } from './files.js';

/** In Next.js lookup order. next.config.cjs / .cts are not supported by Next.js. */
export const NEXT_CONFIG_FILES = ['next.config.js', 'next.config.mjs', 'next.config.ts', 'next.config.mts'] as const;

/**
 * Statically reads the exported next.config object. The file is parsed, never imported or executed.
 * Handles `export default`, `module.exports`, a const reference, wrapper calls such as
 * `withSentryConfig(config)` or `withX(opts)(config)`, and the `(phase) => config` function form.
 */
export function readNextConfig(source: ProjectSource, getSourceFile: (file: string) => SourceFile, skipped: Skipped[]): NextConfigInfo | null {
  const file = NEXT_CONFIG_FILES.find((f) => source.has(f));
  if (!file) return null;

  const sourceFile = getSourceFile(file);
  const exported = findExportedExpression(sourceFile);
  const object = exported ? resolveObject(exported, new Set()) : undefined;
  if (!object) {
    skipped.push({ check: file, reason: 'could not statically resolve the exported config object; next.config checks were skipped' });
    return null;
  }

  const options: Record<string, NextConfigOption> = {};
  let hasSpread = false;
  for (const property of object.getProperties()) {
    if (Node.isSpreadAssignment(property)) {
      hasSpread = true;
      continue;
    }
    const name = staticPropertyName(property.getNameNode());
    if (name === undefined) continue;
    const line = property.getStartLineNumber();
    const initializer = Node.isPropertyAssignment(property) ? property.getInitializer() : undefined;
    const literal = initializer ? literalValue(initializer) : { ok: false as const };
    options[name] = literal.ok ? { value: literal.value, line, dynamic: false } : { value: undefined, line, dynamic: true };
  }

  return {
    file,
    objectLine: object.getStartLineNumber(),
    options,
    hasHeadersFn: options.headers?.dynamic === true,
    hasSpread,
  };
}

/** The last `export default`, `export =` or `module.exports =` value in the file. */
function findExportedExpression(sourceFile: SourceFile): Node | undefined {
  let found: Node | undefined;
  for (const statement of sourceFile.getStatements()) {
    if (Node.isExportAssignment(statement)) {
      found = statement.getExpression();
    } else if (Node.isFunctionDeclaration(statement) && statement.isDefaultExport()) {
      found = statement;
    } else if (Node.isExpressionStatement(statement)) {
      const expression = statement.getExpression();
      if (
        Node.isBinaryExpression(expression) &&
        expression.getOperatorToken().getKind() === SyntaxKind.EqualsToken &&
        expression.getLeft().getText().replace(/\s/g, '') === 'module.exports'
      ) {
        found = expression.getRight();
      }
    }
  }
  return found;
}

function resolveObject(input: Node, seen: Set<Node>): ObjectLiteralExpression | undefined {
  const node = unwrapExpression(input);
  if (seen.has(node)) return undefined;
  seen.add(node);

  if (Node.isObjectLiteralExpression(node)) return node;
  if (Node.isAwaitExpression(node)) return resolveObject(node.getExpression(), seen);
  if (Node.isIdentifier(node)) {
    const initializer = findVariableInitializer(node);
    if (initializer) return resolveObject(initializer, seen);
    const fn = node.getSourceFile().getFunction(node.getText());
    return fn ? resolveObject(fn, seen) : undefined;
  }
  if (Node.isCallExpression(node)) {
    for (const argument of node.getArguments()) {
      const resolved = resolveObject(argument, seen);
      if (resolved) return resolved;
    }
    const callee = unwrapExpression(node.getExpression());
    return Node.isCallExpression(callee) ? resolveObject(callee, seen) : undefined;
  }
  if (Node.isArrowFunction(node) || Node.isFunctionExpression(node) || Node.isFunctionDeclaration(node)) {
    const body = node.getBody();
    if (!body) return undefined;
    if (!Node.isBlock(body)) return resolveObject(body, seen);
    const returns = body
      .getDescendantsOfKind(SyntaxKind.ReturnStatement)
      .filter((ret) => ret.getFirstAncestor((a) => Node.isFunctionLikeDeclaration(a)) === node);
    for (const ret of returns.reverse()) {
      const expression = ret.getExpression();
      const resolved = expression ? resolveObject(expression, seen) : undefined;
      if (resolved) return resolved;
    }
  }
  return undefined;
}

/** Initializer of the closest preceding `const/let/var name = ...` with the identifier's name. */
function findVariableInitializer(identifier: Node): Node | undefined {
  const name = identifier.getText();
  const position = identifier.getStart();
  const candidates = identifier
    .getSourceFile()
    .getDescendantsOfKind(SyntaxKind.VariableDeclaration)
    .filter((decl) => decl.getName() === name && decl.getStart() < position);
  return candidates.at(-1)?.getInitializer();
}
