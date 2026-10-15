import { Node } from 'ts-morph';
import { hasDirective } from '../../context/ast.js';
import { compareStrings } from '../../context/files.js';
import type { ServerAction } from '../../types.js';
import type { NextSource } from './routes.js';

const SCRIPT_FILE = /\.(?:[cm]?[jt]sx?)$/;

type FunctionLike = Node & { getBody(): Node | undefined; isAsync(): boolean };

function isFunctionLike(node: Node): node is FunctionLike {
  return Node.isFunctionDeclaration(node) || Node.isFunctionExpression(node) || Node.isArrowFunction(node) || Node.isMethodDeclaration(node);
}

function isAsyncFunction(node: Node | undefined): node is FunctionLike {
  return node !== undefined && (Node.isFunctionExpression(node) || Node.isArrowFunction(node)) && node.isAsync();
}

/** Name of an inline server function: its own name, the variable or property it is assigned to, or `<inline@line>`. */
function inlineName(fn: FunctionLike): string {
  if ((Node.isFunctionDeclaration(fn) || Node.isFunctionExpression(fn) || Node.isMethodDeclaration(fn)) && fn.getName()) {
    return fn.getName()!;
  }
  const parent = fn.getParent();
  if (parent && (Node.isVariableDeclaration(parent) || Node.isPropertyAssignment(parent))) return parent.getName();
  return `<inline@${fn.getStartLineNumber()}>`;
}

/**
 * Server Functions (Server Actions): exported async functions in files whose first statement is
 * 'use server', plus inline functions whose body starts with 'use server'.
 */
export function findServerActions(source: NextSource): ServerAction[] {
  const actions: ServerAction[] = [];
  for (const file of source.files) {
    if (!SCRIPT_FILE.test(file) || !source.readText(file).includes('use server')) continue;
    const sourceFile = source.getSourceFile(file);
    const seen = new Set<Node>();
    const add = (name: string, node: Node) => {
      if (seen.has(node)) return;
      seen.add(node);
      actions.push({ file, name, node });
    };

    if (hasDirective(sourceFile, 'use server')) {
      for (const fn of sourceFile.getFunctions()) {
        if (fn.isExported() && fn.isAsync()) add(fn.isDefaultExport() ? 'default' : (fn.getName() ?? 'default'), fn);
      }
      for (const statement of sourceFile.getVariableStatements()) {
        if (!statement.isExported()) continue;
        for (const declaration of statement.getDeclarations()) {
          const initializer = declaration.getInitializer();
          if (isAsyncFunction(initializer)) add(declaration.getName(), initializer);
        }
      }
      for (const assignment of sourceFile.getExportAssignments()) {
        const expression = assignment.getExpression();
        if (!assignment.isExportEquals() && isAsyncFunction(expression)) add('default', expression);
      }
    }

    sourceFile.forEachDescendant((node) => {
      if (!isFunctionLike(node)) return;
      const body = node.getBody();
      if (body && Node.isBlock(body) && hasDirective(body, 'use server')) add(inlineName(node), node);
    });
  }

  return actions.sort(
    (a, b) => compareStrings(a.file, b.file) || a.node.getStartLineNumber() - b.node.getStartLineNumber() || compareStrings(a.name, b.name),
  );
}
