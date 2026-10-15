import { Node, SyntaxKind, type CallExpression, type Identifier, type SourceFile } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, ScanContext } from '../../../types.js';

export type FunctionNode = Node & { getParameters(): Node[]; getBody(): Node | undefined };

const SCRIPT_FILE = /\.(?:[cm]?[jt]sx?)$/;
const DECLARATION_FILE = /\.d\.[cm]?ts$/;
const TEST_PATH = /(?:^|\/)(?:__tests__|__mocks__|tests?|e2e|cypress|playwright)\/|\.(?:test|spec)\.[cm]?[jt]sx?$/;

/** Script files a rule should analyse: no tests, no declaration files. `filter` pre-screens raw text cheaply. */
export function sourceFiles(ctx: ScanContext, filter?: (text: string) => boolean): string[] {
  return ctx.files.filter((file) => SCRIPT_FILE.test(file) && !DECLARATION_FILE.test(file) && !TEST_PATH.test(file) && (!filter || filter(ctx.readText(file))));
}

export function isTestPath(file: string): boolean {
  return TEST_PATH.test(file);
}

export function isFunctionNode(node: Node): node is FunctionNode {
  return (
    Node.isFunctionDeclaration(node) ||
    Node.isFunctionExpression(node) ||
    Node.isArrowFunction(node) ||
    Node.isMethodDeclaration(node) ||
    Node.isGetAccessorDeclaration(node) ||
    Node.isSetAccessorDeclaration(node)
  );
}

export function enclosingFunction(node: Node): FunctionNode | undefined {
  return node.getFirstAncestor((a) => isFunctionNode(a)) as FunctionNode | undefined;
}

/** The outermost function containing `node` (or `node` itself when it is a function). */
export function outermostFunction(node: Node): FunctionNode | undefined {
  let found: FunctionNode | undefined = isFunctionNode(node) ? node : undefined;
  for (const ancestor of node.getAncestors()) if (isFunctionNode(ancestor)) found = ancestor;
  return found;
}

/** Repo-relative path of a parsed file (the AST cache stores files as `/<path>`). */
export function relativeFile(node: Node): string {
  return node.getSourceFile().getFilePath().replace(/^\/+/, '');
}

export function calls(node: Node): CallExpression[] {
  return node.getDescendantsOfKind(SyntaxKind.CallExpression);
}

/** Callee as dotted text without parentheses or whitespace: `supabase.auth.getUser`, `createClient().from("t").select`. */
export function calleeText(call: CallExpression): string {
  return expressionPath(call.getExpression());
}

function expressionPath(input: Node): string {
  const node = unwrapExpression(input);
  if (Node.isPropertyAccessExpression(node)) return `${expressionPath(node.getExpression())}.${node.getName()}`;
  if (Node.isCallExpression(node)) return `${expressionPath(node.getExpression())}(${node.getArguments().map((a) => a.getText()).join(',')})`;
  if (Node.isAwaitExpression(node)) return expressionPath(node.getExpression());
  if (Node.isElementAccessExpression(node)) return `${expressionPath(node.getExpression())}[${node.getArgumentExpression()?.getText() ?? ''}]`;
  return node.getText().replace(/\s+/g, '');
}

/** Last name of the callee: `getUser` for `supabase.auth.getUser()`, `fetch` for `fetch()`. */
export function calleeName(call: CallExpression): string {
  const callee = unwrapExpression(call.getExpression());
  if (Node.isPropertyAccessExpression(callee)) return callee.getName();
  if (Node.isIdentifier(callee)) return callee.getText();
  return '';
}

/** Object a method is called on (`supabase.auth` for `supabase.auth.getUser()`), if any. */
export function receiverOf(call: CallExpression): Node | undefined {
  const callee = unwrapExpression(call.getExpression());
  return Node.isPropertyAccessExpression(callee) ? callee.getExpression() : undefined;
}

export function stringLiteral(node: Node | undefined): string | undefined {
  if (!node) return undefined;
  const inner = unwrapExpression(node);
  return Node.isStringLiteral(inner) || Node.isNoSubstitutionTemplateLiteral(inner) ? inner.getLiteralValue() : undefined;
}

/** Text of a string or template literal with substitutions replaced by `${}`. */
export function staticText(node: Node | undefined): string | undefined {
  if (!node) return undefined;
  const inner = unwrapExpression(node);
  const literal = stringLiteral(inner);
  if (literal !== undefined) return literal;
  if (Node.isTemplateExpression(inner)) {
    return inner.getHead().getLiteralText() + inner.getTemplateSpans().map((span) => '${}' + span.getLiteral().getLiteralText()).join('');
  }
  return undefined;
}

/** Declaration (variable, binding element, parameter or function) that `identifier` refers to, searched lexically. */
export function declarationOf(identifier: Identifier): Node | undefined {
  const name = identifier.getText();
  const position = identifier.getStart();
  for (let scope: Node | undefined = identifier.getParent(); scope; scope = scope.getParent()) {
    if (isFunctionNode(scope)) {
      for (const parameter of scope.getParameters()) {
        const found = bindingNamed(parameter, name);
        if (found) return found;
      }
    }
    if (isScope(scope)) {
      const candidates = scopeDeclarations(scope).get(name) ?? [];
      const before = candidates.filter((d) => d.getStart() <= position || Node.isFunctionDeclaration(d));
      const chosen = before.at(-1) ?? candidates[0];
      if (chosen) return chosen;
    }
  }
  return undefined;
}

function isScope(node: Node): boolean {
  return Node.isBlock(node) || Node.isSourceFile(node) || isFunctionNode(node) || Node.isCaseClause(node) || Node.isForOfStatement(node) || Node.isForInStatement(node) || Node.isForStatement(node);
}

const scopeCache = new WeakMap<Node, Map<string, Node[]>>();

/** Declarations owned directly by `scope`, by name, computed once per scope. */
function scopeDeclarations(scope: Node): Map<string, Node[]> {
  let byName = scopeCache.get(scope);
  if (!byName) {
    const map = new Map<string, Node[]>();
    scope.forEachDescendant((d) => {
      if (!(Node.isVariableDeclaration(d) || Node.isBindingElement(d) || Node.isFunctionDeclaration(d)) || ownerScope(d) !== scope) return;
      const name = declaredName(d);
      if (name) map.set(name, [...(map.get(name) ?? []), d]);
    });
    scopeCache.set(scope, map);
    byName = map;
  }
  return byName;
}

function declaredName(node: Node): string | undefined {
  if (Node.isVariableDeclaration(node)) {
    const nameNode = node.getNameNode();
    return Node.isIdentifier(nameNode) ? nameNode.getText() : undefined;
  }
  if (Node.isBindingElement(node)) {
    const nameNode = node.getNameNode();
    return Node.isIdentifier(nameNode) ? nameNode.getText() : undefined;
  }
  if (Node.isFunctionDeclaration(node)) return node.getName();
  return undefined;
}

/** The scope node (block, function body owner, source file, loop) a declaration belongs to. */
function ownerScope(node: Node): Node | undefined {
  for (let current = node.getParent(); current; current = current.getParent()) {
    if (Node.isBlock(current)) {
      const parent = current.getParent();
      return parent && isFunctionNode(parent) ? parent : current;
    }
    if (Node.isSourceFile(current) || isFunctionNode(current) || Node.isCaseClause(current) || Node.isForOfStatement(current) || Node.isForInStatement(current) || Node.isForStatement(current)) {
      return current;
    }
  }
  return undefined;
}

/** A parameter or a binding element inside a parameter's destructuring pattern with the given name. */
function bindingNamed(node: Node, name: string): Node | undefined {
  if (Node.isParameterDeclaration(node)) {
    const nameNode = node.getNameNode();
    if (Node.isIdentifier(nameNode)) return nameNode.getText() === name ? node : undefined;
    return bindingNamed(nameNode, name);
  }
  if (Node.isObjectBindingPattern(node) || Node.isArrayBindingPattern(node)) {
    for (const element of node.getElements()) {
      if (!Node.isBindingElement(element)) continue;
      const nameNode = element.getNameNode();
      if (Node.isIdentifier(nameNode) && nameNode.getText() === name) return element;
      const nested = bindingNamed(nameNode, name);
      if (nested) return nested;
    }
  }
  return undefined;
}

/** Follows identifiers to their `const`/`let` initializers (up to `depth` steps) and unwraps the result. */
export function resolveExpression(node: Node, depth = 3): Node {
  let current = unwrapExpression(node);
  for (let i = 0; i < depth && Node.isIdentifier(current); i++) {
    const declaration = declarationOf(current);
    const initializer = declaration && Node.isVariableDeclaration(declaration) ? declaration.getInitializer() : undefined;
    if (!initializer) break;
    current = unwrapExpression(initializer);
  }
  return current;
}

/** Constant-folds numeric literals and + - * / through identifiers. */
export function numericValue(node: Node | undefined, depth = 3): number | undefined {
  if (!node) return undefined;
  const inner = resolveExpression(node, depth);
  if (Node.isNumericLiteral(inner)) return inner.getLiteralValue();
  if (Node.isPrefixUnaryExpression(inner) && inner.getOperatorToken() === SyntaxKind.MinusToken) {
    const value = numericValue(inner.getOperand(), depth);
    return value === undefined ? undefined : -value;
  }
  if (Node.isBinaryExpression(inner)) {
    const left = numericValue(inner.getLeft(), depth);
    const right = numericValue(inner.getRight(), depth);
    if (left === undefined || right === undefined) return undefined;
    switch (inner.getOperatorToken().getKind()) {
      case SyntaxKind.PlusToken:
        return left + right;
      case SyntaxKind.MinusToken:
        return left - right;
      case SyntaxKind.AsteriskToken:
        return left * right;
      case SyntaxKind.SlashToken:
        return right === 0 ? undefined : left / right;
      default:
        return undefined;
    }
  }
  return undefined;
}

/** Initializer of a property in an object literal (resolving an identifier argument to its object first). */
export function objectProperty(node: Node | undefined, name: string): Node | undefined {
  if (!node) return undefined;
  const object = resolveExpression(node);
  if (!Node.isObjectLiteralExpression(object)) return undefined;
  for (const property of object.getProperties()) {
    if (Node.isPropertyAssignment(property) && propertyName(property.getNameNode()) === name) return property.getInitializer();
    if (Node.isShorthandPropertyAssignment(property) && property.getName() === name) return property.getNameNode();
  }
  return undefined;
}

function propertyName(node: Node): string | undefined {
  if (Node.isIdentifier(node)) return node.getText();
  if (Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node)) return node.getLiteralValue();
  return undefined;
}

/** Whether an object literal (after resolution) spreads another value we cannot see. */
export function objectHasSpread(node: Node | undefined): boolean {
  if (!node) return false;
  const object = resolveExpression(node);
  return Node.isObjectLiteralExpression(object) && object.getProperties().some((p) => Node.isSpreadAssignment(p));
}

export function lineText(sourceFile: SourceFile, line: number): string {
  return sourceFile.getFullText().split(/\r?\n/)[line - 1] ?? '';
}

/** A RawFinding at `node`: its file, start line and that line's trimmed text as evidence. */
export function findingAt(node: Node, extra: Partial<RawFinding> = {}): RawFinding {
  const line = node.getStartLineNumber();
  return { file: relativeFile(node), line, evidence: lineText(node.getSourceFile(), line).trim(), ...extra };
}

/** Whether `fn` (excluding nested function bodies) contains a node matching `predicate`. */
export function someInFunction(fn: Node, predicate: (node: Node) => boolean): boolean {
  let found = false;
  fn.forEachDescendant((node, traversal) => {
    if (found) return traversal.stop();
    if (predicate(node)) {
      found = true;
      traversal.stop();
    }
  });
  return found;
}

/** Top-level statement that holds `node` (the node itself for top-level statements). */
export function topLevelStatement(node: Node): Node | undefined {
  let current: Node | undefined = node;
  while (current && !Node.isSourceFile(current.getParent() ?? current)) current = current.getParent();
  return current && Node.isSourceFile(current) ? undefined : current;
}

/** Whether a top-level statement is exported (`export function`, `export const`, `export default`). */
export function isExportedStatement(statement: Node | undefined): boolean {
  if (!statement) return false;
  if (Node.isFunctionDeclaration(statement) || Node.isVariableStatement(statement) || Node.isClassDeclaration(statement)) return statement.isExported();
  return Node.isExportAssignment(statement);
}

/** The node naming the called method (`eq` in `q.eq('id', x)`), for reporting at the method's own line. */
export function calleeNameNode(call: CallExpression): Node {
  const callee = unwrapExpression(call.getExpression());
  return Node.isPropertyAccessExpression(callee) ? callee.getNameNode() : call;
}

export interface ImportBindings {
  /** Local name -> exported name, for named imports and `const { a } = require(...)`. */
  named: Map<string, string>;
  /** Local names bound to the whole module (default, namespace or `require(...)`). */
  namespaces: Set<string>;
}

/** How a file refers to any of `modules`: named, default and namespace imports plus CommonJS require. */
export function importBindings(sourceFile: SourceFile, modules: readonly string[]): ImportBindings {
  const named = new Map<string, string>();
  const namespaces = new Set<string>();
  for (const declaration of sourceFile.getImportDeclarations()) {
    if (!modules.includes(declaration.getModuleSpecifierValue())) continue;
    const whole = declaration.getNamespaceImport() ?? declaration.getDefaultImport();
    if (whole) namespaces.add(whole.getText());
    for (const specifier of declaration.getNamedImports()) named.set(specifier.getAliasNode()?.getText() ?? specifier.getName(), specifier.getName());
  }
  for (const variable of sourceFile.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const init = variable.getInitializer();
    if (!init || !Node.isCallExpression(init) || init.getExpression().getText() !== 'require' || !modules.includes(stringLiteral(init.getArguments()[0]) ?? '')) continue;
    const name = variable.getNameNode();
    if (Node.isIdentifier(name)) namespaces.add(name.getText());
    else if (Node.isObjectBindingPattern(name)) for (const element of name.getElements()) named.set(element.getName(), element.getPropertyNameNode()?.getText() ?? element.getName());
  }
  return { named, namespaces };
}

/** The module export a call refers to (`verify` for `jwt.verify()` or an imported `verify()`), if bound. */
export function importedCallName(call: CallExpression, bindings: ImportBindings): string | undefined {
  const callee = unwrapExpression(call.getExpression());
  if (Node.isIdentifier(callee)) return bindings.named.get(callee.getText());
  if (Node.isPropertyAccessExpression(callee) && bindings.namespaces.has(callee.getExpression().getText())) return callee.getName();
  return undefined;
}
