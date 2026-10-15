import { Node, Project, ts, type SourceFile } from 'ts-morph';

/**
 * Lazily parses files into ts-morph SourceFiles. The project lives in an in-memory file system and
 * never resolves imports or loads lib files, so parsing never reads, executes or type-checks the
 * scanned project beyond the text handed to it.
 */
export function createAstCache(readText: (file: string) => string): (file: string) => SourceFile {
  const project = new Project({
    useInMemoryFileSystem: true,
    skipAddingFilesFromTsConfig: true,
    skipFileDependencyResolution: true,
    skipLoadingLibFiles: true,
    compilerOptions: { allowJs: true, jsx: ts.JsxEmit.Preserve, noLib: true },
  });
  const cache = new Map<string, SourceFile>();
  return (file) => {
    let sourceFile = cache.get(file);
    if (!sourceFile) {
      sourceFile = project.createSourceFile(`/${file}`, readText(file), { overwrite: true });
      cache.set(file, sourceFile);
    }
    return sourceFile;
  };
}

/** String-literal directives ('use client', 'use server', ...) at the start of a file or block. */
export function directivePrologue(node: Node): string[] {
  if (!Node.isSourceFile(node) && !Node.isBlock(node)) return [];
  const directives: string[] = [];
  for (const statement of node.getStatements()) {
    if (!Node.isExpressionStatement(statement)) break;
    const expression = statement.getExpression();
    if (!Node.isStringLiteral(expression)) break;
    directives.push(expression.getLiteralValue());
  }
  return directives;
}

export function hasDirective(node: Node, directive: string): boolean {
  return directivePrologue(node).includes(directive);
}

/** Strips parentheses, `as`, `satisfies`, `<T>` assertions and `!` so callers see the underlying expression. */
export function unwrapExpression(node: Node): Node {
  let current = node;
  for (;;) {
    if (
      Node.isParenthesizedExpression(current) ||
      Node.isAsExpression(current) ||
      Node.isSatisfiesExpression(current) ||
      Node.isTypeAssertion(current) ||
      Node.isNonNullExpression(current)
    ) {
      current = current.getExpression();
    } else {
      return current;
    }
  }
}

/** Name of an object-literal property key when it is static (identifier, string or number). */
export function staticPropertyName(node: Node): string | undefined {
  if (Node.isIdentifier(node) || Node.isPrivateIdentifier(node)) return node.getText();
  if (Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node)) return node.getLiteralValue();
  if (Node.isNumericLiteral(node)) return String(node.getLiteralValue());
  return undefined;
}

export type LiteralResult = { ok: true; value: unknown } | { ok: false };

/** Evaluates a JSON-like literal (booleans, strings, numbers, null, arrays and objects of literals). */
export function literalValue(input: Node): LiteralResult {
  const node = unwrapExpression(input);
  if (Node.isTrueLiteral(node)) return { ok: true, value: true };
  if (Node.isFalseLiteral(node)) return { ok: true, value: false };
  if (Node.isNullLiteral(node)) return { ok: true, value: null };
  if (Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node)) return { ok: true, value: node.getLiteralValue() };
  if (Node.isNumericLiteral(node)) return { ok: true, value: node.getLiteralValue() };
  if (Node.isIdentifier(node) && node.getText() === 'undefined') return { ok: true, value: undefined };
  if (Node.isPrefixUnaryExpression(node) && node.getOperatorToken() === ts.SyntaxKind.MinusToken) {
    const operand = node.getOperand();
    if (Node.isNumericLiteral(operand)) return { ok: true, value: -operand.getLiteralValue() };
    return { ok: false };
  }
  if (Node.isArrayLiteralExpression(node)) {
    const values: unknown[] = [];
    for (const element of node.getElements()) {
      const result = literalValue(element);
      if (!result.ok) return { ok: false };
      values.push(result.value);
    }
    return { ok: true, value: values };
  }
  if (Node.isObjectLiteralExpression(node)) {
    const value: Record<string, unknown> = {};
    for (const property of node.getProperties()) {
      if (!Node.isPropertyAssignment(property)) return { ok: false };
      const name = staticPropertyName(property.getNameNode());
      const initializer = property.getInitializer();
      if (name === undefined || !initializer) return { ok: false };
      const result = literalValue(initializer);
      if (!result.ok) return { ok: false };
      value[name] = result.value;
    }
    return { ok: true, value };
  }
  return { ok: false };
}
