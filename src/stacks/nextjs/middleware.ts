import { Node } from 'ts-morph';
import { staticPropertyName, unwrapExpression } from '../../context/ast.js';
import { fileSetOf } from '../../context/files.js';
import type { MiddlewareInfo } from '../../types.js';
import type { NextSource } from './routes.js';

/**
 * Next.js 16 renamed middleware.ts to proxy.ts (middleware is deprecated but still loaded).
 * The file lives at the project root, or under src/ when the app uses a src directory.
 */
export const MIDDLEWARE_FILES = [
  'proxy.ts',
  'proxy.js',
  'middleware.ts',
  'middleware.js',
  'src/proxy.ts',
  'src/proxy.js',
  'src/middleware.ts',
  'src/middleware.js',
] as const;

/** The proxy/middleware file and its `config.matcher` sources. null matchers = runs on every route. */
export function findMiddleware(source: NextSource): MiddlewareInfo | null {
  const files = fileSetOf(source.files);
  const file = MIDDLEWARE_FILES.find((f) => files.has(f));
  if (!file) return null;
  return { file, matchers: readMatchers(source, file) };
}

function readMatchers(source: NextSource, file: string): string[] | null {
  const declaration = source.getSourceFile(file).getVariableDeclaration('config');
  if (!declaration?.isExported()) return null;
  const initializer = declaration.getInitializer();
  const config = initializer ? unwrapExpression(initializer) : undefined;
  if (!config || !Node.isObjectLiteralExpression(config)) return null;

  const property = config.getProperties().find((p) => !Node.isSpreadAssignment(p) && staticPropertyName(p.getNameNode()) === 'matcher');
  if (!property || !Node.isPropertyAssignment(property)) return null;
  const value = property.getInitializer();
  if (!value) return null;

  // Next.js ignores matcher values it cannot read statically, so a dynamic matcher means "every route".
  const matcher = unwrapExpression(value);
  const single = stringValue(matcher);
  if (single !== undefined) return [single];
  if (!Node.isArrayLiteralExpression(matcher)) return null;

  const sources: string[] = [];
  for (const element of matcher.getElements()) {
    const entry = unwrapExpression(element);
    const text = stringValue(entry) ?? (Node.isObjectLiteralExpression(entry) ? objectSource(entry) : undefined);
    if (text === undefined) return null;
    sources.push(text);
  }
  return sources;
}

function stringValue(node: Node): string | undefined {
  return Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node) ? node.getLiteralValue() : undefined;
}

function objectSource(object: Node): string | undefined {
  if (!Node.isObjectLiteralExpression(object)) return undefined;
  const property = object.getProperty('source');
  if (!property || !Node.isPropertyAssignment(property)) return undefined;
  const initializer = property.getInitializer();
  return initializer ? stringValue(unwrapExpression(initializer)) : undefined;
}
