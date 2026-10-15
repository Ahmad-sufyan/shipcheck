import { Node } from 'ts-morph';
import type { RouteHandler, ScanContext } from '../../types.js';

export type NextSource = Pick<ScanContext, 'files' | 'readText' | 'getSourceFile'>;
export type HttpMethod = RouteHandler['method'];

export const HTTP_METHODS: readonly HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

const ROUTE_FILE = /^(?:src\/)?app\/(?:(.+)\/)?route\.(?:ts|js|tsx|jsx)$/;

function isHttpMethod(name: string | undefined): name is HttpMethod {
  return name !== undefined && (HTTP_METHODS as readonly string[]).includes(name);
}

/**
 * URL path for an App Router route.ts file, or null when the file is not a route handler.
 * Route groups `(name)` and parallel-route slots `@slot` are dropped; dynamic segments are kept;
 * files under private `_folders` are not routable.
 */
export function routePathFromFile(file: string): string | null {
  const match = ROUTE_FILE.exec(file);
  if (!match) return null;
  const segments: string[] = [];
  for (const segment of (match[1] ?? '').split('/').filter(Boolean)) {
    if (segment.startsWith('_')) return null;
    if (/^\([^.)][^)]*\)$/.test(segment)) continue;
    if (segment.startsWith('@')) continue;
    segments.push(segment);
  }
  return `/${segments.join('/')}`;
}

/**
 * Exported HTTP method handlers: `export [async] function GET`, `export const POST = <arrow | function | wrapper call>`
 * and `export { handler as PATCH }` for local bindings. Re-exports from other modules are not followed.
 */
export function findRouteHandlers(source: NextSource): RouteHandler[] {
  const handlers: RouteHandler[] = [];
  for (const file of source.files) {
    const routePath = routePathFromFile(file);
    if (routePath === null) continue;
    const sourceFile = source.getSourceFile(file);
    const found = new Map<HttpMethod, Node>();

    for (const fn of sourceFile.getFunctions()) {
      const name = fn.getName();
      if (fn.isExported() && !fn.isDefaultExport() && isHttpMethod(name)) found.set(name, fn);
    }
    for (const statement of sourceFile.getVariableStatements()) {
      if (!statement.isExported()) continue;
      for (const declaration of statement.getDeclarations()) {
        const name = declaration.getName();
        const initializer = declaration.getInitializer();
        if (isHttpMethod(name) && initializer) found.set(name, initializer);
      }
    }
    for (const exportDeclaration of sourceFile.getExportDeclarations()) {
      if (exportDeclaration.getModuleSpecifier()) continue;
      for (const specifier of exportDeclaration.getNamedExports()) {
        const exportedName = specifier.getAliasNode()?.getText() ?? specifier.getName();
        if (!isHttpMethod(exportedName)) continue;
        const local = specifier.getName();
        const target = sourceFile.getFunction(local) ?? sourceFile.getVariableDeclaration(local)?.getInitializer();
        if (target) found.set(exportedName, target);
      }
    }

    for (const method of HTTP_METHODS) {
      const node = found.get(method);
      if (node) handlers.push({ file, routePath, method, node });
    }
  }
  return handlers;
}
