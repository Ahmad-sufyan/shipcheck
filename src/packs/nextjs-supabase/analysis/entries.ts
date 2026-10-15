import { Node } from 'ts-morph';
import type { RouteHandler, ScanContext } from '../../../types.js';
import { isFunctionNode, type FunctionNode } from './ast-utils.js';

/** Something an attacker can call directly: a route handler or a server action. */
export interface Entry {
  kind: 'route' | 'action';
  file: string;
  /** The exported node (a function, or a wrapper call such as `withAuth(fn)`). */
  node: Node;
  /** The function holding the handler body (the wrapped function for wrapper calls). */
  fn: FunctionNode | undefined;
  name: string;
  routePath?: string;
  method?: RouteHandler['method'];
}

/** The function behind an exported handler: itself, or the first function argument of a wrapper call. */
export function handlerFunction(node: Node): FunctionNode | undefined {
  if (isFunctionNode(node)) return node;
  if (Node.isCallExpression(node)) {
    for (const arg of node.getArguments()) {
      const fn = handlerFunction(arg);
      if (fn) return fn;
    }
  }
  return undefined;
}

const cache = new WeakMap<ScanContext, Entry[]>();

export function entries(ctx: ScanContext): Entry[] {
  let list = cache.get(ctx);
  if (!list) {
    list = [
      ...ctx.next.routeHandlers().map(
        (h): Entry => ({ kind: 'route', file: h.file, node: h.node, fn: handlerFunction(h.node), name: h.method, routePath: h.routePath, method: h.method }),
      ),
      ...ctx.next.serverActions().map((a): Entry => ({ kind: 'action', file: a.file, node: a.node, fn: handlerFunction(a.node), name: a.name })),
    ];
    cache.set(ctx, list);
  }
  return list;
}

export const MUTATING_METHODS: ReadonlySet<string> = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const PAGE_FILE = /^(?:src\/)?app\/(?:(.+)\/)?page\.(?:tsx|jsx|ts|js)$/;

/** URL path of an App Router page.tsx, or null (same segment rules as route handlers). */
export function pagePathFromFile(file: string): string | null {
  const match = PAGE_FILE.exec(file);
  if (!match) return null;
  const segments: string[] = [];
  for (const segment of (match[1] ?? '').split('/').filter(Boolean)) {
    if (segment.startsWith('_')) return null;
    if (/^\([^.)][^)]*\)$/.test(segment) || segment.startsWith('@')) continue;
    segments.push(segment);
  }
  return `/${segments.join('/')}`;
}

/** Pages with their default-exported component function. */
export function pages(ctx: ScanContext): { file: string; routePath: string; fn: FunctionNode | undefined }[] {
  const result: { file: string; routePath: string; fn: FunctionNode | undefined }[] = [];
  for (const file of ctx.files) {
    const routePath = pagePathFromFile(file);
    if (routePath === null) continue;
    const sourceFile = ctx.getSourceFile(file);
    const fn = sourceFile.getFunctions().find((f) => f.isDefaultExport());
    result.push({ file, routePath, fn });
  }
  return result;
}
