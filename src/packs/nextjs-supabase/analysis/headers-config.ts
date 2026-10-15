import { Node, SyntaxKind } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import { fileSetOf } from '../../../context/files.js';
import type { ScanContext } from '../../../types.js';
import { calleeName, isFunctionNode, objectProperty, receiverOf, resolveExpression, staticText } from './ast-utils.js';
import { middlewareFunction } from './auth-check.js';

export interface HeaderEntry {
  /** Lower-cased header name. */
  key: string;
  /** Literal value; template substitutions appear as `${}`; undefined when computed at runtime. */
  value: string | undefined;
  source: 'next.config' | 'middleware' | 'vercel.json' | '_headers';
  file: string;
  line: number;
}

/** Elements of an array literal, flattening `...spread` of other array constants. */
function arrayElements(node: Node | undefined, depth = 0): Node[] {
  if (!node || depth > 4) return [];
  const array = resolveExpression(node);
  if (!Node.isArrayLiteralExpression(array)) return [];
  return array.getElements().flatMap((element) => (Node.isSpreadElement(element) ? arrayElements(element.getExpression(), depth + 1) : [element]));
}

function nextConfigHeaders(ctx: ScanContext): HeaderEntry[] {
  const config = ctx.nextConfig;
  const option = config?.options.headers;
  if (!config || !option) return [];
  const sourceFile = ctx.getSourceFile(config.file);
  const property = sourceFile
    .getDescendants()
    .find((n) => (Node.isMethodDeclaration(n) || Node.isPropertyAssignment(n)) && n.getName() === 'headers' && n.getStartLineNumber() === option.line);
  if (!property) return [];
  const fn = Node.isPropertyAssignment(property) ? property.getInitializer() : property;
  if (!fn || !isFunctionNode(fn)) return [];
  const body = fn.getBody();
  const returned = body && Node.isBlock(body) ? body.getDescendantsOfKind(SyntaxKind.ReturnStatement).map((r) => r.getExpression()) : [body];
  const entries: HeaderEntry[] = [];
  for (const rule of returned.flatMap((value) => arrayElements(value))) {
    for (const header of arrayElements(objectProperty(rule, 'headers'))) {
      const key = staticText(objectProperty(header, 'key'));
      if (!key) continue;
      const valueNode = objectProperty(header, 'value');
      entries.push({ key: key.toLowerCase(), value: staticText(valueNode), source: 'next.config', file: config.file, line: header.getStartLineNumber() });
    }
  }
  return entries;
}

function middlewareHeaders(ctx: ScanContext): HeaderEntry[] {
  const middleware = ctx.next.middleware();
  const fn = middleware ? middlewareFunction(ctx, middleware.file) : undefined;
  if (!middleware || !fn) return [];
  const entries: HeaderEntry[] = [];
  for (const call of fn.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const receiver = receiverOf(call);
    if (!['set', 'append'].includes(calleeName(call)) || !receiver || !/headers$/i.test(unwrapExpression(receiver).getText())) continue;
    const [keyNode, valueNode] = call.getArguments();
    const key = staticText(keyNode);
    if (key) entries.push({ key: key.toLowerCase(), value: valueNode ? staticText(valueNode) : undefined, source: 'middleware', file: middleware.file, line: call.getStartLineNumber() });
  }
  return entries;
}

function vercelHeaders(ctx: ScanContext): HeaderEntry[] {
  const vercel = ctx.vercelJson;
  const rules = (vercel?.data as { headers?: { headers?: { key?: unknown; value?: unknown }[] }[] } | undefined)?.headers;
  if (!vercel || !Array.isArray(rules)) return [];
  const lines = ctx.readText(vercel.file).split(/\r?\n/);
  let cursor = 0;
  const entries: HeaderEntry[] = [];
  for (const rule of rules) {
    for (const header of rule.headers ?? []) {
      if (typeof header.key !== 'string') continue;
      const index = lines.findIndex((line, i) => i >= cursor && line.includes(JSON.stringify(header.key)));
      if (index !== -1) cursor = index + 1;
      entries.push({ key: header.key.toLowerCase(), value: typeof header.value === 'string' ? header.value : undefined, source: 'vercel.json', file: vercel.file, line: index + 1 });
    }
  }
  return entries;
}

/** Cloudflare Pages / Netlify `_headers`: path lines followed by indented `Name: value` lines. */
function headersFile(ctx: ScanContext): HeaderEntry[] {
  const file = 'public/_headers';
  if (!fileSetOf(ctx.files).has(file)) return [];
  const entries: HeaderEntry[] = [];
  ctx
    .readText(file)
    .split(/\r?\n/)
    .forEach((line, index) => {
      const match = /^\s+([A-Za-z0-9-]+)\s*:\s*(.*)$/.exec(line);
      if (match) entries.push({ key: match[1]!.toLowerCase(), value: match[2]!.trim(), source: '_headers', file, line: index + 1 });
    });
  return entries;
}

const cache = new WeakMap<ScanContext, HeaderEntry[]>();

/** Response headers the project sets for its pages: next.config headers(), proxy/middleware, vercel.json and public/_headers. */
export function collectHeaders(ctx: ScanContext): HeaderEntry[] {
  let entries = cache.get(ctx);
  if (!entries) {
    entries = [...nextConfigHeaders(ctx), ...middlewareHeaders(ctx), ...vercelHeaders(ctx), ...headersFile(ctx)];
    cache.set(ctx, entries);
  }
  return entries;
}

/** Values configured for one header (lower-case name); undefined entries are dynamic values. */
export function headerValues(ctx: ScanContext, key: string): (string | undefined)[] {
  return collectHeaders(ctx)
    .filter((h) => h.key === key)
    .map((h) => h.value);
}
