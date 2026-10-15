import { posix } from 'node:path';
import { Node, SyntaxKind } from 'ts-morph';
import { parseJsonc } from '../../../context/configs.js';
import { fileSetOf } from '../../../context/files.js';
import type { ScanContext } from '../../../types.js';
import { sourceFiles, stringLiteral } from './ast-utils.js';

const EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.mts', '.cjs', '.cts'];

interface PathAliases {
  baseUrl: string;
  paths: [pattern: string, targets: string[]][];
}

const aliasCache = new WeakMap<ScanContext, PathAliases>();

/** compilerOptions.baseUrl and paths from tsconfig.json or jsconfig.json at the scan root. */
function pathAliases(ctx: ScanContext): PathAliases {
  let aliases = aliasCache.get(ctx);
  if (!aliases) {
    aliases = { baseUrl: '.', paths: [] };
    const files = fileSetOf(ctx.files);
    const configFile = ['tsconfig.json', 'jsconfig.json'].find((f) => files.has(f));
    if (configFile) {
      try {
        const options = (parseJsonc(ctx.readText(configFile)) as { compilerOptions?: { baseUrl?: string; paths?: Record<string, string[]> } }).compilerOptions ?? {};
        aliases = { baseUrl: options.baseUrl ?? '.', paths: Object.entries(options.paths ?? {}) };
      } catch {
        // An unparseable tsconfig only costs us alias resolution.
      }
    }
    aliasCache.set(ctx, aliases);
  }
  return aliases;
}

function existing(ctx: ScanContext, base: string): string | undefined {
  const files = fileSetOf(ctx.files);
  const normalized = posix.normalize(base).replace(/^\.\//, '');
  const withoutJs = normalized.replace(/\.(?:m|c)?js$/, '');
  const candidates = [
    normalized,
    ...EXTENSIONS.map((ext) => normalized + ext),
    ...EXTENSIONS.map((ext) => withoutJs + ext),
    ...EXTENSIONS.map((ext) => `${normalized}/index${ext}`),
  ];
  return candidates.find((candidate) => files.has(candidate));
}

/** Resolves a relative or tsconfig-alias import to a project file; packages from node_modules resolve to undefined. */
export function resolveImport(ctx: ScanContext, fromFile: string, specifier: string): string | undefined {
  if (specifier.startsWith('.')) return existing(ctx, posix.join(posix.dirname(fromFile), specifier));
  const { baseUrl, paths } = pathAliases(ctx);
  for (const [pattern, targets] of paths) {
    const star = pattern.indexOf('*');
    const prefix = star === -1 ? pattern : pattern.slice(0, star);
    const suffix = star === -1 ? '' : pattern.slice(star + 1);
    const matches = star === -1 ? specifier === pattern : specifier.startsWith(prefix) && specifier.endsWith(suffix) && specifier.length >= prefix.length + suffix.length;
    if (!matches) continue;
    const captured = star === -1 ? '' : specifier.slice(prefix.length, specifier.length - suffix.length);
    for (const target of targets) {
      const resolved = existing(ctx, posix.join(baseUrl, target.replace('*', captured)));
      if (resolved) return resolved;
    }
  }
  return undefined;
}

/** Import specifiers that end up in the bundle: static imports and re-exports (not `import type`), dynamic import() and require(). */
export function importSpecifiers(ctx: ScanContext, file: string): string[] {
  const sourceFile = ctx.getSourceFile(file);
  const specifiers: string[] = [];
  for (const declaration of sourceFile.getImportDeclarations()) {
    if (!declaration.isTypeOnly()) specifiers.push(declaration.getModuleSpecifierValue());
  }
  for (const declaration of sourceFile.getExportDeclarations()) {
    const value = declaration.getModuleSpecifierValue();
    if (value && !declaration.isTypeOnly()) specifiers.push(value);
  }
  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const callee = call.getExpression();
    const isDynamicImport = callee.getKind() === SyntaxKind.ImportKeyword;
    const isRequire = Node.isIdentifier(callee) && callee.getText() === 'require';
    const target = isDynamicImport || isRequire ? stringLiteral(call.getArguments()[0]) : undefined;
    if (target) specifiers.push(target);
  }
  return specifiers;
}

const reachableCache = new WeakMap<ScanContext, Map<string, string[]>>();

/**
 * Every project module that ships to the browser: 'use client' files and everything they import
 * (relative and tsconfig-alias imports only). Each module maps to the import chain from its client entry.
 */
export function clientReachableModules(ctx: ScanContext): Map<string, string[]> {
  let reachable = reachableCache.get(ctx);
  if (!reachable) {
    reachable = new Map();
    const queue: string[] = [];
    for (const file of sourceFiles(ctx, (text) => text.includes('use client'))) {
      if (ctx.next.isClientFile(file) && !reachable.has(file)) {
        reachable.set(file, [file]);
        queue.push(file);
      }
    }
    while (queue.length) {
      const file = queue.shift()!;
      for (const specifier of importSpecifiers(ctx, file)) {
        const target = resolveImport(ctx, file, specifier);
        if (!target || reachable.has(target)) continue;
        reachable.set(target, [...reachable.get(file)!, target]);
        queue.push(target);
      }
    }
    reachableCache.set(ctx, reachable);
  }
  return reachable;
}
