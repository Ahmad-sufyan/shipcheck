import { readFileSync, statSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import fg from 'fast-glob';
import { ShipcheckError } from '../core/errors.js';

/** Never scanned: dependencies, VCS metadata and build output. */
export const DEFAULT_IGNORES: readonly string[] = [
  '**/node_modules/**',
  '**/.git/**',
  '**/.next/**',
  '**/.turbo/**',
  '**/.vercel/output/**',
  '**/.wrangler/**',
  '**/.open-next/**',
  '**/dist/**',
  '**/build/**',
  '**/out/**',
  '**/coverage/**',
];

/** Read access to the scanned project. Paths are repo-relative with forward slashes. */
export interface ProjectSource {
  root: string;
  /** Files to scan, after ignores, sorted. */
  files: readonly string[];
  /** Whether `file` is in {@link files}. */
  has(file: string): boolean;
  readText(file: string): string;
  /** Whether a directory exists, regardless of ignores (used for stack detection). */
  isDirectory(dir: string): boolean;
  /** Whether a file exists, regardless of ignores (used for stack detection). */
  isFile(file: string): boolean;
}

/** Plain code-unit order, identical on every platform and locale. */
export function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

const fileSets = new WeakMap<readonly string[], ReadonlySet<string>>();

/** A cached Set view of a file list, for O(1) membership checks. */
export function fileSetOf(files: readonly string[]): ReadonlySet<string> {
  let set = fileSets.get(files);
  if (!set) {
    set = new Set(files);
    fileSets.set(files, set);
  }
  return set;
}

/** The 1-based line `line` of `text`, or '' when out of range. */
export function lineAt(text: string, line: number): string {
  return text.split(/\r?\n/)[line - 1] ?? '';
}

export async function listFiles(root: string, ignorePaths: readonly string[]): Promise<string[]> {
  const ignore = [...DEFAULT_IGNORES, ...ignorePaths.map((p) => (p.endsWith('/') ? `${p}**` : p))];
  const files = await fg('**/*', {
    cwd: root,
    dot: true,
    onlyFiles: true,
    followSymbolicLinks: false,
    suppressErrors: true,
    ignore,
  });
  return files.sort(compareStrings);
}

export function createDiskSource(root: string, files: readonly string[]): ProjectSource {
  const absRoot = resolve(root);
  const cache = new Map<string, string>();
  const fileSet = new Set(files);

  const toAbs = (file: string): string => {
    const abs = resolve(absRoot, file);
    const rel = relative(absRoot, abs);
    if (isAbsolute(file) || rel.startsWith('..') || isAbsolute(rel)) {
      throw new ShipcheckError(`Refusing to read ${file}: outside the scan root`);
    }
    return abs;
  };
  const stat = (p: string) => statSync(join(absRoot, p), { throwIfNoEntry: false });

  return {
    root,
    files,
    has: (file) => fileSet.has(file),
    readText(file) {
      let text = cache.get(file);
      if (text === undefined) {
        text = stripBom(readFileSync(toAbs(file), 'utf8'));
        cache.set(file, text);
      }
      return text;
    },
    isDirectory: (dir) => stat(dir)?.isDirectory() ?? false,
    isFile: (file) => stat(file)?.isFile() ?? false,
  };
}

/** A source backed by a plain object; used by tests and by callers that already hold file contents. */
export function createMemorySource(contents: Record<string, string>, root = '/virtual'): ProjectSource {
  const files = Object.keys(contents).sort(compareStrings);
  const fileSet = new Set(files);
  return {
    root,
    files,
    has: (file) => fileSet.has(file),
    readText(file) {
      const text = contents[file];
      if (text === undefined) throw new Error(`File not found in memory source: ${file}`);
      return stripBom(text);
    },
    isDirectory: (dir) => {
      const prefix = dir.replace(/\/+$/, '') + '/';
      return files.some((f) => f.startsWith(prefix));
    },
    isFile: (file) => fileSet.has(file),
  };
}
