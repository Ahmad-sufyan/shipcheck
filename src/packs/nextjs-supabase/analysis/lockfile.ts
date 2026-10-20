import { parseJsonc } from '../../../context/configs.js';
import type { ScanContext } from '../../../types.js';
import { dependencyNames } from '../../../stacks/detect.js';

export interface LockedPackage {
  name: string;
  version: string;
  /** Only installed for development (npm `dev: true`, pnpm devDependencies). */
  dev: boolean;
  /** Listed in the root package.json. */
  direct: boolean;
  hasInstallScript: boolean;
  file: string;
  line: number;
}

/** Semver-ish comparison: numeric major.minor.patch, then a release sorts after its prereleases. */
export function compareVersions(a: string, b: string): number {
  const split = (v: string) => {
    const [core = '', pre] = v.replace(/^v/, '').split('-', 2);
    return { nums: core.split('.').map((n) => Number.parseInt(n, 10) || 0), pre };
  };
  const x = split(a);
  const y = split(b);
  for (let i = 0; i < 3; i++) {
    const diff = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (diff) return diff;
  }
  if (x.pre === y.pre) return 0;
  if (x.pre === undefined) return 1;
  if (y.pre === undefined) return -1;
  return x.pre < y.pre ? -1 : 1;
}

function lineIndex(text: string): (needle: string, from?: number) => number {
  const lines = text.split(/\r?\n/);
  return (needle, from = 0) => {
    const index = lines.findIndex((line, i) => i >= from && line.includes(needle));
    return index === -1 ? 0 : index + 1;
  };
}

function devDependencyNames(ctx: ScanContext): Set<string> {
  const dev = ctx.packageJson?.data.devDependencies;
  return new Set(dev && typeof dev === 'object' ? Object.keys(dev) : []);
}

function npmLock(ctx: ScanContext, file: string, direct: Set<string>): LockedPackage[] {
  const text = ctx.readText(file);
  const find = lineIndex(text);
  let data: { packages?: Record<string, { version?: string; dev?: boolean; hasInstallScript?: boolean }>; dependencies?: Record<string, { version?: string; dev?: boolean }> };
  try {
    data = JSON.parse(text) as typeof data;
  } catch {
    return [];
  }
  if (data.packages) {
    return Object.entries(data.packages)
      .filter(([key, entry]) => key.includes('node_modules/') && typeof entry.version === 'string')
      .map(([key, entry]) => {
        const name = key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
        const topLevel = key === `node_modules/${name}`;
        return {
          name,
          version: entry.version!,
          dev: entry.dev === true,
          direct: topLevel && direct.has(name),
          hasInstallScript: entry.hasInstallScript === true,
          file,
          line: find(JSON.stringify(key)),
        };
      });
  }
  return Object.entries(data.dependencies ?? {})
    .filter(([, entry]) => typeof entry.version === 'string')
    .map(([name, entry]) => ({ name, version: entry.version!, dev: entry.dev === true, direct: direct.has(name), hasInstallScript: false, file, line: find(JSON.stringify(name)) }));
}

/** pnpm-lock.yaml v6/v9, read line by line (no YAML dependency): package keys under `packages:` plus devDependencies of the root importer. */
function pnpmLock(ctx: ScanContext, file: string, direct: Set<string>): LockedPackage[] {
  const lines = ctx.readText(file).split(/\r?\n/);
  const devNames = devDependencyNames(ctx);
  const prod = ctx.packageJson?.data.dependencies;
  const prodNames = new Set(prod && typeof prod === 'object' ? Object.keys(prod) : []);
  const packages: LockedPackage[] = [];
  let section = '';
  lines.forEach((line, index) => {
    if (/^\S/.test(line)) section = line.replace(/:.*$/, '');
    if (section !== 'packages') return;
    const match = /^ {2}['"]?\/?((?:@[^/\s'"]+\/)?[^@\s'"/]+)@([^:('"\s]+)/.exec(line);
    if (!match) return;
    const [, name, version] = match as unknown as [string, string, string];
    packages.push({ name, version, dev: devNames.has(name) && !prodNames.has(name), direct: direct.has(name), hasInstallScript: false, file, line: index + 1 });
  });
  return packages;
}

/** yarn.lock v1 and berry: `"name@range":` headers followed by a version line. */
function yarnLock(ctx: ScanContext, file: string, direct: Set<string>): LockedPackage[] {
  const lines = ctx.readText(file).split(/\r?\n/);
  const devNames = devDependencyNames(ctx);
  const packages: LockedPackage[] = [];
  let current: string | undefined;
  lines.forEach((line, index) => {
    const header = /^"?((?:@[^/@\s"]+\/)?[^@\s"]+)@[^\s]*?:$/.exec(line.split(',')[0]!.replace(/:?$/, ':'));
    if (/^\S/.test(line) && header) current = header[1];
    const version = /^\s+version:?\s+"?([^"\s]+)"?/.exec(line);
    if (current && version) {
      packages.push({ name: current, version: version[1]!, dev: devNames.has(current), direct: direct.has(current), hasInstallScript: false, file, line: index + 1 });
      current = undefined;
    }
  });
  return packages;
}

/** bun.lock (JSONC): packages: { name: ["name@version", ...] }. */
function bunLock(ctx: ScanContext, file: string, direct: Set<string>): LockedPackage[] {
  if (file.endsWith('.lockb')) return [];
  const text = ctx.readText(file);
  const find = lineIndex(text);
  const devNames = devDependencyNames(ctx);
  try {
    const data = parseJsonc(text) as { packages?: Record<string, unknown[]> };
    return Object.values(data.packages ?? {}).flatMap((entry) => {
      const spec = typeof entry[0] === 'string' ? entry[0] : '';
      const at = spec.lastIndexOf('@');
      if (at <= 0) return [];
      const name = spec.slice(0, at);
      return [{ name, version: spec.slice(at + 1), dev: devNames.has(name), direct: direct.has(name), hasInstallScript: false, file, line: find(JSON.stringify(spec)) }];
    });
  } catch {
    return [];
  }
}

const cache = new WeakMap<ScanContext, LockedPackage[]>();

/** Packages pinned by the project's lockfile (npm, pnpm, yarn or bun), in lockfile order. */
export function lockedPackages(ctx: ScanContext): LockedPackage[] {
  let packages = cache.get(ctx);
  if (!packages) {
    const lock = ctx.lockfile;
    const direct = dependencyNames(ctx.packageJson);
    if (!lock) packages = [];
    else if (lock.kind === 'npm') packages = npmLock(ctx, lock.file, direct);
    else if (lock.kind === 'pnpm') packages = pnpmLock(ctx, lock.file, direct);
    else if (lock.kind === 'yarn') packages = yarnLock(ctx, lock.file, direct);
    else packages = bunLock(ctx, lock.file, direct);
    cache.set(ctx, packages);
  }
  return packages;
}
