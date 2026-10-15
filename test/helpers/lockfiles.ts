/** A package.json with the given dependencies (and any extra top-level fields). */
export function packageJson(dependencies: Record<string, string>, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ name: 'app', version: '1.0.0', private: true, ...extra, dependencies }, null, 2);
}

export interface LockedSpec {
  version: string;
  dev?: boolean;
  hasInstallScript?: boolean;
}

/** A package-lock.json v3 pinning `packages` (keys are install paths, e.g. `node_modules/next`). */
export function npmLockfile(packages: Record<string, LockedSpec>): string {
  const entries = Object.fromEntries(Object.entries(packages).map(([path, spec]) => [path, { ...spec, license: 'MIT' }]));
  return JSON.stringify({ name: 'app', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'app', version: '1.0.0' }, ...entries } }, null, 2);
}
