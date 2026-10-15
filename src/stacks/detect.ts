import type { ProjectSource } from '../context/files.js';
import { STACK_IDS } from '../schema.js';
import type { ScanContext, StackId } from '../types.js';

const DEPENDENCY_FIELDS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'] as const;

export function dependencyNames(packageJson: ScanContext['packageJson']): Set<string> {
  const names = new Set<string>();
  for (const field of DEPENDENCY_FIELDS) {
    const deps = packageJson?.data[field];
    if (deps && typeof deps === 'object') for (const name of Object.keys(deps)) names.add(name);
  }
  return names;
}

/** Detected stacks, in the fixed order of STACK_IDS. */
export function detectStacks(source: ProjectSource, packageJson: ScanContext['packageJson']): Set<StackId> {
  const deps = dependencyNames(packageJson);
  const found = new Set<StackId>();
  if (deps.has('next') && (source.isDirectory('app') || source.isDirectory('src/app'))) found.add('nextjs-app-router');
  if (deps.has('@supabase/supabase-js') || deps.has('@supabase/ssr') || source.isDirectory('supabase')) found.add('supabase');
  if (source.isFile('vercel.json') || source.isDirectory('.vercel')) found.add('vercel');
  if (['wrangler.toml', 'wrangler.json', 'wrangler.jsonc'].some((f) => source.isFile(f))) found.add('cloudflare');
  return new Set(STACK_IDS.filter((id) => found.has(id)));
}
