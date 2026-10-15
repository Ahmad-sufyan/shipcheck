import { TOOL_TIMEOUT_MS, type ToolContext } from './exec.js';

export interface GitRepo {
  /** The scan root's path inside the repository: '' at the top level, otherwise ending in '/'. */
  prefix: string;
}

const repos = new WeakMap<ToolContext, Map<string, Promise<GitRepo | null>>>();

async function lookupRepo(root: string, tools: ToolContext): Promise<GitRepo | null> {
  const result = await tools.exec('git', ['rev-parse', '--show-prefix'], { cwd: root, timeoutMs: TOOL_TIMEOUT_MS });
  if (result.missing || result.exitCode !== 0) return null;
  return { prefix: result.stdout.trim() };
}

/** The work tree containing `root`, or null when git is not installed or `root` is not inside a repository. Cached per scan. */
export function gitRepo(root: string, tools: ToolContext): Promise<GitRepo | null> {
  let byRoot = repos.get(tools);
  if (!byRoot) repos.set(tools, (byRoot = new Map()));
  let repo = byRoot.get(root);
  if (!repo) byRoot.set(root, (repo = lookupRepo(root, tools)));
  return repo;
}

function nulSeparated(stdout: string): Set<string> {
  return new Set(stdout.split('\0').filter(Boolean));
}

/** Which of `paths` (relative to `root`) git tracks, or null when git cannot tell. */
export async function gitTracked(root: string, tools: ToolContext, paths: readonly string[]): Promise<Set<string> | null> {
  if (!paths.length) return new Set();
  const result = await tools.exec('git', ['ls-files', '-z', '--', ...paths], { cwd: root, timeoutMs: TOOL_TIMEOUT_MS });
  return result.missing || result.exitCode !== 0 ? null : nulSeparated(result.stdout);
}

/**
 * Which untracked `paths` git ignores (any .gitignore, .git/info/exclude or core.excludesFile), or null
 * when git cannot tell. git check-ignore exits 1 when none of the paths is ignored.
 */
export async function gitIgnored(root: string, tools: ToolContext, paths: readonly string[]): Promise<Set<string> | null> {
  if (!paths.length) return new Set();
  const result = await tools.exec('git', ['check-ignore', '-z', '--', ...paths], { cwd: root, timeoutMs: TOOL_TIMEOUT_MS });
  return result.missing || (result.exitCode !== 0 && result.exitCode !== 1) ? null : nulSeparated(result.stdout);
}
