import { gitIgnored, gitRepo, gitTracked } from '../../../adapters/git.js';
import type { ScanContext } from '../../../types.js';

export interface FileGitStatus {
  /** Undefined when git could not be asked (not installed, not a repository); then only the root .gitignore was checked. */
  tracked?: boolean;
  ignored: boolean;
}

interface IgnoreRule {
  regex: RegExp;
  negate: boolean;
}

function escapeRegex(char: string): string {
  return /[.+^${}()|[\]\\]/.test(char) ? `\\${char}` : char;
}

/** A .gitignore line as a regex over repo-relative paths (a match also covers everything inside a matched directory). */
function ignoreRule(line: string): IgnoreRule {
  let pattern = line;
  const negate = pattern.startsWith('!');
  if (negate) pattern = pattern.slice(1);
  if (pattern.startsWith('\\')) pattern = pattern.slice(1);
  const dirOnly = pattern.endsWith('/');
  if (dirOnly) pattern = pattern.slice(0, -1);
  // A slash at the start or in the middle anchors the pattern to the .gitignore's directory.
  const anchored = pattern.includes('/');
  pattern = pattern.replace(/^\//, '');

  let body = '';
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i]!;
    if (char === '*' && pattern[i + 1] === '*') {
      if (pattern[i + 2] === '/') {
        body += '(?:.*/)?';
        i += 2;
      } else {
        body += '.*';
        i += 1;
      }
    } else if (char === '*') body += '[^/]*';
    else if (char === '?') body += '[^/]';
    else body += escapeRegex(char);
  }
  return { regex: new RegExp(`${anchored ? '^' : '^(?:.*/)?'}${body}${dirOnly ? '/.*' : '(?:/.*)?'}$`), negate };
}

/** Whether `file` is ignored by these root .gitignore lines; the last matching line wins, as in git. */
export function isGitignored(patterns: readonly string[], file: string): boolean {
  let ignored = false;
  for (const line of patterns) {
    const rule = ignoreRule(line);
    if (rule.regex.test(file)) ignored = !rule.negate;
  }
  return ignored;
}

/**
 * Whether each file is tracked and whether it is ignored. Asks git when it is available (every
 * .gitignore, .git/info/exclude and the global excludes file count); otherwise falls back to the
 * project's root .gitignore.
 */
export async function gitStatus(ctx: ScanContext, files: readonly string[]): Promise<Map<string, FileGitStatus>> {
  const statuses = new Map<string, FileGitStatus>();
  if (ctx.tools && files.length && (await gitRepo(ctx.root, ctx.tools))) {
    const tracked = await gitTracked(ctx.root, ctx.tools, files);
    const ignored = tracked && (await gitIgnored(ctx.root, ctx.tools, files.filter((f) => !tracked.has(f))));
    if (tracked && ignored) {
      for (const file of files) statuses.set(file, { tracked: tracked.has(file), ignored: ignored.has(file) });
      return statuses;
    }
  }
  const patterns = ctx.gitignore?.patterns ?? [];
  for (const file of files) statuses.set(file, { ignored: isGitignored(patterns, file) });
  return statuses;
}
