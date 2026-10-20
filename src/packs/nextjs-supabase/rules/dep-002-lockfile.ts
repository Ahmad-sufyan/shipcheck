import type { RawFinding, Rule } from '../../../types.js';
import { dependencyNames } from '../../../stacks/detect.js';
import { gitStatus } from '../analysis/git-status.js';

function lineOf(text: string, needle: string): number {
  const index = text.split(/\r?\n/).findIndex((line) => line.includes(needle));
  return index === -1 ? 1 : index + 1;
}

export const dep002: Rule = {
  id: 'DEP-002',
  title: 'Missing or uncommitted lockfile',
  category: 'dependencies',
  severity: 'high',
  confidence: 'high',
  stacks: [],
  description:
    'Reports a package.json with dependencies but no lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock), ' +
    'and a lockfile that git ignores (or, outside a repository, that the root .gitignore lists). A lockfile that exists but ' +
    'is not committed yet is reported with medium confidence. Packages meant for publishing (no "private": true, with ' +
    '"main" or "exports") get low confidence.',
  explanation:
    'Without a committed lockfile, every install resolves version ranges again, so builds can silently pull a new (or ' +
    'compromised) release of any dependency, and vulnerability checks run against versions you are not deploying.',
  fix: 'Commit the lockfile and install with `npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable` or `bun install --frozen-lockfile` in CI and deploys.',
  falsePositiveNote: 'Libraries published to npm often leave lockfiles out on purpose; apps should always commit one.',
  cwe: 'CWE-1357',
  references: ['https://docs.npmjs.com/cli/configuring-npm/package-lock-json', 'https://pnpm.io/cli/install#--frozen-lockfile'],
  async run(ctx) {
    const pkg = ctx.packageJson;
    if (!pkg || dependencyNames(pkg).size === 0) return [];
    if (!ctx.lockfile) {
      const finding: RawFinding = { file: pkg.file, line: lineOf(ctx.readText(pkg.file), '"dependencies"'), evidence: `${pkg.file} declares dependencies but there is no lockfile` };
      const { private: isPrivate, main, exports } = pkg.data;
      return [isPrivate !== true && (main !== undefined || exports !== undefined) ? { ...finding, confidence: 'low' } : finding];
    }
    const { file } = ctx.lockfile;
    const status = (await gitStatus(ctx, [file])).get(file);
    if (!status) return [];
    if (status.tracked === true) return [];
    if (status.ignored) return [{ file, line: 1, evidence: `${file} is ${status.tracked === undefined ? 'listed in .gitignore' : 'ignored by git'}` }];
    if (status.tracked === false) return [{ file, line: 1, evidence: `${file} is not committed`, confidence: 'medium' }];
    return [];
  },
};
