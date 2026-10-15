import { describe, expect, it } from 'vitest';
import { dep002 as rule } from '../../../src/packs/nextjs-supabase/rules/dep-002-lockfile.js';
import { fakeExec, toolContext } from '../../helpers/fake-exec.js';
import { npmLockfile, packageJson } from '../../helpers/lockfiles.js';
import { runRule } from '../../helpers/memory-context.js';

const PKG = packageJson({ next: '^16.4.1' });
const LOCK = npmLockfile({ 'node_modules/next': { version: '16.4.1' } });

const git = (tracked: string[], ignored: string[] = []) =>
  toolContext(
    fakeExec((command, args) => {
      if (command !== 'git') return 'missing';
      if (args[0] === 'rev-parse') return { stdout: '\n' };
      if (args[0] === 'ls-files') return { stdout: args.slice(3).filter((f) => tracked.includes(f)).map((f) => `${f}\0`).join('') };
      const hits = args.slice(2).filter((f) => ignored.includes(f));
      return { exitCode: hits.length ? 0 : 1, stdout: hits.map((f) => `${f}\n`).join('') };
    }).exec,
  );

describe('DEP-002 Missing or uncommitted lockfile', () => {
  it('reports dependencies without a lockfile at the dependencies key', async () => {
    expect(await runRule(rule, { 'package.json': PKG })).toEqual([
      { file: 'package.json', line: 5, evidence: 'package.json declares dependencies but there is no lockfile' },
    ]);
  });

  it('lowers confidence for publishable libraries', async () => {
    const library = JSON.stringify({ name: 'lib', version: '1.0.0', exports: './index.js', dependencies: { zod: '^4.0.0' } }, null, 2);
    expect(await runRule(rule, { 'package.json': library })).toEqual([expect.objectContaining({ confidence: 'low' })]);
  });

  it('reports a lockfile that git ignores', async () => {
    expect(await runRule(rule, { 'package.json': PKG, 'package-lock.json': LOCK }, {}, { tools: git([], ['package-lock.json']) })).toEqual([
      { file: 'package-lock.json', line: 1, evidence: 'package-lock.json is ignored by git' },
    ]);
  });

  it('reports a lockfile that is not committed yet with medium confidence', async () => {
    expect(await runRule(rule, { 'package.json': PKG, 'package-lock.json': LOCK }, {}, { tools: git([]) })).toEqual([
      { file: 'package-lock.json', line: 1, evidence: 'package-lock.json is not committed', confidence: 'medium' },
    ]);
  });

  it('falls back to the root .gitignore outside a repository', async () => {
    expect(await runRule(rule, { 'package.json': PKG, 'package-lock.json': LOCK, '.gitignore': 'node_modules\npackage-lock.json\n' })).toEqual([
      { file: 'package-lock.json', line: 1, evidence: 'package-lock.json is listed in .gitignore' },
    ]);
  });

  it('is quiet for a committed lockfile or a project without dependencies', async () => {
    expect(await runRule(rule, { 'package.json': PKG, 'package-lock.json': LOCK }, {}, { tools: git(['package-lock.json']) })).toEqual([]);
    expect(await runRule(rule, { 'package.json': PKG, 'package-lock.json': LOCK })).toEqual([]);
    expect(await runRule(rule, { 'package.json': JSON.stringify({ name: 'x', scripts: { build: 'tsc' } }) })).toEqual([]);
  });
});
