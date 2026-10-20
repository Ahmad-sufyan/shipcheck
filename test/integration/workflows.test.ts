import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { findExecutable } from '../../src/adapters/exec.js';
import { execa } from 'execa';
import { REPO_ROOT } from '../helpers/cli.js';

const FILES = ['action.yml', '.github/workflows/ci.yml', '.github/workflows/shipcheck.yml', 'examples/github/shipcheck.yml'];
const read = (file: string) => readFileSync(new URL(`../../${file}`, import.meta.url), 'utf8');

describe('GitHub Action and workflows', () => {
  it('pin every third-party action to a full commit SHA', () => {
    for (const file of FILES) {
      for (const [, ref] of read(file).matchAll(/^\s*(?:-\s+)?uses:\s*([^\s#]+)/gm)) {
        if (ref === './' || ref!.startsWith('Ahmad-sufyan/shipcheck@')) continue;
        expect(ref, `${file}: ${ref}`).toMatch(/@[0-9a-f]{40}$/);
      }
    }
  });

  it('declare the inputs the composite action promises', () => {
    const action = read('action.yml');
    for (const input of ['path', 'mode', 'fail-on', 'baseline', 'live-url', 'version', 'upload-sarif']) expect(action).toMatch(new RegExp(`^  ${input}:$`, 'm'));
    expect(action).toContain('using: composite');
    expect(action).toMatch(/sha256sum --check --strict/);
  });

  it('keep workflow permissions minimal', () => {
    expect(read('.github/workflows/ci.yml')).toMatch(/permissions:\n {2}contents: read\n/);
    expect(read('.github/workflows/shipcheck.yml')).toMatch(/permissions:\n {2}contents: read\n {2}security-events: write\n/);
    expect(read('examples/github/shipcheck.yml')).toMatch(/^permissions: \{\}$/m);
  });

  const actionlint = findExecutable('actionlint');
  it.skipIf(!actionlint)(`pass actionlint${actionlint ? '' : ' (skipped: actionlint is not installed)'}`, async () => {
    const { exitCode, stdout } = await execa(actionlint!, FILES.filter((f) => f !== 'action.yml'), { cwd: REPO_ROOT, reject: false });
    expect(stdout).toBe('');
    expect(exitCode).toBe(0);
  });
});
