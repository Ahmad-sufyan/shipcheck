import { execFileSync } from 'node:child_process';
import { rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { findExecutable } from '../../src/adapters/exec.js';
import { scan } from '../../src/core/scan.js';
import { tmpProject } from '../helpers/context.js';
import { FAKE } from '../helpers/fake-secrets.js';

const gitleaks = findExecutable('gitleaks');
const title = gitleaks ? 'a secret committed and then deleted' : 'a secret committed and then deleted (skipped: gitleaks is not installed)';

describe.skipIf(!gitleaks)('SECRET-003 against a real repository', () => {
  it(title, async () => {
    const root = tmpProject({ 'package.json': '{"name":"history-test","private":true}', 'config.ts': `export const stripeKey = '${FAKE.stripe}'\n` });
    const git = (...args: string[]) => execFileSync('git', ['-c', 'user.name=shipcheck', '-c', 'user.email=shipcheck@example.com', '-c', 'commit.gpgsign=false', ...args], { cwd: root, stdio: 'pipe' });
    git('init', '-q');
    git('add', '.');
    git('commit', '-q', '-m', 'add config');
    rmSync(join(root, 'config.ts'));
    writeFileSync(join(root, 'README.txt'), 'keys now come from the environment\n');
    git('add', '-A');
    git('commit', '-q', '-m', 'remove hardcoded key');

    const result = await scan(root, { offline: true });
    expect(result.ruleErrors).toEqual([]);
    expect(result.findings.filter((f) => f.ruleId === 'SECRET-003').map((f) => f.evidence)).toEqual([expect.stringMatching(/^stripe-access-token in config\.ts:1, commit [0-9a-f]{7}/)]);
    expect(result.findings.filter((f) => f.ruleId === 'SECRET-004')).toEqual([]);
    expect(JSON.stringify(result)).not.toContain(FAKE.stripe.slice(0, 5));
  });
});
