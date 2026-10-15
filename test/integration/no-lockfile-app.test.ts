import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { scan } from '../../src/core/scan.js';
import { gitOnlyExec } from '../helpers/fake-exec.js';

const APP = fileURLToPath(new URL('../../fixtures/no-lockfile-app', import.meta.url));

describe('fixtures/no-lockfile-app', () => {
  it('reports only DEP-002', async () => {
    const result = await scan(APP, { offline: true, exec: gitOnlyExec });
    expect(result.ruleErrors).toEqual([]);
    expect(result.findings.map((f) => `${f.ruleId} ${f.file}:${f.line}`)).toEqual(['DEP-002 package.json:6']);
  });
});
