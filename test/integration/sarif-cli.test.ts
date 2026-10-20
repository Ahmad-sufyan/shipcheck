import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { defaultRegistry } from '../../src/packs/index.js';
import { shipcheck } from '../helpers/cli.js';
import { tmpProject } from '../helpers/context.js';
import { sarifErrors } from '../helpers/sarif.js';

describe('--format sarif', () => {
  it('writes valid SARIF 2.1.0 for fixtures/demo-app with repository-relative locations', { timeout: 120_000 }, async () => {
    const out = join(tmpProject({}), 'out.sarif');
    const sarifRun = await shipcheck(['scan', 'fixtures/demo-app', '--offline', '--format', 'sarif', '--out', out]);
    expect(sarifRun.exitCode).toBe(1);
    const sarif = JSON.parse(readFileSync(out, 'utf8')) as { runs: { tool: { driver: { rules: { id: string }[] } }; results: { ruleId: string; locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[] }[] };
    expect(sarifErrors(sarif)).toEqual([]);

    const json = JSON.parse((await shipcheck(['scan', 'fixtures/demo-app', '--offline', '--format', 'json'])).stdout) as { findings: { ruleId: string }[] };
    const [run] = sarif.runs;
    expect(run!.results.map((r) => r.ruleId)).toEqual(json.findings.map((f) => f.ruleId));
    expect(run!.results.every((r) => r.locations[0]!.physicalLocation.artifactLocation.uri.startsWith('fixtures/demo-app/'))).toBe(true);
    expect(run!.tool.driver.rules.map((r) => r.id)).toEqual(defaultRegistry().all().map((r) => r.id).sort());
  });

  it('is offered by scan and live', async () => {
    expect((await shipcheck(['scan', '--help'])).stdout).toMatch(/"md",\s+"sarif"/);
    expect((await shipcheck(['live', '--help'])).stdout).toMatch(/"md",\s+"sarif"/);
  });
});
