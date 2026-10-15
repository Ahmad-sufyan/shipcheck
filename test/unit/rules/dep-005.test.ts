import { describe, expect, it } from 'vitest';
import MIN_SECURE from '../../../src/packs/nextjs-supabase/data/min-secure-versions.json' with { type: 'json' };
import { dep005 as rule } from '../../../src/packs/nextjs-supabase/rules/dep-005-framework-below-fix.js';
import { npmLockfile, packageJson } from '../../helpers/lockfiles.js';
import { lineOf, runRule } from '../../helpers/memory-context.js';

const project = (version: string) => ({ 'package.json': packageJson({ next: version }), 'package-lock.json': npmLockfile({ 'node_modules/next': { version } }) });

describe('DEP-005 Framework below its security fix', () => {
  it('reports a locked version below the minimum for its major, citing the advisory', async () => {
    const files = project('15.1.0');
    expect(await runRule(rule, files)).toEqual([
      {
        file: 'package-lock.json',
        line: lineOf(files['package-lock.json'], '"node_modules/next"'),
        evidence: 'next@15.1.0 is below 15.5.24',
        explanation: expect.stringMatching(/GHSA-2xp9-vwfh-vxw4.*https:\/\/github\.com\/advisories\/GHSA-2xp9-vwfh-vxw4.*checked on 2026-10-15/s),
        fix: 'Upgrade next to 15.5.24 or later.',
      },
    ]);
  });

  it('points old majors without an in-line fix at the next fixed release', async () => {
    expect(await runRule(rule, project('12.3.4'))).toEqual([expect.objectContaining({ evidence: 'next@12.3.4 is below 15.5.24' })]);
  });

  it('accepts versions at or above the minimum', async () => {
    expect(await runRule(rule, project('16.4.1'))).toEqual([]);
    expect(await runRule(rule, project('16.3.8'))).toEqual([]);
    expect(await runRule(rule, project('16.3.7'))).toHaveLength(1);
  });

  it('ignores packages and majors the data does not cover, and projects without a lockfile', async () => {
    expect(await runRule(rule, project('11.1.0'))).toEqual([]);
    expect(await runRule(rule, { 'package.json': packageJson({ next: '15.1.0' }) })).toEqual([]);
  });

  it('ships data with a source and check date for every entry', () => {
    for (const entry of MIN_SECURE) {
      expect(entry).toEqual(expect.objectContaining({ package: expect.any(String), major: expect.any(Number), minVersion: expect.stringMatching(/^\d+\.\d+\.\d+$/), advisory: expect.any(String) }));
      expect(entry.source).toMatch(/^https:\/\//);
      expect(entry.checkedOn).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });
});
