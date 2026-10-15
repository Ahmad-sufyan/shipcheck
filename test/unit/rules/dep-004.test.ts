import { describe, expect, it } from 'vitest';
import { dep004 as rule, editDistance } from '../../../src/packs/nextjs-supabase/rules/dep-004-typosquat.js';
import { packageJson } from '../../helpers/lockfiles.js';
import { lineOf, runRule } from '../../helpers/memory-context.js';

describe('DEP-004 Typosquat-like dependency', () => {
  it('reports a direct dependency one edit away from a popular package', async () => {
    const pkg = packageJson({ next: '16.4.1', lodahs: '^4.17.21' });
    expect(await runRule(rule, { 'package.json': pkg })).toEqual([
      { file: 'package.json', line: lineOf(pkg, '"lodahs"'), evidence: '"lodahs": "^4.17.21"', explanation: expect.stringContaining('"lodash"') },
    ]);
  });

  it.each(['raect', 'expres', 'axois', '@supabase/supabse-js', 'nextt'])('reports %s', async (name) => {
    expect(await runRule(rule, { 'package.json': packageJson({}, { devDependencies: { [name]: '1.0.0' } }) })).toHaveLength(1);
  });

  it('ignores popular packages, short names and unrelated names', async () => {
    const pkg = packageJson({ react: '19.0.0', preact: '10.0.0', 'react-dom': '19.0.0', zod: '4.0.0', pg: '8.0.0', 'my-company-ui': '1.0.0' });
    expect(await runRule(rule, { 'package.json': pkg })).toEqual([]);
  });

  it('counts adjacent transpositions as one edit', () => {
    expect(editDistance('lodash', 'lodahs')).toBe(1);
    expect(editDistance('react', 'preact')).toBe(1);
    expect(editDistance('vite', 'vitest')).toBe(2);
  });
});
