import { describe, expect, it } from 'vitest';
import { secret006SourceMaps as rule } from '../../../../../src/packs/nextjs-supabase/rules/secret-006-source-maps.js';
import { memoryContext } from '../../../../helpers/context.js';

async function run(files: Record<string, string>) {
  return await rule.run(memoryContext(files));
}

describe('SECRET-006 Production browser source maps enabled', () => {
  it('has the documented metadata', async () => {
    expect(rule).toMatchObject({
      id: 'SECRET-006',
      title: 'Production browser source maps enabled',
      category: 'secrets',
      severity: 'medium',
      confidence: 'high',
      stacks: ['nextjs-app-router'],
      cwe: 'CWE-540',
    });
    expect(rule.falsePositiveNote).toMatch(/open-source/i);
  });

  it('reports productionBrowserSourceMaps: true at the property line', async () => {
    expect(await run({ 'next.config.mjs': 'const nextConfig = {\n  poweredByHeader: false,\n  productionBrowserSourceMaps: true,\n}\nexport default nextConfig\n' })).toEqual([
      { file: 'next.config.mjs', line: 3, evidence: 'productionBrowserSourceMaps: true,' },
    ]);
  });

  it('reports a dynamic value with low confidence', async () => {
    expect(await run({ 'next.config.ts': "export default {\n  productionBrowserSourceMaps: process.env.MAPS === 'on',\n}\n" })).toEqual([
      { file: 'next.config.ts', line: 2, evidence: "productionBrowserSourceMaps: process.env.MAPS === 'on',", confidence: 'low' },
    ]);
  });

  it('ignores false or absent values', async () => {
    expect(await run({ 'next.config.mjs': 'export default { productionBrowserSourceMaps: false }' })).toEqual([]);
    expect(await run({ 'next.config.mjs': 'export default {}' })).toEqual([]);
    expect(await run({ 'app/page.tsx': '' })).toEqual([]);
  });
});
