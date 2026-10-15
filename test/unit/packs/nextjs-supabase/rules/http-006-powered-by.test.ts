import { describe, expect, it } from 'vitest';
import { http006PoweredBy as rule } from '../../../../../src/packs/nextjs-supabase/rules/http-006-powered-by.js';
import { memoryContext } from '../../../../helpers/context.js';

async function run(files: Record<string, string>) {
  return await rule.run(memoryContext(files));
}

describe('HTTP-006 X-Powered-By header enabled', () => {
  it('has the documented metadata', async () => {
    expect(rule).toMatchObject({
      id: 'HTTP-006',
      title: 'X-Powered-By header enabled',
      category: 'http-config',
      severity: 'low',
      confidence: 'high',
      stacks: ['nextjs-app-router'],
      cwe: 'CWE-200',
    });
    expect(rule.falsePositiveNote).toMatch(/LIVE-001/);
  });

  it('reports a missing poweredByHeader at the config object line', async () => {
    expect(await run({ 'next.config.mjs': '// cfg\nconst nextConfig = {\n  reactStrictMode: true,\n}\nexport default nextConfig\n' })).toEqual([
      { file: 'next.config.mjs', line: 2, evidence: 'const nextConfig = {' },
    ]);
  });

  it('reports poweredByHeader: true at the property line', async () => {
    expect(await run({ 'next.config.ts': 'export default {\n  poweredByHeader: true,\n}\n' })).toEqual([
      { file: 'next.config.ts', line: 2, evidence: 'poweredByHeader: true,' },
    ]);
  });

  it('reports a dynamic value with medium confidence', async () => {
    expect(await run({ 'next.config.js': "module.exports = {\n  poweredByHeader: process.env.HIDE !== '1',\n}\n" })).toEqual([
      { file: 'next.config.js', line: 2, evidence: "poweredByHeader: process.env.HIDE !== '1',", confidence: 'medium' },
    ]);
  });

  it('lowers confidence when a spread could set the option', async () => {
    const [finding] = await run({ 'next.config.mjs': "import base from './base.mjs'\nexport default {\n  ...base,\n}\n" });
    expect(finding).toMatchObject({ line: 2, confidence: 'medium' });
  });

  it('accepts poweredByHeader: false', async () => {
    expect(await run({ 'next.config.mjs': 'export default { poweredByHeader: false }' })).toEqual([]);
  });

  it('does nothing without a statically readable next.config', async () => {
    expect(await run({ 'app/page.tsx': '' })).toEqual([]);
    expect(await run({ 'next.config.mjs': "import c from './c.mjs'\nexport default c" })).toEqual([]);
  });
});
