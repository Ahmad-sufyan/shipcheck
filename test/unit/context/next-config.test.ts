import { describe, expect, it } from 'vitest';
import { createAstCache } from '../../../src/context/ast.js';
import { createMemorySource } from '../../../src/context/files.js';
import { NEXT_CONFIG_FILES, readNextConfig } from '../../../src/context/next-config.js';

function read(files: Record<string, string>) {
  const source = createMemorySource(files);
  const skipped: { check: string; reason: string }[] = [];
  const info = readNextConfig(source, createAstCache(source.readText), skipped);
  return { info, skipped };
}

describe('readNextConfig', () => {
  it('lists the supported file names in Next.js lookup order', () => {
    expect(NEXT_CONFIG_FILES).toEqual(['next.config.js', 'next.config.mjs', 'next.config.ts', 'next.config.mts']);
  });

  it('returns null when there is no next.config', () => {
    expect(read({ 'package.json': '{}' }).info).toBeNull();
  });

  it('reads `export default { ... }` with literal values and lines', () => {
    const { info } = read({
      'next.config.mjs': [
        '/** @type {import("next").NextConfig} */',
        'export default {',
        '  reactStrictMode: true,',
        "  output: 'standalone',",
        '  "poweredByHeader": false,',
        '  compress: 1,',
        '  images: { remotePatterns: [{ hostname: "x.test" }] },',
        '  pageExtensions: ["ts", "tsx"],',
        '  env: { A: process.env.A },',
        '}',
      ].join('\n'),
    });
    expect(info?.file).toBe('next.config.mjs');
    expect(info?.objectLine).toBe(2);
    expect(info?.options).toEqual({
      reactStrictMode: { value: true, line: 3, dynamic: false },
      output: { value: 'standalone', line: 4, dynamic: false },
      poweredByHeader: { value: false, line: 5, dynamic: false },
      compress: { value: 1, line: 6, dynamic: false },
      images: { value: { remotePatterns: [{ hostname: 'x.test' }] }, line: 7, dynamic: false },
      pageExtensions: { value: ['ts', 'tsx'], line: 8, dynamic: false },
      env: { value: undefined, line: 9, dynamic: true },
    });
    expect(info?.hasHeadersFn).toBe(false);
    expect(info?.hasSpread).toBe(false);
  });

  it('follows `const nextConfig: NextConfig = {...}; export default nextConfig` in next.config.ts', () => {
    const { info } = read({
      'next.config.ts': [
        "import type { NextConfig } from 'next'",
        '',
        'const nextConfig: NextConfig = {',
        '  productionBrowserSourceMaps: true,',
        '}',
        '',
        'export default nextConfig',
      ].join('\n'),
    });
    expect(info?.objectLine).toBe(3);
    expect(info?.options.productionBrowserSourceMaps).toEqual({ value: true, line: 4, dynamic: false });
  });

  it('handles module.exports', () => {
    const { info } = read({ 'next.config.js': '// @ts-check\nconst config = {\n  poweredByHeader: false,\n}\nmodule.exports = config\n' });
    expect(info?.objectLine).toBe(2);
    expect(info?.options.poweredByHeader).toEqual({ value: false, line: 3, dynamic: false });
  });

  it('unwraps satisfies and as expressions', () => {
    const satisfies = read({ 'next.config.ts': "import type { NextConfig } from 'next'\nexport default { poweredByHeader: false } satisfies NextConfig\n" });
    expect(satisfies.info?.options.poweredByHeader?.value).toBe(false);
    const asExpr = read({ 'next.config.ts': "import type { NextConfig } from 'next'\nconst c = ({ poweredByHeader: false }) as NextConfig\nexport default c\n" });
    expect(asExpr.info?.options.poweredByHeader?.value).toBe(false);
  });

  it('unwraps plugin wrappers, including curried ones', () => {
    const wrapped = read({
      'next.config.mjs': "import { withSentryConfig } from '@sentry/nextjs'\nconst nextConfig = { poweredByHeader: false }\nexport default withSentryConfig(nextConfig, { org: 'x' })\n",
    });
    expect(wrapped.info?.objectLine).toBe(2);
    expect(Object.keys(wrapped.info?.options ?? {})).toEqual(['poweredByHeader']);

    const curried = read({
      'next.config.js': "const withBundleAnalyzer = require('@next/bundle-analyzer')({ enabled: true })\nmodule.exports = withBundleAnalyzer({\n  productionBrowserSourceMaps: true,\n})\n",
    });
    expect(curried.info?.options.productionBrowserSourceMaps).toEqual({ value: true, line: 3, dynamic: false });
  });

  it('handles the function form by reading the last returned object', () => {
    const { info } = read({
      'next.config.mjs': [
        "import { PHASE_DEVELOPMENT_SERVER } from 'next/constants'",
        'export default (phase) => {',
        '  if (phase === PHASE_DEVELOPMENT_SERVER) {',
        '    return { productionBrowserSourceMaps: false }',
        '  }',
        '  return { productionBrowserSourceMaps: true }',
        '}',
      ].join('\n'),
    });
    expect(info?.options.productionBrowserSourceMaps).toEqual({ value: true, line: 6, dynamic: false });

    const arrow = read({ 'next.config.mjs': 'export default async () => ({\n  poweredByHeader: true,\n})\n' });
    expect(arrow.info?.options.poweredByHeader).toEqual({ value: true, line: 2, dynamic: false });
  });

  it('marks non-literal values dynamic and detects a headers function', () => {
    const { info } = read({
      'next.config.mjs': [
        'const isProd = process.env.NODE_ENV === "production"',
        'const base = {}',
        'export default {',
        '  ...base,',
        "  productionBrowserSourceMaps: process.env.SOURCE_MAPS === 'true',",
        '  poweredByHeader: isProd ? false : true,',
        '  async headers() {',
        '    return []',
        '  },',
        '}',
      ].join('\n'),
    });
    expect(info?.options.productionBrowserSourceMaps).toEqual({ value: undefined, line: 5, dynamic: true });
    expect(info?.options.poweredByHeader).toEqual({ value: undefined, line: 6, dynamic: true });
    expect(info?.options.headers).toEqual({ value: undefined, line: 7, dynamic: true });
    expect(info?.hasHeadersFn).toBe(true);
    expect(info?.hasSpread).toBe(true);
  });

  it('detects headers as an arrow-function property', () => {
    const { info } = read({ 'next.config.mjs': 'export default { headers: async () => [] }' });
    expect(info?.hasHeadersFn).toBe(true);
  });

  it('returns null and records a skip when the config object cannot be resolved statically', () => {
    const { info, skipped } = read({ 'next.config.mjs': "import config from './shared-config.mjs'\nexport default config\n" });
    expect(info).toBeNull();
    expect(skipped).toEqual([{ check: 'next.config.mjs', reason: expect.stringMatching(/could not statically resolve/) }]);
  });

  it('uses Next.js lookup order when several config files exist', () => {
    const { info } = read({
      'next.config.ts': 'export default { poweredByHeader: true }',
      'next.config.mjs': 'export default { poweredByHeader: false }',
    });
    expect(info?.file).toBe('next.config.mjs');
  });
});
