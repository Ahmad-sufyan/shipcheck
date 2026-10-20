import { describe, expect, it } from 'vitest';
import { compareVersions, lockedPackages } from '../../../src/packs/nextjs-supabase/analysis/lockfile.js';
import { code, memoryContext } from '../../helpers/memory-context.js';

const pkg = JSON.stringify({ dependencies: { next: '15.1.0', sharp: '0.33.0' }, devDependencies: { typescript: '5.6.3' } });

describe('compareVersions', () => {
  it.each([
    ['15.1.0', '15.5.24', -1],
    ['15.5.24', '15.5.24', 0],
    ['16.3.8', '16.3.7', 1],
    ['16.0.0-canary.1', '16.0.0', -1],
    ['10.0.0', '9.9.9', 1],
  ])('%s vs %s -> %i', (a, b, sign) => {
    expect(Math.sign(compareVersions(a, b))).toBe(sign);
  });
});

describe('lockedPackages', () => {
  it('reads package-lock.json v3 with dev, direct, install-script flags and lines', () => {
    const lock = JSON.stringify(
      {
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { next: '15.1.0' } },
          'node_modules/next': { version: '15.1.0' },
          'node_modules/sharp': { version: '0.33.0', hasInstallScript: true, optional: true },
          'node_modules/typescript': { version: '5.6.3', dev: true },
          'node_modules/next/node_modules/postcss': { version: '8.4.31' },
        },
      },
      null,
      2,
    );
    const ctx = memoryContext({ 'package.json': pkg, 'package-lock.json': lock });
    expect(lockedPackages(ctx)).toEqual([
      { name: 'next', version: '15.1.0', dev: false, direct: true, hasInstallScript: false, file: 'package-lock.json', line: 10 },
      { name: 'sharp', version: '0.33.0', dev: false, direct: true, hasInstallScript: true, file: 'package-lock.json', line: 13 },
      { name: 'typescript', version: '5.6.3', dev: true, direct: true, hasInstallScript: false, file: 'package-lock.json', line: 18 },
      { name: 'postcss', version: '8.4.31', dev: false, direct: false, hasInstallScript: false, file: 'package-lock.json', line: 22 },
    ]);
  });

  it('reads pnpm-lock.yaml v9', () => {
    const lock = code(
      "lockfileVersion: '9.0'",
      'importers:',
      '  .:',
      '    dependencies:',
      '      next:',
      '        specifier: 15.1.0',
      '        version: 15.1.0(react-dom@19.0.0(react@19.0.0))(react@19.0.0)',
      '    devDependencies:',
      '      typescript:',
      '        specifier: 5.6.3',
      '        version: 5.6.3',
      'packages:',
      '  next@15.1.0:',
      '    resolution: {integrity: sha512-x}',
      '  typescript@5.6.3:',
      '    resolution: {integrity: sha512-y}',
      "  '@supabase/ssr@0.5.2':",
      '    resolution: {integrity: sha512-z}',
    );
    const found = lockedPackages(memoryContext({ 'package.json': pkg, 'pnpm-lock.yaml': lock })).map((p) => [p.name, p.version, p.dev, p.direct, p.line]);
    expect(found).toEqual([
      ['next', '15.1.0', false, true, 13],
      ['typescript', '5.6.3', true, true, 15],
      ['@supabase/ssr', '0.5.2', false, false, 17],
    ]);
  });

  it('reads yarn.lock v1', () => {
    const lock = code('# yarn lockfile v1', '', 'next@15.1.0:', '  version "15.1.0"', '  resolved "https://registry.yarnpkg.com/next/-/next-15.1.0.tgz"', '', '"@supabase/ssr@^0.5.0":', '  version "0.5.2"');
    expect(lockedPackages(memoryContext({ 'package.json': pkg, 'yarn.lock': lock })).map((p) => [p.name, p.version, p.line])).toEqual([
      ['next', '15.1.0', 4],
      ['@supabase/ssr', '0.5.2', 8],
    ]);
  });

  it('returns nothing without a lockfile', () => {
    expect(lockedPackages(memoryContext({ 'package.json': pkg }))).toEqual([]);
  });
});
