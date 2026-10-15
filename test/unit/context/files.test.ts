import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createDiskSource, createMemorySource, listFiles } from '../../../src/context/files.js';
import { tmpProject } from '../../helpers/context.js';

describe('listFiles', () => {
  it('returns sorted repo-relative posix paths including dotfiles', async () => {
    const root = tmpProject({
      'app/page.tsx': '',
      '.env': 'A=1',
      'lib/b.ts': '',
      'lib/a.ts': '',
    });
    expect(await listFiles(root, [])).toEqual(['.env', 'app/page.tsx', 'lib/a.ts', 'lib/b.ts']);
  });

  it('skips dependency, VCS and build output directories', async () => {
    const root = tmpProject({
      'node_modules/x/index.js': '',
      'apps/web/node_modules/y/index.js': '',
      '.next/server/app.js': '',
      '.git/HEAD': '',
      'dist/cli.js': '',
      'src/index.ts': '',
    });
    expect(await listFiles(root, [])).toEqual(['src/index.ts']);
  });

  it('applies ignorePaths globs', async () => {
    const root = tmpProject({ 'fixtures/a/x.ts': '', 'src/y.ts': '', 'src/y.test.ts': '' });
    expect(await listFiles(root, ['fixtures/**', '**/*.test.ts'])).toEqual(['src/y.ts']);
  });
});

describe('createDiskSource', () => {
  it('reads and caches file text, stripping a BOM', () => {
    const root = tmpProject({ 'a.ts': '﻿const a = 1' });
    const source = createDiskSource(root, ['a.ts']);
    expect(source.readText('a.ts')).toBe('const a = 1');
    writeFileSync(join(root, 'a.ts'), 'changed');
    expect(source.readText('a.ts')).toBe('const a = 1');
  });

  it('refuses paths that escape the root', () => {
    const root = tmpProject({ 'a.ts': '' });
    const source = createDiskSource(root, ['a.ts']);
    expect(() => source.readText('../outside.ts')).toThrow(/outside the scan root/);
    expect(() => source.readText('/etc/passwd')).toThrow(/outside the scan root/);
  });

  it('answers directory and file existence relative to the root', () => {
    const root = tmpProject({ 'app/page.tsx': '', 'vercel.json': '{}' });
    mkdirSync(join(root, '.vercel'));
    const source = createDiskSource(root, ['app/page.tsx', 'vercel.json']);
    expect(source.isDirectory('app')).toBe(true);
    expect(source.isDirectory('.vercel')).toBe(true);
    expect(source.isDirectory('src/app')).toBe(false);
    expect(source.isFile('vercel.json')).toBe(true);
    expect(source.isFile('app')).toBe(false);
  });
});

describe('createMemorySource', () => {
  it('serves files from a map and derives directories', () => {
    const source = createMemorySource({ 'src/app/api/x/route.ts': 'x', 'b.ts': 'y' });
    expect(source.files).toEqual(['b.ts', 'src/app/api/x/route.ts']);
    expect(source.readText('b.ts')).toBe('y');
    expect(source.isDirectory('src/app')).toBe(true);
    expect(source.isDirectory('app')).toBe(false);
    expect(source.isFile('b.ts')).toBe(true);
    expect(() => source.readText('missing.ts')).toThrow(/not found/);
  });
});
