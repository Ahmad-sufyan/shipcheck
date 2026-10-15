import { describe, expect, it } from 'vitest';
import {
  collectSqlMigrations,
  detectLockfile,
  parseEnv,
  parseEnvFiles,
  parseJsonc,
  readGitignore,
  readPackageJson,
  readVercelJson,
  readWranglerConfig,
} from '../../../src/context/configs.js';
import { createMemorySource } from '../../../src/context/files.js';

describe('parseEnv', () => {
  it('parses keys, values and line numbers', () => {
    const text = [
      '# comment',
      '',
      'PLAIN=value',
      'export EXPORTED=yes',
      'DOUBLE="quoted # not a comment"',
      "SINGLE='single'",
      'INLINE=value # trailing comment',
      'EMPTY=',
      'SPACED = padded ',
      'not a valid line',
    ].join('\n');
    expect(parseEnv(text)).toEqual([
      { key: 'PLAIN', value: 'value', line: 3 },
      { key: 'EXPORTED', value: 'yes', line: 4 },
      { key: 'DOUBLE', value: 'quoted # not a comment', line: 5 },
      { key: 'SINGLE', value: 'single', line: 6 },
      { key: 'INLINE', value: 'value', line: 7 },
      { key: 'EMPTY', value: '', line: 8 },
      { key: 'SPACED', value: 'padded', line: 9 },
    ]);
  });

  it('handles CRLF line endings', () => {
    expect(parseEnv('A=1\r\nB=2\r\n')).toEqual([
      { key: 'A', value: '1', line: 1 },
      { key: 'B', value: '2', line: 2 },
    ]);
  });
});

describe('parseEnvFiles', () => {
  it('collects .env* and .dev.vars* files anywhere in the project', () => {
    const source = createMemorySource({
      '.env': 'A=1',
      '.env.local': 'B=2',
      'apps/web/.env.production': 'C=3',
      '.dev.vars': 'D=4',
      '.envrc': 'export X=1',
      'lib/env.ts': 'export const env = {}',
    });
    expect(parseEnvFiles(source).map((e) => e.file)).toEqual(['.dev.vars', '.env', '.env.local', 'apps/web/.env.production']);
    expect(parseEnvFiles(source)[0]?.entries).toEqual([{ key: 'D', value: '4', line: 1 }]);
  });
});

describe('detectLockfile', () => {
  it.each([
    ['pnpm-lock.yaml', 'pnpm'],
    ['package-lock.json', 'npm'],
    ['npm-shrinkwrap.json', 'npm'],
    ['yarn.lock', 'yarn'],
    ['bun.lock', 'bun'],
    ['bun.lockb', 'bun'],
  ])('%s -> %s', (file, kind) => {
    expect(detectLockfile(createMemorySource({ [file]: '' }))).toEqual({ kind, file });
  });

  it('prefers pnpm, then npm, yarn and bun, and only looks at the root', () => {
    expect(detectLockfile(createMemorySource({ 'yarn.lock': '', 'pnpm-lock.yaml': '' }))?.kind).toBe('pnpm');
    expect(detectLockfile(createMemorySource({ 'apps/web/yarn.lock': '' }))).toBeNull();
  });
});

describe('readPackageJson', () => {
  it('parses the root package.json', () => {
    const skipped: { check: string; reason: string }[] = [];
    const pkg = readPackageJson(createMemorySource({ 'package.json': '{"name":"x","dependencies":{"next":"16.0.0"}}' }), skipped);
    expect(pkg).toEqual({ file: 'package.json', data: { name: 'x', dependencies: { next: '16.0.0' } } });
    expect(skipped).toEqual([]);
  });

  it('returns null and records a skip for invalid JSON', () => {
    const skipped: { check: string; reason: string }[] = [];
    expect(readPackageJson(createMemorySource({ 'package.json': '{ nope' }), skipped)).toBeNull();
    expect(skipped[0]?.check).toBe('package.json');
    expect(skipped[0]?.reason).toMatch(/invalid JSON/i);
  });

  it('returns null without a package.json', () => {
    expect(readPackageJson(createMemorySource({ 'a.ts': '' }), [])).toBeNull();
  });
});

describe('collectSqlMigrations', () => {
  it('collects every .sql file in path order', () => {
    const source = createMemorySource({
      'supabase/migrations/0002_b.sql': 'select 2;',
      'supabase/migrations/0001_a.sql': 'select 1;',
      'supabase/seed.sql': 'insert;',
      'README.txt': '',
    });
    expect(collectSqlMigrations(source)).toEqual([
      { file: 'supabase/migrations/0001_a.sql', text: 'select 1;' },
      { file: 'supabase/migrations/0002_b.sql', text: 'select 2;' },
      { file: 'supabase/seed.sql', text: 'insert;' },
    ]);
  });
});

describe('platform configs', () => {
  it('reads vercel.json', () => {
    expect(readVercelJson(createMemorySource({ 'vercel.json': '{"headers":[]}' }), [])).toEqual({ file: 'vercel.json', data: { headers: [] } });
    expect(readVercelJson(createMemorySource({}), [])).toBeNull();
  });

  it('reads wrangler.toml', () => {
    const cfg = readWranglerConfig(createMemorySource({ 'wrangler.toml': 'name = "app"\n[vars]\nMODE = "prod"\n' }), []);
    expect(cfg).toEqual({ file: 'wrangler.toml', data: { name: 'app', vars: { MODE: 'prod' } } });
  });

  it('reads wrangler.jsonc with comments and trailing commas', () => {
    const text = '{\n  // comment\n  "name": "app", /* block */\n  "main": "https://x.test/a//b",\n  "vars": { "A": "1", },\n}\n';
    const cfg = readWranglerConfig(createMemorySource({ 'wrangler.jsonc': text }), []);
    expect(cfg).toEqual({ file: 'wrangler.jsonc', data: { name: 'app', main: 'https://x.test/a//b', vars: { A: '1' } } });
  });

  it('prefers wrangler.toml over JSON variants', () => {
    const cfg = readWranglerConfig(createMemorySource({ 'wrangler.json': '{"name":"json"}', 'wrangler.toml': 'name = "toml"' }), []);
    expect(cfg?.file).toBe('wrangler.toml');
  });

  it('records a skip for unparseable TOML', () => {
    const skipped: { check: string; reason: string }[] = [];
    expect(readWranglerConfig(createMemorySource({ 'wrangler.toml': 'name = ' }), skipped)).toBeNull();
    expect(skipped[0]?.check).toBe('wrangler.toml');
  });
});

describe('readGitignore', () => {
  it('returns non-empty, non-comment patterns', () => {
    const source = createMemorySource({ '.gitignore': '# deps\nnode_modules\n\n.env*\n!.env.example\n' });
    expect(readGitignore(source)).toEqual({ file: '.gitignore', patterns: ['node_modules', '.env*', '!.env.example'] });
  });
});

describe('parseJsonc', () => {
  it('keeps comment-like text inside strings', () => {
    expect(parseJsonc('{"a": "// not a comment", "b": "/* nor this */"}')).toEqual({ a: '// not a comment', b: '/* nor this */' });
  });

  it('handles escaped quotes', () => {
    expect(parseJsonc('{"a": "say \\"hi\\" // ok", /* c */ "b": [1, 2,],}')).toEqual({ a: 'say "hi" // ok', b: [1, 2] });
  });
});
