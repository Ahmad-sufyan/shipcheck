import { describe, expect, it } from 'vitest';
import { secret002 as rule } from '../../../src/packs/nextjs-supabase/rules/secret-002-env-committed.js';
import { fakeExec, toolContext } from '../../helpers/fake-exec.js';
import { FAKE } from '../../helpers/fake-secrets.js';
import { runRule } from '../../helpers/memory-context.js';

const LOCAL = `# local values\nNEXT_PUBLIC_SUPABASE_URL=https://x.supabase.co\nSTRIPE_SECRET_KEY=${FAKE.stripe}`;

/** git answers: the project is a repository, `tracked` files are in the index, `ignored` ones are excluded. */
const git = (tracked: string[], ignored: string[]) =>
  toolContext(
    fakeExec((command, args) => {
      if (command !== 'git') return 'missing';
      if (args[0] === 'rev-parse') return { stdout: '\n' };
      if (args[0] === 'ls-files') return { stdout: tracked.map((f) => `${f}\0`).join('') };
      const hits = args.slice(2).filter((f) => ignored.includes(f));
      return { exitCode: hits.length ? 0 : 1, stdout: hits.map((f) => `${f}\n`).join('') };
    }).exec,
  );

describe('SECRET-002 .env file committed or not ignored', () => {
  it('reports a tracked env file as critical, at its first entry', async () => {
    expect(await runRule(rule, { '.env.local': LOCAL }, {}, { tools: git(['.env.local'], []) })).toEqual([
      { file: '.env.local', line: 2, evidence: '.env.local is tracked by git', severity: 'critical' },
    ]);
  });

  it('reports an untracked env file that git does not ignore as high', async () => {
    expect(await runRule(rule, { '.env.local': LOCAL }, {}, { tools: git([], []) })).toEqual([
      { file: '.env.local', line: 2, evidence: '.env.local is not ignored by git', severity: 'high' },
    ]);
  });

  it('is quiet when git ignores the file', async () => {
    expect(await runRule(rule, { '.env.local': LOCAL }, {}, { tools: git([], ['.env.local']) })).toEqual([]);
  });

  it('falls back to the root .gitignore outside a repository', async () => {
    expect(await runRule(rule, { '.env.local': LOCAL, '.gitignore': 'node_modules\n.env\n' })).toEqual([
      { file: '.env.local', line: 2, evidence: '.env.local is not listed in .gitignore', severity: 'high' },
    ]);
    expect(await runRule(rule, { '.env.local': LOCAL, '.gitignore': '.env*.local\n' })).toEqual([]);
  });

  it('ignores example files and empty files', async () => {
    expect(await runRule(rule, { '.env.example': 'STRIPE_SECRET_KEY=', '.env.sample': 'A=', '.env.local': '# nothing yet\n' }, {}, { tools: git(['.env.example', '.env.sample', '.env.local'], []) })).toEqual([]);
  });

  it('only reports shared defaults files (.env, .env.production) when they hold secrets', async () => {
    const tools = git(['.env', '.env.production'], []);
    expect(await runRule(rule, { '.env': 'NEXT_PUBLIC_SITE_URL=https://example.com\nLOG_LEVEL=info' }, {}, { tools })).toEqual([]);
    expect(await runRule(rule, { '.env.production': 'DATABASE_URL=postgres://app:hunter2hunter2@db.internal/app' }, {}, { tools })).toEqual([expect.objectContaining({ file: '.env.production', severity: 'critical' })]);
    expect(await runRule(rule, { '.env': `SUPABASE_SERVICE_ROLE_KEY=${FAKE.supabaseServiceJwt}` }, {}, { tools })).toHaveLength(1);
  });

  it('treats Cloudflare .dev.vars like a local env file', async () => {
    expect(await runRule(rule, { '.dev.vars': 'API_TOKEN=abc' }, {}, { tools: git([], []) })).toEqual([expect.objectContaining({ file: '.dev.vars', line: 1 })]);
  });
});
