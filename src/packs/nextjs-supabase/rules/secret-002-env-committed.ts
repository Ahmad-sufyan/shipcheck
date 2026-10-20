import type { RawFinding, Rule, ScanContext } from '../../../types.js';
import { gitStatus } from '../analysis/git-status.js';
import { findSecrets, hasUrlCredentials, isExampleEnvFile, isPlaceholder, looksRandom, SECRET_ENV_NAME } from '../analysis/secret-patterns.js';

/** .env*.local and Cloudflare .dev.vars hold machine-specific secrets by convention. */
const LOCAL_ENV_FILE = /(?:^|\/)(?:\.env(?:\..+)?\.local|\.dev\.vars(?:\.[^.]+)?)$/;

type EnvEntry = ScanContext['envFiles'][number]['entries'][number];

function holdsSecret({ key, value }: EnvEntry): boolean {
  const trimmed = value.trim();
  if (!trimmed || isPlaceholder(trimmed)) return false;
  if (findSecrets(trimmed).length || hasUrlCredentials(trimmed)) return true;
  return !key.startsWith('NEXT_PUBLIC_') && (SECRET_ENV_NAME.test(key) || looksRandom(trimmed));
}

export const secret002: Rule = {
  id: 'SECRET-002',
  title: '.env file committed or not ignored',
  category: 'secrets',
  severity: 'critical',
  confidence: 'high',
  stacks: [],
  description:
    'Reports .env files (and Cloudflare .dev.vars) that git tracks, as critical, or that git does not ignore, as high. ' +
    'Example files (.env.example, .env.sample, .env.template) are exempt. Shared defaults files such as .env or ' +
    '.env.production are only reported when they contain secret-looking values, since Next.js allows committing ' +
    'non-secret defaults. Uses git ls-files and git check-ignore when the project is a repository, otherwise the ' +
    'root .gitignore.',
  explanation:
    'Env files hold API keys and database passwords. A tracked file is in the repository history for everyone with access ' +
    '(and the whole internet if the repository is public); an unignored one is one `git add .` away from it.',
  fix:
    'Add `.env*` (with `!.env.example`) to .gitignore, run `git rm --cached <file>` for tracked files, and rotate every ' +
    'secret the file contained: removing it from the latest commit does not remove it from history.',
  falsePositiveNote: 'None expected for files with real values; files with only public defaults are skipped.',
  cwe: 'CWE-538',
  references: ['https://nextjs.org/docs/app/guides/environment-variables', 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository'],
  async run(ctx) {
    const candidates = ctx.envFiles.filter(
      (env) => env.entries.length > 0 && !isExampleEnvFile(env.file) && (LOCAL_ENV_FILE.test(env.file) || env.entries.some(holdsSecret)),
    );
    if (!candidates.length) return [];
    const statuses = await gitStatus(
      ctx,
      candidates.map((env) => env.file),
    );
    const findings: RawFinding[] = [];
    for (const env of candidates) {
      const status = statuses.get(env.file);
      if (!status || (status.tracked !== true && status.ignored)) continue;
      const line = env.entries[0]!.line;
      if (status.tracked) findings.push({ file: env.file, line, evidence: `${env.file} is tracked by git`, severity: 'critical' });
      else findings.push({ file: env.file, line, evidence: `${env.file} is ${status.tracked === false ? 'not ignored by git' : 'not listed in .gitignore'}`, severity: 'high' });
    }
    return findings;
  },
};
