import type { Rule } from '../../../types.js';
import { sourceFiles } from '../analysis/ast-utils.js';

const VALIDATION_PACKAGES = ['@t3-oss/env-nextjs', '@t3-oss/env-core', 'envalid', 'znv', 'env-var', '@julr/vite-plugin-validate-env'];
/** A schema parse of process.env (zod, valibot, yup, ...), t3-env's createEnv or envalid's cleanEnv. */
const VALIDATION_CALL = /\b(?:createEnv|cleanEnv)\s*\(|\.(?:safeParse|parse|parseAsync|safeParseAsync|validateSync|validate)\s*\(\s*process\.env\b|\b(?:parse|safeParse)\s*\(\s*\w+\s*,\s*process\.env\b|\bparseEnv\s*\(\s*process\.env\b/;

function dependencies(data: Record<string, unknown> | undefined): string[] {
  if (!data) return [];
  return ['dependencies', 'devDependencies'].flatMap((field) => {
    const deps = data[field];
    return deps && typeof deps === 'object' ? Object.keys(deps) : [];
  });
}

export const secret008: Rule = {
  id: 'SECRET-008',
  title: 'No startup validation of environment variables',
  category: 'secrets',
  severity: 'info',
  confidence: 'medium',
  advisory: true,
  stacks: [],
  description:
    'Project-level advisory: reported once when the code reads process.env but nothing validates it, i.e. no ' +
    '@t3-oss/env-nextjs, envalid or similar package, and no schema parse of process.env (zod, valibot) anywhere.',
  explanation:
    'Without validation, a missing or mistyped secret only shows up when a request hits the code that needs it, often as ' +
    'a confusing runtime error or, worse, a silently disabled check (for example a webhook secret that is undefined).',
  fix: 'Parse process.env once at startup with a schema (for example `EnvSchema.parse(process.env)` with zod, or @t3-oss/env-nextjs) and import the typed result instead of reading process.env directly.',
  falsePositiveNote: 'Projects that validate env vars in a custom startup script or CI step can turn this advisory off.',
  cwe: 'CWE-1188',
  references: ['https://env.t3.gg/docs/nextjs', 'https://zod.dev/'],
  run(ctx) {
    const readsEnv = sourceFiles(ctx, (text) => text.includes('process.env'));
    if (!readsEnv.length) return [];
    if (dependencies(ctx.packageJson?.data).some((name) => VALIDATION_PACKAGES.includes(name))) return [];
    if (readsEnv.some((file) => VALIDATION_CALL.test(ctx.readText(file)))) return [];
    return [{ evidence: `process.env is read in ${readsEnv.length} file${readsEnv.length === 1 ? '' : 's'} but never validated at startup` }];
  },
};
