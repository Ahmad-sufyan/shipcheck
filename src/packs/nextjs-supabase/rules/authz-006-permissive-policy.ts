import { lineAt } from '../../../context/files.js';
import type { RawFinding, Rule } from '../../../types.js';
import { sqlModel } from '../analysis/sql-model.js';

const ALWAYS_TRUE = /^\(*\s*true\s*\)*$/i;

export const authz006: Rule = {
  id: 'AUTHZ-006',
  title: 'Permissive RLS policy',
  category: 'authorization',
  severity: 'high',
  confidence: 'high',
  stacks: ['supabase'],
  description:
    'Reports RLS policies in migrations whose USING or WITH CHECK expression is literally `true`, which lets every role the ' +
    'policy applies to see or change every row. Write policies (insert, update, delete, all) and policies granted to anon are ' +
    'high; select-only policies for other roles are medium with low confidence because public read access is often ' +
    'intended. Limitations: expressions that are always true in other ways (1 = 1) are not recognised.',
  explanation:
    'This policy does not restrict which rows a user can reach: any user it applies to can act on every row in the table, ' +
    'not just their own.',
  fix: 'Scope the policy to the owner, for example `using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id)`.',
  falsePositiveNote: 'Intentionally public read policies (for example published blog posts) are expected; they are reported as medium/low.',
  cwe: 'CWE-285',
  references: ['https://supabase.com/docs/guides/database/postgres/row-level-security', 'https://www.postgresql.org/docs/current/sql-createpolicy.html'],
  run(ctx) {
    const model = sqlModel(ctx);
    const findings: RawFinding[] = [];
    for (const policy of model.policies) {
      const alwaysTrue = [policy.using, policy.withCheck].some((expression) => expression !== null && ALWAYS_TRUE.test(expression));
      if (!alwaysTrue) continue;
      const text = ctx.sqlMigrations.find((m) => m.file === policy.file)?.text ?? '';
      const finding: RawFinding = { file: policy.file, line: policy.line, evidence: lineAt(text, policy.line).trim() };
      if (policy.command === 'select' && !policy.roles.includes('anon')) {
        finding.severity = 'medium';
        finding.confidence = 'low';
      }
      findings.push(finding);
    }
    return findings;
  },
};
