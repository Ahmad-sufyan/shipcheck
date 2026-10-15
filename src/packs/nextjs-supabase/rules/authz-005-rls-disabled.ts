import { lineAt } from '../../../context/files.js';
import type { RawFinding, Rule } from '../../../types.js';
import { sqlModel } from '../analysis/sql-model.js';

export const authz005: Rule = {
  id: 'AUTHZ-005',
  title: 'Row level security disabled',
  category: 'authorization',
  severity: 'critical',
  confidence: 'high',
  stacks: ['supabase'],
  description:
    'Supabase exposes every table in the public schema through its Data API using the anon key that ships to browsers. ' +
    'The rule replays all .sql migrations in path order and reports public tables that end up without `enable row level ' +
    'security` (at the create statement), and tables whose RLS is later disabled (at the disable statement). Tables revoked ' +
    'from both anon and authenticated are skipped. Limitations: tables created or changed in the dashboard are invisible.',
  explanation:
    'Anyone with your public anon key, which is in every browser that loads your app, can read and change every row in this ' +
    'table through the Supabase API.',
  fix:
    'Add `alter table public.<table> enable row level security;` in a migration, then add policies that scope rows to their ' +
    'owner, for example `using ((select auth.uid()) = user_id)`.',
  falsePositiveNote:
    'Tables created in the Supabase dashboard are invisible; a table that should never be reachable through the API can be ' +
    'revoked from anon and authenticated instead.',
  cwe: 'CWE-862',
  references: ['https://supabase.com/docs/guides/database/postgres/row-level-security'],
  run(ctx) {
    const model = sqlModel(ctx);
    const text = (file: string) => ctx.sqlMigrations.find((m) => m.file === file)?.text ?? '';
    const finding = (file: string, line: number): RawFinding => ({ file, line, evidence: lineAt(text(file), line).trim() });

    const findings: RawFinding[] = [];
    const disabled = new Set(model.rlsDisabled.map((d) => d.table));
    for (const table of model.tables) {
      const key = table.name;
      if (table.schema !== 'public' || model.rlsEnabled.has(key) || disabled.has(key) || model.revokedFromApi.has(key)) continue;
      findings.push(finding(table.file, table.line));
    }
    for (const entry of model.rlsDisabled) {
      if (entry.table.includes('.') || model.revokedFromApi.has(entry.table)) continue;
      findings.push(finding(entry.file, entry.line));
    }
    return findings;
  },
};
