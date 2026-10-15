import { lineAt } from '../../../context/files.js';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calls, findingAt, objectProperty, sourceFiles } from '../analysis/ast-utils.js';
import { splitStatements, sqlModel } from '../analysis/sql-model.js';

const INSERT_BUCKET = /^insert\s+into\s+storage\.buckets\s*\(([^)]*)\)\s*values\s*([\s\S]*)$/i;
const UPDATE_PUBLIC = /^update\s+storage\.buckets\s+set\s+[\s\S]*\bpublic\s*=\s*true\b/i;
const ALWAYS_TRUE = /^\(*\s*true\s*\)*$/i;

/** Splits `('a', 'b', true), ('c', 'd', false)` into value lists, respecting quotes. */
function tuples(values: string): string[][] {
  const result: string[][] = [];
  let depth = 0;
  let quote = false;
  let current = '';
  let row: string[] = [];
  for (const ch of values) {
    if (ch === "'") quote = !quote;
    if (!quote && ch === '(') {
      if (depth++ === 0) {
        current = '';
        row = [];
        continue;
      }
    }
    if (!quote && ch === ')') {
      if (--depth === 0) {
        row.push(current.trim());
        result.push(row);
        continue;
      }
    }
    if (!quote && ch === ',' && depth === 1) {
      row.push(current.trim());
      current = '';
      continue;
    }
    if (depth >= 1) current += ch;
  }
  return result;
}

export const data003: Rule = {
  id: 'DATA-003',
  title: 'Public storage bucket',
  category: 'data-protection',
  severity: 'high',
  confidence: 'high',
  stacks: ['supabase'],
  description:
    'Reports Supabase Storage buckets made public: `insert into storage.buckets (..., public) values (..., true)` or ' +
    '`update storage.buckets set public = true` in migrations, storage.createBucket/updateBucket(..., { public: true }) in ' +
    'code, and storage.objects select policies using (true). Public buckets serve every file to anyone with the URL and ' +
    'bypass read policies.',
  explanation:
    'Every file in this bucket can be downloaded by anyone who has or guesses its URL, without signing in, regardless of ' +
    'your row level security policies.',
  fix: 'Make the bucket private (public: false), add owner-scoped policies on storage.objects, and hand out short-lived signed URLs (createSignedUrl) for downloads.',
  falsePositiveNote: 'Buckets meant for genuinely public assets (marketing images) are fine; accept them in a baseline.',
  cwe: 'CWE-284',
  references: ['https://supabase.com/docs/guides/storage/buckets/fundamentals', 'https://supabase.com/docs/guides/storage/security/access-control'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const { file, text } of ctx.sqlMigrations) {
      for (const { sql, line } of splitStatements(text)) {
        const insert = INSERT_BUCKET.exec(sql);
        const columns = insert ? insert[1]!.split(',').map((c) => c.trim().replace(/"/g, '').toLowerCase()) : [];
        const publicIndex = columns.indexOf('public');
        const insertsPublic = insert !== null && publicIndex !== -1 && tuples(insert[2]!).some((row) => /^true$/i.test(row[publicIndex] ?? ''));
        if (insertsPublic || UPDATE_PUBLIC.test(sql)) findings.push({ file, line, evidence: lineAt(text, line).trim() });
      }
    }
    for (const policy of sqlModel(ctx).policies) {
      if (policy.table !== 'storage.objects' || !['select', 'all'].includes(policy.command) || !ALWAYS_TRUE.test(policy.using ?? '')) continue;
      const text = ctx.sqlMigrations.find((m) => m.file === policy.file)?.text ?? '';
      findings.push({ file: policy.file, line: policy.line, evidence: lineAt(text, policy.line).trim() });
    }
    for (const file of sourceFiles(ctx, (text) => /createBucket|updateBucket/.test(text))) {
      for (const call of calls(ctx.getSourceFile(file))) {
        if (!['createBucket', 'updateBucket'].includes(calleeName(call))) continue;
        const options = call.getArguments()[1];
        if (objectProperty(options, 'public')?.getText() === 'true') findings.push(findingAt(call));
      }
    }
    return findings;
  },
};
