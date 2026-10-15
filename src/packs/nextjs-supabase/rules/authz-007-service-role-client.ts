import { Node, SyntaxKind } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { findingAt, sourceFiles, stringLiteral } from '../analysis/ast-utils.js';

const SERVICE_ROLE_ENV = /SERVICE_ROLE/i;
const PUBLIC_SERVICE_ROLE_ENV = /^NEXT_PUBLIC_.*SERVICE_ROLE/i;
const JWT = /^eyJ[\w-]+\.([\w-]+)\.[\w-]*$/;

/** Env var name for `process.env.X` or `process.env['X']`. */
function envName(node: Node): string | undefined {
  if (Node.isPropertyAccessExpression(node) && node.getExpression().getText() === 'process.env') return node.getName();
  if (Node.isElementAccessExpression(node) && node.getExpression().getText() === 'process.env') return stringLiteral(node.getArgumentExpression());
  return undefined;
}

function isServiceRoleKey(value: string): boolean {
  if (value.startsWith('sb_secret_')) return true;
  const payload = JWT.exec(value)?.[1];
  if (!payload) return false;
  try {
    return (JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { role?: unknown }).role === 'service_role';
  } catch {
    return false;
  }
}

export const authz007: Rule = {
  id: 'AUTHZ-007',
  title: 'service_role key in client code',
  category: 'authorization',
  severity: 'critical',
  confidence: 'high',
  stacks: ['supabase'],
  description:
    "Reports 'use client' files that read a *SERVICE_ROLE* environment variable or contain a literal Supabase key whose " +
    'JWT payload has role service_role (or a new-style sb_secret_ key), and any NEXT_PUBLIC_*SERVICE_ROLE* variable in code ' +
    'or .env files, since Next.js inlines NEXT_PUBLIC_ values into the browser bundle. Limitations: server modules that a ' +
    'client component imports are not followed.',
  explanation:
    'The service_role key bypasses every row level security policy. If it reaches the browser, anyone can copy it and read, ' +
    'change or delete all data in your project.',
  fix:
    'Use the service role key only in server code (route handlers, server actions, files that import "server-only"), keep it ' +
    'out of NEXT_PUBLIC_ variables, and rotate it if it was ever shipped to a browser.',
  falsePositiveNote: 'None expected: a service role key is never safe in client code.',
  cwe: 'CWE-522',
  references: ['https://supabase.com/docs/guides/api/api-keys', 'https://nextjs.org/docs/app/guides/environment-variables'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => /SERVICE_ROLE|eyJ|sb_secret_/i.test(text))) {
      const client = ctx.next.isClientFile(file);
      const reported = new Set<number>();
      const report = (node: Node) => {
        const finding = findingAt(node);
        if (!reported.has(finding.line!)) findings.push(finding);
        reported.add(finding.line!);
      };
      ctx.getSourceFile(file).forEachDescendant((node) => {
        const name = envName(node);
        if (name && SERVICE_ROLE_ENV.test(name) && (client || PUBLIC_SERVICE_ROLE_ENV.test(name))) report(node);
        if (client && (node.getKind() === SyntaxKind.StringLiteral || node.getKind() === SyntaxKind.NoSubstitutionTemplateLiteral)) {
          const value = stringLiteral(node);
          if (value && isServiceRoleKey(value)) report(node);
        }
      });
    }
    for (const env of ctx.envFiles) {
      for (const entry of env.entries) {
        if (PUBLIC_SERVICE_ROLE_ENV.test(entry.key)) findings.push({ file: env.file, line: entry.line, evidence: `${entry.key}=<redacted>` });
      }
    }
    return findings;
  },
};
