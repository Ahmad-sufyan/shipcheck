import { Node } from 'ts-morph';
import type { RawFinding, Rule, ScanContext } from '../../../types.js';
import { calleeName, calls, findingAt } from '../analysis/ast-utils.js';
import { hasAuthCheck } from '../analysis/auth-check.js';
import { entries } from '../analysis/entries.js';

const JOB_SEGMENT = /^(?:cron|crons|internal|jobs|tasks)$/i;
const AUTH_HEADER = /headers(?:\(\))?\.get\(\s*['"`]authorization['"`]\s*\)/i;
const SIGNED_WRAPPER = /^(?:verifySignature|verifySignatureAppRouter|verifySignatureEdge|withCronAuth|withCron)/;

function cronPaths(ctx: ScanContext): Set<string> {
  const crons = (ctx.vercelJson?.data as { crons?: { path?: unknown }[] } | undefined)?.crons;
  return new Set((Array.isArray(crons) ? crons : []).flatMap((c) => (typeof c.path === 'string' ? [c.path.split('?')[0]!] : [])));
}

/** A shared secret check (Authorization header compared with an env var), a signed-request wrapper, or a signed-in user. */
function isProtected(node: Node, ctx: ScanContext): boolean {
  if (Node.isCallExpression(node) && SIGNED_WRAPPER.test(calleeName(node))) return true;
  if (hasAuthCheck(node, ctx)) return true;
  const text = node.getText();
  if (AUTH_HEADER.test(text) && /process\.env\./.test(text)) return true;
  return calls(node).some((call) => calleeName(call) === 'verify' && /Receiver/.test(text));
}

export const integ002: Rule = {
  id: 'INTEG-002',
  title: 'Cron or internal endpoint without a secret',
  category: 'integrations',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports route handlers under /api/cron (or a cron, internal, jobs or tasks segment) and routes listed in vercel.json ' +
    'crons that never compare the Authorization header with an environment secret (Vercel sends `Bearer $CRON_SECRET`), ' +
    'are not wrapped in QStash signature verification, and do not authenticate a user.',
  explanation:
    'This scheduled or internal job is a public URL. Anyone who finds it can trigger it as often as they like, deleting ' +
    'data, sending emails or running up costs.',
  fix: "Set CRON_SECRET in your project and start the handler with `if (request.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) return new Response('Unauthorized', { status: 401 })`.",
  falsePositiveNote: 'Endpoints protected by platform features outside the code (Vercel deployment protection, firewall rules) are still reported.',
  cwe: 'CWE-306',
  references: ['https://vercel.com/docs/cron-jobs/manage-cron-jobs#securing-cron-jobs'],
  run(ctx) {
    const crons = cronPaths(ctx);
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      if (entry.kind !== 'route' || !entry.routePath) continue;
      const job = crons.has(entry.routePath) || entry.routePath.split('/').some((segment) => JOB_SEGMENT.test(segment));
      if (job && !isProtected(entry.node, ctx)) findings.push(findingAt(entry.node));
    }
    return findings;
  },
};
