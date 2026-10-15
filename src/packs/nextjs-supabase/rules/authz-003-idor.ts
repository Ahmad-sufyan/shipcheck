import { Node, type CallExpression } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeNameNode, calls, findingAt, objectProperty, resolveExpression, stringLiteral } from '../analysis/ast-utils.js';
import { hasAuthCheck } from '../analysis/auth-check.js';
import { chainCalls, chainTop, prismaMethod, supabaseTable } from '../analysis/db-write.js';
import { entries } from '../analysis/entries.js';
import { hasOwnerPolicy, sqlModel } from '../analysis/sql-model.js';
import { entryFunctionOf, isUserInput } from '../analysis/taint.js';

const OWNER_COLUMN = /^(?:user_id|owner_id|author_id|created_by|profile_id|account_id|userId|ownerId|authorId|createdBy|profileId|accountId)$/;
const PRISMA_BY_ID = new Set(['findUnique', 'findUniqueOrThrow', 'findFirst', 'findFirstOrThrow', 'update', 'delete', 'upsert']);
const SERVICE_CLIENT = /admin|service/i;

function objectKeys(node: Node | undefined): string[] {
  const object = node ? resolveExpression(node) : undefined;
  if (!object || !Node.isObjectLiteralExpression(object)) return [];
  return object.getProperties().flatMap((p) => (Node.isPropertyAssignment(p) || Node.isShorthandPropertyAssignment(p) ? [p.getName().replace(/^['"]|['"]$/g, '')] : []));
}

function hasOwnerFilter(chain: CallExpression[]): boolean {
  return chain.some((call) => {
    const name = calleeName(call);
    const [first] = call.getArguments();
    if (['eq', 'filter'].includes(name)) return OWNER_COLUMN.test(stringLiteral(first) ?? '');
    if (name === 'match') return objectKeys(first).some((key) => OWNER_COLUMN.test(key));
    return false;
  });
}

/** Whether the Supabase client at the root of the chain was created with the service role key. */
function usesServiceRole(chain: CallExpression[]): boolean {
  const innermost = chain.at(-1);
  if (!innermost) return false;
  let root: Node = innermost.getExpression();
  while (Node.isPropertyAccessExpression(root) || Node.isCallExpression(root)) root = root.getExpression();
  if (Node.isIdentifier(root) && SERVICE_CLIENT.test(root.getText())) return true;
  let resolved = resolveExpression(root);
  if (Node.isAwaitExpression(resolved)) resolved = resolved.getExpression();
  return Node.isCallExpression(resolved) && (/SERVICE_ROLE|sb_secret/i.test(resolved.getText()) || SERVICE_CLIENT.test(calleeName(resolved)));
}

export const authz003: Rule = {
  id: 'AUTHZ-003',
  title: 'IDOR: record fetched by a request-controlled id',
  category: 'authorization',
  severity: 'high',
  confidence: 'medium',
  stacks: ['nextjs-app-router'],
  description:
    'In handlers and server actions that authenticate the user, reports queries that select a row by an id taken from the ' +
    "request (Supabase .eq('id', x) or .match({ id: x }), Prisma where: { id }) without an owner filter (user_id, owner_id, " +
    'author_id, ...). Supabase queries are skipped when migrations enable RLS on the table with an auth.uid() policy, unless ' +
    'the client was created with the service role key, which bypasses RLS. Limitations: RLS configured outside migrations ' +
    'is invisible, and ownership checks done after the query are not recognised.',
  explanation:
    'A signed-in user can change the id in the URL or request and read or modify another user’s record, because nothing ' +
    'ties the row to the person asking for it.',
  fix:
    "Filter by owner as well, for example `.eq('id', id).eq('user_id', user.id)`, and enable RLS with a policy such as " +
    '`using ((select auth.uid()) = user_id)` so the database enforces it too.',
  falsePositiveNote: 'RLS policies created in the Supabase dashboard rather than in migrations are invisible to this rule.',
  cwe: 'CWE-639',
  references: [
    'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
    'https://supabase.com/docs/guides/database/postgres/row-level-security',
  ],
  run(ctx) {
    const model = sqlModel(ctx);
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      if (!hasAuthCheck(entry.node, ctx)) continue;
      for (const call of calls(entry.node)) {
        const name = calleeName(call);
        const fn = entryFunctionOf(call);
        const [first, second] = call.getArguments();

        if (name === 'eq' || name === 'match') {
          const idValue = name === 'eq' ? (stringLiteral(first) === 'id' ? second : undefined) : objectProperty(first, 'id');
          if (!idValue || !isUserInput(idValue, fn)) continue;
          const chain = chainCalls(chainTop(call));
          if (hasOwnerFilter(chain)) continue;
          const table = supabaseTable(chainTop(call));
          const rlsProtected = table !== undefined && model.rlsEnabled.has(table) && hasOwnerPolicy(model, table);
          if (rlsProtected && !usesServiceRole(chain)) continue;
          findings.push(findingAt(calleeNameNode(call)));
          continue;
        }

        const method = prismaMethod(call);
        if (method && PRISMA_BY_ID.has(method)) {
          const where = objectProperty(first, 'where');
          const id = objectProperty(where, 'id');
          if (!id || !isUserInput(id, fn)) continue;
          if (objectKeys(where).some((key) => OWNER_COLUMN.test(key))) continue;
          findings.push(findingAt(calleeNameNode(call)));
        }
      }
    }
    return findings;
  },
};
