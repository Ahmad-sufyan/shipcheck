import { Node, type CallExpression } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeNameNode, calls, findingAt, objectProperty, resolveExpression, type FunctionNode } from '../analysis/ast-utils.js';
import { chainCalls, isSupabaseChain, prismaMethod, supabaseTable } from '../analysis/db-write.js';
import { entries } from '../analysis/entries.js';
import { entryFunctionOf, isUserInput } from '../analysis/taint.js';

const SUPABASE_PAYLOAD = new Set(['insert', 'update', 'upsert']);
const PRISMA_PAYLOAD: Record<string, string[]> = {
  create: ['data'],
  createMany: ['data'],
  update: ['data'],
  updateMany: ['data'],
  upsert: ['create', 'update'],
};
const SENSITIVE_TABLE = /^(?:users?|profiles?|accounts?|members?)$/i;

/** A whole request object written through: the tainted value itself, or a spread of it into an object literal. */
function massAssigned(payload: Node, fn: FunctionNode | undefined): boolean {
  const node = unwrapExpression(payload);
  const resolved = Node.isIdentifier(node) ? resolveExpression(node) : node;
  if (Node.isObjectLiteralExpression(resolved)) {
    return resolved.getProperties().some((p) => Node.isSpreadAssignment(p) && isUserInput(p.getExpression(), fn));
  }
  if (Node.isArrayLiteralExpression(resolved)) return resolved.getElements().some((element) => massAssigned(element, fn));
  return isUserInput(node, fn);
}

/** The written payloads of a call and the table/model it writes to. */
function payloadsOf(call: CallExpression): { payloads: Node[]; table: string | undefined } | undefined {
  const name = calleeName(call);
  const [first] = call.getArguments();
  if (SUPABASE_PAYLOAD.has(name) && first) {
    return isSupabaseChain(chainCalls(call)) ? { payloads: [first], table: supabaseTable(call) } : undefined;
  }
  const method = prismaMethod(call);
  const keys = method ? PRISMA_PAYLOAD[method] : undefined;
  if (keys) {
    const callee = call.getExpression();
    const model = Node.isPropertyAccessExpression(callee) && Node.isPropertyAccessExpression(callee.getExpression()) ? callee.getExpression() : undefined;
    const modelName = model && Node.isPropertyAccessExpression(model) ? model.getName() : undefined;
    return { payloads: keys.flatMap((key) => objectProperty(first, key) ?? []), table: modelName };
  }
  return undefined;
}

export const authz008: Rule = {
  id: 'AUTHZ-008',
  title: 'Mass assignment',
  category: 'authorization',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports Supabase insert/update/upsert and Prisma create/update/upsert calls in route handlers and server actions whose ' +
    'payload is the request body or server action input as a whole (or spreads it), instead of named fields. Writes to ' +
    'users, profiles, accounts or members tables are critical. Output of schema.parse()/safeParse() counts as sanitized. ' +
    'Limitations: payloads built by helpers in other files are not followed.',
  explanation:
    'Whatever fields the caller sends are written to the database, so a user can set columns you never meant to expose, ' +
    'such as role, is_admin, user_id or a price.',
  fix: 'Validate the input with a schema and write only named fields, for example `insert({ email: input.email, name: input.name })`.',
  falsePositiveNote: 'A body already validated by a strict schema in another file is still reported; pick fields explicitly to be safe.',
  cwe: 'CWE-915',
  references: ['https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      for (const call of calls(entry.node)) {
        const write = payloadsOf(call);
        if (!write) continue;
        const fn = entryFunctionOf(call);
        if (!write.payloads.some((payload) => massAssigned(payload, fn))) continue;
        findings.push(findingAt(calleeNameNode(call), SENSITIVE_TABLE.test(write.table ?? '') ? { severity: 'critical' } : {}));
      }
    }
    return findings;
  },
};
