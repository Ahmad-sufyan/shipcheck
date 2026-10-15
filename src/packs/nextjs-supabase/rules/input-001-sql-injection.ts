import { Node, SyntaxKind } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeNameNode, calleeText, calls, findingAt, receiverOf, resolveExpression, sourceFiles } from '../analysis/ast-utils.js';
import { entryFunctionOf, isUserInput } from '../analysis/taint.js';

/** Methods that always take raw SQL. */
const RAW_SQL_METHODS = new Set(['unsafe', '$queryRawUnsafe', '$executeRawUnsafe', 'raw']);
/** Methods that take SQL when called on a database client. */
const QUERY_METHODS = new Set(['query', 'execute', 'exec', 'run', 'all']);
const DB_RECEIVER = /(?:^|\.)(?:pool|client|db|conn|connection|pg|sql|knex|mysql|tx|trx|sequelize|database|prisma)$/i;
const SQL_TEXT = /^\s*\(?\s*(?:select|insert|update|delete|with|merge|upsert|create|drop|alter)\b/i;
/** PostgREST filter strings: an injected value can add filters or OR clauses. */
const SUPABASE_FILTER_STRINGS = new Set(['or', 'filter']);

/** The string-building expression behind an argument: a template or concatenation, following one variable. */
function builtString(arg: Node): Node | undefined {
  const node = unwrapExpression(arg);
  const resolved = Node.isIdentifier(node) ? resolveExpression(node) : node;
  if (Node.isTemplateExpression(resolved)) return resolved;
  if (Node.isBinaryExpression(resolved) && resolved.getOperatorToken().getKind() === SyntaxKind.PlusToken) return resolved;
  return undefined;
}

function leadingText(node: Node): string {
  if (Node.isTemplateExpression(node)) return node.getHead().getLiteralText();
  let current: Node = node;
  while (Node.isBinaryExpression(current)) current = current.getLeft();
  return Node.isStringLiteral(current) || Node.isNoSubstitutionTemplateLiteral(current) ? current.getLiteralValue() : '';
}

export const input001: Rule = {
  id: 'INPUT-001',
  title: 'SQL injection',
  category: 'input-validation',
  severity: 'critical',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports SQL text built with a template literal or string concatenation that includes request data (body, query, params, ' +
    'headers, cookies, server action arguments) and is passed to query()/execute() on a database client, sql.unsafe(), ' +
    "Prisma $queryRawUnsafe/$executeRawUnsafe, knex.raw/sql.raw, or Supabase .or()/.filter() strings. Tagged sql`` templates " +
    'are parameterised and safe. Limitations: SQL assembled in helpers in other files is not followed.',
  explanation:
    'Request data is pasted into a SQL statement, so an attacker can change the query: read other users’ data, bypass ' +
    'filters or modify and delete rows.',
  fix:
    'Use parameters instead of string building, for example `pool.query(\'select * from posts where id = $1\', [id])`, a ' +
    'tagged sql`` template, or Supabase query builder methods such as .eq() and .ilike() instead of raw filter strings.',
  falsePositiveNote: 'Strings built only from constants are not reported; values validated against a strict allowlist in a helper may still be.',
  cwe: 'CWE-89',
  references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx)) {
      for (const call of calls(ctx.getSourceFile(file))) {
        const name = calleeName(call);
        const args = call.getArguments();
        const candidates: Node[] = [];
        if (RAW_SQL_METHODS.has(name) && receiverOf(call)) candidates.push(...args.slice(0, 1));
        else if (SUPABASE_FILTER_STRINGS.has(name) && receiverOf(call) && Node.isCallExpression(receiverOf(call)!)) candidates.push(...args);
        else if (QUERY_METHODS.has(name)) {
          const first = args[0];
          const built = first ? builtString(first) : undefined;
          const receiver = calleeText(call).slice(0, -(name.length + 1));
          if (first && built && (DB_RECEIVER.test(receiver) || SQL_TEXT.test(leadingText(built)))) candidates.push(first);
        }
        const fn = entryFunctionOf(call);
        const injected = candidates.some((arg) => {
          const built = builtString(arg);
          return built !== undefined && isUserInput(built, fn);
        });
        if (injected) findings.push(findingAt(calleeNameNode(call)));
      }
    }
    return findings;
  },
};
