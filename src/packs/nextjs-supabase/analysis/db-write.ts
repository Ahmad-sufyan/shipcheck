import { Node, SyntaxKind, type CallExpression, type TaggedTemplateExpression } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import { calleeName, calleeText, receiverOf, staticText, stringLiteral } from './ast-utils.js';

const SUPABASE_WRITES = new Set(['insert', 'update', 'upsert', 'delete']);
const PRISMA_WRITES = new Set(['create', 'createMany', 'createManyAndReturn', 'update', 'updateMany', 'updateManyAndReturn', 'upsert', 'delete', 'deleteMany']);
const PRISMA_READS = new Set(['findMany', 'findUnique', 'findUniqueOrThrow', 'findFirst', 'findFirstOrThrow', 'count', 'aggregate', 'groupBy']);
const MONGO_WRITES = new Set(['insertOne', 'insertMany', 'updateOne', 'updateMany', 'replaceOne', 'deleteOne', 'deleteMany', 'findOneAndUpdate', 'findOneAndReplace', 'findOneAndDelete', 'bulkWrite']);
const MONGO_READS = new Set(['find', 'findOne', 'aggregate', 'countDocuments', 'distinct']);
const SQL_METHODS = new Set(['query', 'execute', 'exec', 'raw', 'unsafe', 'sql', 'run', '$executeRaw', '$executeRawUnsafe', '$queryRaw', '$queryRawUnsafe']);
const SQL_WRITE = /^\s*(?:insert|update|delete|merge|upsert)\b/i;
const SQL_ANY = /^\s*(?:select|insert|update|delete|merge|upsert|with)\b/i;
const PRISMA_CLIENT = /prisma|^db$|^tx$|^client$/i;
const DRIZZLE_CLIENT = /^(?:db|tx|trx|database)$/;
const FS_FUNCTIONS = new Set([
  'readFile',
  'readFileSync',
  'writeFile',
  'writeFileSync',
  'appendFile',
  'appendFileSync',
  'unlink',
  'unlinkSync',
  'rm',
  'rmSync',
  'readdir',
  'readdirSync',
  'mkdir',
  'mkdirSync',
  'copyFile',
  'rename',
  'createReadStream',
  'createWriteStream',
  'open',
  'stat',
  'access',
]);
const FS_RECEIVER = /(?:^|\.)(?:fs|fsp|promises|fsPromises)$/;
const HTTP_CLIENT = /^(?:axios|got|ky|superagent|undici)(?:\.(?:get|post|put|patch|delete|head|request|fetch))?$/;

/** The call itself plus every call further down its method chain (`a.from().update().eq()` -> eq, update, from). */
export function chainCalls(call: CallExpression): CallExpression[] {
  const chain: CallExpression[] = [];
  let current: Node = call;
  for (;;) {
    current = unwrapExpression(current);
    if (Node.isAwaitExpression(current)) current = current.getExpression();
    if (Node.isCallExpression(current)) {
      chain.push(current);
      current = current.getExpression();
    } else if (Node.isPropertyAccessExpression(current) || Node.isElementAccessExpression(current)) {
      current = current.getExpression();
    } else {
      return chain;
    }
  }
}

function isSupabaseChain(chain: CallExpression[]): boolean {
  return chain.some((c) => calleeName(c) === 'from') && !chain.some((c) => calleeText(c).includes('storage.'));
}

/** `prisma.user.create()` style: client.model.method() */
function prismaMethod(call: CallExpression): string | undefined {
  const callee = unwrapExpression(call.getExpression());
  if (!Node.isPropertyAccessExpression(callee)) return undefined;
  const model = unwrapExpression(callee.getExpression());
  if (!Node.isPropertyAccessExpression(model)) return undefined;
  const client = unwrapExpression(model.getExpression());
  const clientName = Node.isIdentifier(client) ? client.getText() : Node.isPropertyAccessExpression(client) ? client.getName() : '';
  return PRISMA_CLIENT.test(clientName) ? callee.getName() : undefined;
}

function sqlTextOf(call: CallExpression): string | undefined {
  return SQL_METHODS.has(calleeName(call)) ? staticText(call.getArguments()[0]) : undefined;
}

function isSqlTag(node: TaggedTemplateExpression): boolean {
  return /(?:^|\.)sql$/i.test(node.getTag().getText());
}

/** Supabase insert/update/upsert/delete, Prisma and Mongo writes, Drizzle db.insert/update/delete, and INSERT/UPDATE/DELETE SQL strings. */
export function isDbWrite(node: CallExpression | TaggedTemplateExpression): boolean {
  if (Node.isTaggedTemplateExpression(node)) return isSqlTag(node) && SQL_WRITE.test(staticText(node.getTemplate()) ?? '');
  const chain = chainCalls(node);
  if (isSupabaseChain(chain) && chain.some((c) => SUPABASE_WRITES.has(calleeName(c)))) return true;
  for (const call of chain) {
    const name = calleeName(call);
    const prisma = prismaMethod(call);
    if (prisma && PRISMA_WRITES.has(prisma)) return true;
    if (MONGO_WRITES.has(name)) return true;
    const receiver = receiverOf(call);
    if (receiver && Node.isIdentifier(receiver) && DRIZZLE_CLIENT.test(receiver.getText()) && SUPABASE_WRITES.has(name)) return true;
    if (SQL_WRITE.test(sqlTextOf(call) ?? '')) return true;
  }
  return false;
}

/** Any database read or write, including Supabase storage and RPC calls. */
export function isDbCall(node: CallExpression | TaggedTemplateExpression): boolean {
  if (Node.isTaggedTemplateExpression(node)) return isSqlTag(node);
  if (isDbWrite(node)) return true;
  const chain = chainCalls(node);
  for (const call of chain) {
    const name = calleeName(call);
    if (name === 'from' || name === 'rpc') return true;
    const prisma = prismaMethod(call);
    if (prisma && PRISMA_READS.has(prisma)) return true;
    if (SQL_ANY.test(sqlTextOf(call) ?? '')) return true;
    if (MONGO_READS.has(name) && isMongoCollection(receiverOf(call))) return true;
  }
  return false;
}

/** Heuristic: the receiver came from `.collection(...)`/`getCollection(...)` or is named like a collection. */
export function isMongoCollection(receiver: Node | undefined): boolean {
  if (!receiver) return false;
  let node: Node = unwrapExpression(receiver);
  if (Node.isIdentifier(node)) {
    if (/collection/i.test(node.getText())) return true;
    const declaration = node.getSourceFile().getDescendantsOfKind(SyntaxKind.VariableDeclaration).find((d) => d.getName() === node.getText());
    const initializer = declaration?.getInitializer();
    if (!initializer) return false;
    node = unwrapExpression(initializer);
    if (Node.isAwaitExpression(node)) node = node.getExpression();
  }
  return Node.isCallExpression(node) && /collection/i.test(calleeName(node));
}

/** Supabase table name from `.from('table')` in the call's chain (not storage buckets). */
export function supabaseTable(call: CallExpression | TaggedTemplateExpression): string | undefined {
  if (Node.isTaggedTemplateExpression(call)) return undefined;
  const chain = chainCalls(call);
  if (!isSupabaseChain(chain)) return undefined;
  const from = chain.find((c) => calleeName(c) === 'from');
  return stringLiteral(from?.getArguments()[0]);
}

export function isFsCall(call: CallExpression): boolean {
  const name = calleeName(call);
  if (!FS_FUNCTIONS.has(name)) return false;
  const receiver = receiverOf(call);
  if (receiver) return FS_RECEIVER.test(calleeText(call).slice(0, -(name.length + 1)));
  return !['open', 'stat', 'access', 'rm'].includes(name);
}

export function isHttpCall(call: CallExpression): boolean {
  const text = calleeText(call);
  return text === 'fetch' || HTTP_CLIENT.test(text);
}

export interface DataAccess {
  db: boolean;
  fs: boolean;
  fetch: boolean;
  write: boolean;
}

/** What kinds of data a function (including nested callbacks) touches. */
export function touchesData(fn: Node): DataAccess {
  const access: DataAccess = { db: false, fs: false, fetch: false, write: false };
  for (const node of fn.getDescendants()) {
    if (Node.isTaggedTemplateExpression(node) && isSqlTag(node)) {
      access.db = true;
      if (isDbWrite(node)) access.write = true;
    }
    if (!Node.isCallExpression(node)) continue;
    if (isDbWrite(node)) access.db = access.write = true;
    else if (isDbCall(node)) access.db = true;
    if (isFsCall(node)) access.fs = true;
    if (isHttpCall(node)) access.fetch = true;
  }
  return access;
}
