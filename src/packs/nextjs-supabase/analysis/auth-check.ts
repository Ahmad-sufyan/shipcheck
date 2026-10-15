import { Node } from 'ts-morph';
import type { ScanContext } from '../../../types.js';
import { calleeName, calleeText, calls, declarationOf, isFunctionNode } from './ast-utils.js';
import { isCoveredByMatchers, matchesGlob } from './route-match.js';

/**
 * Calls that verify the user on the server. supabase.auth.getSession() is deliberately absent:
 * Supabase documents that its result must not be trusted in server code (use getClaims or getUser).
 */
const SUPABASE_AUTH = /(?:^|\.)auth\.(?:getUser|getClaims)$/;
const AUTH_FUNCTIONS = new Set(['auth', 'getServerSession', 'currentUser', 'getAuth']);
const AUTH_METHODS = new Set(['auth.protect']);
const AUTH_WRAPPER = /^with(?:Auth|Session|User|ApiAuth|Authentication|Authorization|PageAuthRequired|ApiAuthRequired)/i;
const MAX_DEPTH = 3;

function isConfiguredHelper(name: string, text: string, ctx: ScanContext): boolean {
  return ctx.config.authHelpers.includes(name) || ctx.config.authHelpers.includes(text);
}

/** Whether a single call is itself an auth check. */
export function isAuthCall(call: Node, ctx: ScanContext): boolean {
  if (!Node.isCallExpression(call)) return false;
  const text = calleeText(call);
  const name = calleeName(call);
  if (SUPABASE_AUTH.test(text) || AUTH_METHODS.has(text) || isConfiguredHelper(name, text, ctx)) return true;
  return Node.isIdentifier(call.getExpression()) && AUTH_FUNCTIONS.has(name);
}

/** The function body a same-file call resolves to, if any. */
export function localFunctionTarget(call: Node): Node | undefined {
  if (!Node.isCallExpression(call)) return undefined;
  const callee = call.getExpression();
  if (!Node.isIdentifier(callee)) return undefined;
  const declaration = declarationOf(callee);
  if (!declaration || declaration.getSourceFile() !== call.getSourceFile()) return undefined;
  if (Node.isFunctionDeclaration(declaration)) return declaration;
  if (Node.isVariableDeclaration(declaration)) {
    const initializer = declaration.getInitializer();
    if (initializer && isFunctionNode(initializer)) return initializer;
  }
  return undefined;
}

/**
 * Whether `fn` (a handler function or a wrapper call such as `withAuth(handler)`) authenticates the
 * caller: supabase.auth.getUser()/getClaims(), Auth.js auth(), getServerSession(), Clerk
 * auth()/currentUser()/auth.protect(), configured authHelpers, or a same-file function that does.
 */
export function hasAuthCheck(fn: Node, ctx: ScanContext, depth = 0, seen: Set<Node> = new Set()): boolean {
  if (seen.has(fn) || depth > MAX_DEPTH) return false;
  seen.add(fn);
  if (Node.isCallExpression(fn)) {
    const name = calleeName(fn);
    if (AUTH_WRAPPER.test(name) || isAuthCall(fn, ctx)) return true;
  }
  for (const call of calls(fn)) {
    if (isAuthCall(call, ctx)) return true;
    const target = localFunctionTarget(call);
    if (target && hasAuthCheck(target, ctx, depth + 1, seen)) return true;
  }
  return false;
}

/** Whether the function only reads the session with getSession(), which is not a server-side check. */
export function usesOnlyGetSession(fn: Node, ctx: ScanContext): boolean {
  return !hasAuthCheck(fn, ctx) && calls(fn).some((call) => /(?:^|\.)auth\.getSession$/.test(calleeText(call)));
}

/** The exported proxy/middleware function (or wrapper call), if it can be found. */
export function middlewareFunction(ctx: ScanContext, file: string): Node | undefined {
  const sourceFile = ctx.getSourceFile(file);
  for (const fn of sourceFile.getFunctions()) {
    if (fn.isDefaultExport() || (fn.isExported() && ['proxy', 'middleware'].includes(fn.getName() ?? ''))) return fn;
  }
  for (const statement of sourceFile.getVariableStatements()) {
    if (!statement.isExported()) continue;
    for (const declaration of statement.getDeclarations()) {
      if (['proxy', 'middleware'].includes(declaration.getName())) return declaration.getInitializer();
    }
  }
  for (const assignment of sourceFile.getExportAssignments()) {
    const expression = assignment.getExpression();
    if (Node.isIdentifier(expression)) {
      const declaration = declarationOf(expression);
      if (declaration && Node.isVariableDeclaration(declaration)) return declaration.getInitializer();
      if (declaration) return declaration;
    }
    return expression;
  }
  return undefined;
}

/** Whether the proxy both verifies the user and turns unauthenticated requests away. */
function middlewareBlocks(fn: Node, ctx: ScanContext): boolean {
  if (calls(fn).some((call) => calleeName(call) === 'updateSession')) return true;
  if (!hasAuthCheck(fn, ctx)) return false;
  const text = fn.getText();
  return /\.redirect\(|\.rewrite\(|status:\s*40[13]|auth\.protect\(|Unauthorized/.test(text);
}

/** Whether the project has a proxy/middleware that verifies the user and blocks unauthenticated requests. */
export function middlewareChecksAuth(ctx: ScanContext): boolean {
  const middleware = ctx.next.middleware();
  const fn = middleware ? middlewareFunction(ctx, middleware.file) : undefined;
  return fn !== undefined && middlewareBlocks(fn, ctx);
}

/** Whether an auth-checking proxy/middleware runs for `routePath`. */
export function middlewareAuthCovers(routePath: string, ctx: ScanContext): boolean {
  const middleware = ctx.next.middleware();
  if (!middleware) return false;
  const fn = middlewareFunction(ctx, middleware.file);
  if (!fn || !middlewareBlocks(fn, ctx)) return false;
  return isCoveredByMatchers(routePath, middleware.matchers);
}

/** Route segments that are public by design: sign-in flows, OAuth, webhooks, cron and health checks. */
const PUBLIC_SEGMENTS = new Set([
  'login',
  'log-in',
  'signin',
  'sign-in',
  'signup',
  'sign-up',
  'register',
  'logout',
  'log-out',
  'signout',
  'sign-out',
  'password-reset',
  'reset-password',
  'forgot-password',
  'callback',
  'oauth',
  'auth',
  'webhook',
  'webhooks',
  'cron',
  'health',
  'healthz',
]);

/** Whether a route is meant to be reachable without a session (built-in list plus config.publicPaths). */
export function isIntentionallyPublic(routePath: string, ctx: ScanContext): boolean {
  if (ctx.config.publicPaths.some((glob) => matchesGlob(routePath, glob))) return true;
  return routePath
    .toLowerCase()
    .split('/')
    .some((segment) => PUBLIC_SEGMENTS.has(segment));
}
