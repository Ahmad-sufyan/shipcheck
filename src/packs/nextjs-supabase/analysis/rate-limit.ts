import { Node } from 'ts-morph';
import type { ScanContext } from '../../../types.js';
import { calleeName, calleeText, calls, receiverOf, resolveExpression } from './ast-utils.js';
import { localFunctionTarget, middlewareFunction } from './auth-check.js';
import { isCoveredByMatchers } from './route-match.js';

const LIMITER_FUNCTION = /rate[-_]?limit|throttl/i;
const LIMITER_OBJECT = /rate[-_]?limit|limiter|throttl/i;
const LIMITER_METHODS = new Set(['limit', 'consume', 'check', 'hit', 'take', 'blockEffective']);
const LIMITER_CLASS = /Ratelimit|RateLimiter/;
const MAX_DEPTH = 3;

function isLimiterCall(call: Node, ctx: ScanContext): boolean {
  if (!Node.isCallExpression(call)) return false;
  const name = calleeName(call);
  const text = calleeText(call);
  if (ctx.config.rateLimitHelpers.includes(name) || ctx.config.rateLimitHelpers.includes(text)) return true;
  if (LIMITER_FUNCTION.test(name)) return true;
  if (!LIMITER_METHODS.has(name)) return false;
  const receiver = receiverOf(call);
  if (!receiver || !Node.isIdentifier(receiver)) return false;
  if (LIMITER_OBJECT.test(receiver.getText())) return true;
  const resolved = resolveExpression(receiver);
  return Node.isNewExpression(resolved) && LIMITER_CLASS.test(resolved.getExpression().getText());
}

function limitsDirectly(fn: Node, ctx: ScanContext, depth: number, seen: Set<Node>): boolean {
  if (seen.has(fn) || depth > MAX_DEPTH) return false;
  seen.add(fn);
  if (Node.isCallExpression(fn) && isLimiterCall(fn, ctx)) return true;
  for (const call of calls(fn)) {
    if (isLimiterCall(call, ctx)) return true;
    const target = localFunctionTarget(call);
    if (target && limitsDirectly(target, ctx, depth + 1, seen)) return true;
  }
  return false;
}

/**
 * Whether `fn` is rate limited: `.limit()` on an @upstash/ratelimit instance (or any limiter-named
 * object), calls to rateLimit-like functions or configured rateLimitHelpers, a same-file helper that
 * does so, or a proxy/middleware covering `routePath` that does so.
 */
export function hasRateLimit(fn: Node, ctx: ScanContext, routePath?: string): boolean {
  if (limitsDirectly(fn, ctx, 0, new Set())) return true;
  if (routePath === undefined) return false;
  const middleware = ctx.next.middleware();
  if (!middleware || !isCoveredByMatchers(routePath, middleware.matchers)) return false;
  const proxy = middlewareFunction(ctx, middleware.file);
  return proxy !== undefined && limitsDirectly(proxy, ctx, 0, new Set());
}
