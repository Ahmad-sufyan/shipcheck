import { Node, SyntaxKind, type SourceFile } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { findingAt, importBindings, importedCallName, objectProperty, sourceFiles } from '../analysis/ast-utils.js';

const IN_MEMORY_CLASS = /^(?:Map|WeakMap|LRUCache|LRU|QuickLRU|RateLimiterMemory|NodeCache|TTLCache)$/;
const LIMITER_NAME = /rate[-_]?limit|limiter|throttl/i;

/** Module-level variables holding limiter state in process memory. */
function memoryState(sourceFile: SourceFile, file: string): Node[] {
  const limiterFile = LIMITER_NAME.test(file) || sourceFile.getDescendants().some((n) => (Node.isFunctionDeclaration(n) || Node.isVariableDeclaration(n)) && LIMITER_NAME.test(n.getName() ?? ''));
  const found: Node[] = [];
  for (const statement of sourceFile.getVariableStatements()) {
    for (const declaration of statement.getDeclarations()) {
      const init = declaration.getInitializer();
      if (!init || !Node.isNewExpression(init)) continue;
      const className = init.getExpression().getText();
      if (className === 'RateLimiterMemory' || (IN_MEMORY_CLASS.test(className) && limiterFile)) found.push(declaration);
    }
  }
  const expressRateLimit = importBindings(sourceFile, ['express-rate-limit']);
  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const callee = call.getExpression();
    const defaultImport = Node.isIdentifier(callee) && expressRateLimit.namespaces.has(callee.getText());
    const named = importedCallName(call, expressRateLimit);
    if ((defaultImport || named === 'rateLimit' || named === 'default') && !objectProperty(call.getArguments()[0], 'store')) found.push(call);
  }
  return found;
}

export const rate003: Rule = {
  id: 'RATE-003',
  title: 'In-memory rate limiter on serverless',
  category: 'rate-limiting',
  severity: 'medium',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'On Vercel or Cloudflare projects, reports limiter state kept in process memory: module-level Map/LRU caches in ' +
    'rate-limit modules, RateLimiterMemory, and express-rate-limit without a store. Serverless instances do not share ' +
    'memory and are recycled often, so these limits barely apply.',
  explanation:
    'Each serverless instance keeps its own counter, and instances are created and discarded constantly, so an attacker ' +
    'spread across instances is effectively not rate limited at all.',
  fix: 'Keep limiter state in a shared store: @upstash/ratelimit with Redis, Vercel KV, or Cloudflare rate limiting / Durable Objects.',
  falsePositiveNote: 'Apps that run on a single long-lived server (self-hosted Node) are not affected; this rule only runs on Vercel and Cloudflare projects.',
  cwe: 'CWE-770',
  references: ['https://upstash.com/docs/redis/sdks/ratelimit-ts/overview', 'https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/'],
  run(ctx) {
    if (!ctx.stacks.has('vercel') && !ctx.stacks.has('cloudflare')) return [];
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => /new (?:Map|WeakMap|LRU|QuickLRU|RateLimiterMemory|NodeCache|TTLCache)|express-rate-limit/.test(text))) {
      for (const node of memoryState(ctx.getSourceFile(file), file)) findings.push(findingAt(node));
    }
    return findings;
  },
};
