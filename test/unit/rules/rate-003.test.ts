import { describe, expect, it } from 'vitest';
import { rate003 as rule } from '../../../src/packs/nextjs-supabase/rules/rate-003-memory-limiter.js';
import { code, runRule } from '../../helpers/memory-context.js';

const limiter = code('const hits = new Map<string, number>()', 'export function rateLimit(key: string) {', '  hits.set(key, (hits.get(key) ?? 0) + 1)', '  return (hits.get(key) ?? 0) <= 5', '}');
const vercel = { 'vercel.json': '{}' };

describe('RATE-003 In-memory limiter on serverless', () => {
  it('reports module-level limiter state on Vercel', async () => {
    expect(await runRule(rule, { 'lib/rate-limit.ts': limiter, ...vercel })).toEqual([{ file: 'lib/rate-limit.ts', line: 1, evidence: 'const hits = new Map<string, number>()' }]);
  });

  it('reports lru-cache and RateLimiterMemory on Cloudflare, and express-rate-limit without a store', async () => {
    const lru = code("import { LRUCache } from 'lru-cache'", 'const tokens = new LRUCache<string, number>({ max: 500 })', 'export const limiter = (ip: string) => tokens.get(ip)');
    expect(await runRule(rule, { 'lib/limit.ts': lru, 'wrangler.toml': 'name = "x"' })).toEqual([expect.objectContaining({ line: 2 })]);
    expect(await runRule(rule, { 'lib/limit.ts': code("import { RateLimiterMemory } from 'rate-limiter-flexible'", 'export const limiter = new RateLimiterMemory({ points: 5, duration: 60 })'), ...vercel })).toHaveLength(1);
    expect(await runRule(rule, { 'lib/limit.ts': code("import rateLimit from 'express-rate-limit'", 'export const limiter = rateLimit({ windowMs: 60000, limit: 100 })'), ...vercel })).toHaveLength(1);
  });

  it('ignores the same code outside serverless platforms', async () => {
    expect(await runRule(rule, { 'lib/rate-limit.ts': limiter })).toEqual([]);
  });

  it('ignores shared stores and unrelated maps', async () => {
    const upstash = code("import { Ratelimit } from '@upstash/ratelimit'", 'const ratelimit = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(5, "1 m") })');
    expect(await runRule(rule, { 'lib/rate-limit.ts': upstash, ...vercel })).toEqual([]);
    expect(await runRule(rule, { 'lib/i18n.ts': code('const messages = new Map<string, string>()', 'export const t = (k: string) => messages.get(k)'), ...vercel })).toEqual([]);
  });
});
