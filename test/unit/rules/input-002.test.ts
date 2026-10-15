import { describe, expect, it } from 'vitest';
import { input002 as rule } from '../../../src/packs/nextjs-supabase/rules/input-002-nosql-injection.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/orders/route.ts';
const post = (...body: string[]) =>
  code("import { getCollection } from '@/lib/mongo'", 'export async function POST(request: Request) {', '  const body = await request.json()', "  const orders = await getCollection('orders')", ...body.map((l) => `  ${l}`), '}');

describe('INPUT-002 NoSQL injection', () => {
  it('reports a request body used as a Mongo filter', async () => {
    expect(await runRule(rule, { [ROUTE]: post('const found = await orders.find(body).toArray()') })).toEqual([
      { file: ROUTE, line: 5, evidence: 'const found = await orders.find(body).toArray()' },
    ]);
  });

  it('reports filters that spread request data and any $where', async () => {
    expect(await runRule(rule, { [ROUTE]: post('await orders.deleteMany({ ...body, archived: true })') })).toHaveLength(1);
    expect(await runRule(rule, { [ROUTE]: post("await orders.findOne({ $where: 'this.total > 100' })") })).toHaveLength(1);
  });

  it('reports Mongoose models in files that import mongoose', async () => {
    const text = code("import mongoose from 'mongoose'", 'export async function POST(request: Request) {', '  const body = await request.json()', '  return Response.json(await User.findOne(body))', '}');
    expect(await runRule(rule, { [ROUTE]: text })).toHaveLength(1);
  });

  it('ignores typed filters built from validated fields', async () => {
    expect(await runRule(rule, { [ROUTE]: post('const { status } = StatusSchema.parse(body)', 'await orders.find({ status, userId: user.id }).toArray()') })).toEqual([]);
  });

  it('ignores Array.prototype.find', async () => {
    expect(await runRule(rule, { [ROUTE]: post('const item = body.items.find((i: { id: string }) => i.id === body.id)') })).toEqual([]);
  });
});
