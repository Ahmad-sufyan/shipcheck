import { describe, expect, it } from 'vitest';
import { integ003 as rule } from '../../../src/packs/nextjs-supabase/rules/integ-003-client-price.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/checkout/route.ts';
const post = (...body: string[]) => code('export async function POST(request: Request) {', '  const body = await request.json()', ...body.map((l) => `  ${l}`), '}');

describe('INTEG-003 Client-trusted price or quantity', () => {
  it('reports a unit_amount taken from the request as critical', async () => {
    const text = post(
      'await stripe.checkout.sessions.create({',
      "  mode: 'payment',",
      "  line_items: [{ price_data: { currency: 'usd', product_data: { name: 'Pro' },",
      '    unit_amount: body.amount }, quantity: body.quantity }],',
      '})',
    );
    const findings = await runRule(rule, { [ROUTE]: text });
    expect(findings).toEqual([expect.objectContaining({ file: ROUTE, line: 6, evidence: 'unit_amount: body.amount }, quantity: body.quantity }],' })]);
    expect(findings[0]?.explanation).toMatch(/unit_amount.*quantity/);
  });

  it('reports a PaymentIntent amount from the request', async () => {
    expect(await runRule(rule, { [ROUTE]: post("await stripe.paymentIntents.create({ amount: body.total, currency: 'usd' })") })).toEqual([expect.objectContaining({ line: 3 })]);
  });

  it('reports a price id chosen by the client as medium', async () => {
    expect(await runRule(rule, { [ROUTE]: post("await stripe.checkout.sessions.create({ mode: 'payment', line_items: [{ price: body.priceId, quantity: 1 }] })") })).toEqual([
      expect.objectContaining({ severity: 'medium' }),
    ]);
  });

  it('ignores server-side price lookups with schema-bounded quantities', async () => {
    const text = code(
      "const PRICES = { pro: 'price_pro' } as const",
      'export async function POST(request: Request) {',
      '  const input = Schema.parse(await request.json())',
      "  await stripe.checkout.sessions.create({ mode: 'payment', line_items: [{ price: PRICES[input.plan], quantity: input.seats }] })",
      '}',
    );
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([]);
  });

  it('ignores constant amounts', async () => {
    expect(await runRule(rule, { [ROUTE]: post("await stripe.paymentIntents.create({ amount: 4900, currency: 'usd' })") })).toEqual([]);
  });
});
