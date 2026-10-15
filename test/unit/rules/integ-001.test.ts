import { describe, expect, it } from 'vitest';
import { integ001 as rule } from '../../../src/packs/nextjs-supabase/rules/integ-001-webhook-signature.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/webhooks/stripe/route.ts';
const post = (...body: string[]) => code('export async function POST(request: Request) {', ...body.map((l) => `  ${l}`), "  return Response.json({ received: true })", '}');

describe('INTEG-001 Webhook without signature verification', () => {
  it('reports a webhook route that never verifies the signature', async () => {
    expect(await runRule(rule, { [ROUTE]: post('const event = await request.json()', "if (event.type === 'invoice.paid') await markPaid(event.data.object.id)") })).toEqual([
      { file: ROUTE, line: 1, evidence: 'export async function POST(request: Request) {' },
    ]);
  });

  it('reports handlers that switch on event.type outside a webhooks path', async () => {
    const text = post('const event = await request.json()', 'switch (event.type) {', "  case 'charge.refunded': await refund(event.data.object.id)", '}');
    expect(await runRule(rule, { 'app/api/stripe-events/route.ts': text })).toHaveLength(1);
  });

  it('reports constructEvent on a re-serialised JSON body as high', async () => {
    const text = post("const event = stripe.webhooks.constructEvent(JSON.stringify(await request.json()), request.headers.get('stripe-signature')!, secret)");
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([expect.objectContaining({ line: 2, severity: 'high' })]);
  });

  it('accepts Stripe constructEvent on the raw body', async () => {
    const text = post('const payload = await request.text()', "const event = await stripe.webhooks.constructEventAsync(payload, request.headers.get('stripe-signature')!, secret)");
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([]);
  });

  it('accepts svix/standardwebhooks verify and HMAC with timingSafeEqual', async () => {
    const svix = post('const payload = await request.text()', 'const event = new Webhook(secret).verify(payload, Object.fromEntries(request.headers))');
    expect(await runRule(rule, { 'app/api/webhooks/clerk/route.ts': svix })).toEqual([]);
    const hmac = post(
      'const payload = await request.text()',
      "const expected = createHmac('sha256', secret).update(payload).digest()",
      "if (!timingSafeEqual(expected, Buffer.from(request.headers.get('x-signature') ?? '', 'hex'))) return new Response(null, { status: 401 })",
    );
    expect(await runRule(rule, { 'app/api/webhooks/github/route.ts': hmac })).toEqual([]);
  });

  it('accepts configured webhookVerifiers', async () => {
    const text = post('const event = await verifyPaddleWebhook(request)');
    expect(await runRule(rule, { 'app/api/webhooks/paddle/route.ts': text })).toHaveLength(1);
    expect(await runRule(rule, { 'app/api/webhooks/paddle/route.ts': text }, { webhookVerifiers: ['verifyPaddleWebhook'] })).toEqual([]);
  });
});
