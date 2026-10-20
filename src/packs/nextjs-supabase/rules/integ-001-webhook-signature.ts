import { Node, type CallExpression } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, Rule, ScanContext } from '../../../types.js';
import { calleeName, calleeNameNode, calleeText, calls, findingAt, receiverOf, resolveExpression } from '../analysis/ast-utils.js';
import { localFunctionTarget } from '../analysis/auth-check.js';
import { entries, MUTATING_METHODS } from '../analysis/entries.js';

const WEBHOOK_PATH = /(?:^|\/)webhooks?(?:\/|$)/i;
const EVENT_TYPE = /\bevent\.type\b/;
const STRIPE_VERIFY = new Set(['constructEvent', 'constructEventAsync']);

/** `new Webhook(secret).verify(...)` (svix / standardwebhooks) or `wh.verify(...)` on such an instance. */
function isSvixVerify(call: CallExpression): boolean {
  if (calleeName(call) !== 'verify') return false;
  const receiver = receiverOf(call);
  if (!receiver) return false;
  let target = unwrapExpression(receiver);
  if (Node.isIdentifier(target)) target = resolveExpression(target);
  return Node.isNewExpression(target) && /Webhook$/.test(target.getExpression().getText());
}

interface Verification {
  verified: boolean;
  /** constructEvent called on JSON.stringify(await request.json()) instead of the raw body. */
  reserialized?: CallExpression;
}

function verification(fn: Node, ctx: ScanContext, depth = 0): Verification {
  const found = calls(fn);
  const names = new Set(found.map(calleeName));
  for (const call of found) {
    if (STRIPE_VERIFY.has(calleeName(call))) {
      const payload = call.getArguments()[0];
      return payload && /JSON\.stringify\(/.test(payload.getText()) ? { verified: true, reserialized: call } : { verified: true };
    }
    if (isSvixVerify(call) || ctx.config.webhookVerifiers.includes(calleeName(call)) || ctx.config.webhookVerifiers.includes(calleeText(call))) return { verified: true };
  }
  if (names.has('createHmac') && names.has('timingSafeEqual')) return { verified: true };
  if (depth < 3) {
    for (const call of found) {
      const target = localFunctionTarget(call);
      const nested = target ? verification(target, ctx, depth + 1) : undefined;
      if (nested?.verified) return nested;
    }
  }
  return { verified: false };
}

export const integ001: Rule = {
  id: 'INTEG-001',
  title: 'Webhook without signature verification',
  category: 'integrations',
  severity: 'critical',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports mutating route handlers under a /webhook(s) path, or that branch on event.type, which never call ' +
    'stripe.webhooks.constructEvent(Async), a svix/standardwebhooks Webhook.verify, createHmac together with ' +
    'timingSafeEqual, or a function listed in config.webhookVerifiers (directly or in a same-file helper). constructEvent ' +
    'on JSON.stringify(await request.json()) is reported as high, because re-serialised JSON never matches the signature.',
  explanation:
    'Anyone can POST a fake event to this endpoint (for example "checkout.session.completed") and the app will act on it ' +
    'as if the payment provider had sent it.',
  fix:
    "Read the raw body with `await request.text()` and verify it: `stripe.webhooks.constructEvent(body, request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET)`; reject the request when verification throws.",
  falsePositiveNote: 'Verification done in a helper imported from another module should be listed in config.webhookVerifiers.',
  cwe: 'CWE-345',
  references: ['https://docs.stripe.com/webhooks#verify-official-libraries', 'https://docs.svix.com/receiving/verifying-payloads/how'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      if (entry.kind !== 'route' || !MUTATING_METHODS.has(entry.method ?? '')) continue;
      if (!WEBHOOK_PATH.test(entry.routePath ?? '') && !EVENT_TYPE.test(entry.node.getText())) continue;
      const result = verification(entry.node, ctx);
      if (!result.verified) {
        findings.push(findingAt(entry.node));
      } else if (result.reserialized) {
        findings.push(
          findingAt(calleeNameNode(result.reserialized), {
            severity: 'high',
            explanation:
              'The signature is checked against JSON.stringify(await request.json()), which never matches the bytes the provider signed, so verification fails for real events and tends to get disabled or bypassed.',
          }),
        );
      }
    }
    return findings;
  },
};
