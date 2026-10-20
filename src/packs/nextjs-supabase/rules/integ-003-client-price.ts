import { Node } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeText, calls, findingAt, objectProperty, resolveExpression, sourceFiles, type FunctionNode } from '../analysis/ast-utils.js';
import { entryFunctionOf, isUserInput } from '../analysis/taint.js';

const CHECKOUT = /(?:^|\.)checkout\.sessions\.create$/;
const PAYMENT_INTENT = /(?:^|\.)paymentIntents\.(?:create|update)$/;

interface Offender {
  name: string;
  value: Node;
  /** amount-like fields decide what the customer pays; price ids only pick from your catalogue. */
  kind: 'amount' | 'price';
}

function items(node: Node | undefined): Node[] {
  const array = node ? resolveExpression(node) : undefined;
  return array && Node.isArrayLiteralExpression(array) ? array.getElements() : [];
}

function offenders(args: Node | undefined, intent: boolean, fn: FunctionNode | undefined): Offender[] {
  const found: Offender[] = [];
  const check = (name: string, value: Node | undefined, kind: Offender['kind']) => {
    if (value && isUserInput(value, fn)) found.push({ name, value, kind });
  };
  if (intent) {
    check('amount', objectProperty(args, 'amount'), 'amount');
    return found;
  }
  for (const item of items(objectProperty(args, 'line_items'))) {
    const priceData = objectProperty(item, 'price_data');
    check('unit_amount', objectProperty(priceData, 'unit_amount'), 'amount');
    check('unit_amount_decimal', objectProperty(priceData, 'unit_amount_decimal'), 'amount');
    check('quantity', objectProperty(item, 'quantity'), 'amount');
    check('price', objectProperty(item, 'price'), 'price');
  }
  return found;
}

export const integ003: Rule = {
  id: 'INTEG-003',
  title: 'Client-trusted price or quantity',
  category: 'integrations',
  severity: 'critical',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports stripe.checkout.sessions.create and paymentIntents.create/update calls whose amount, line_items[].price_data.' +
    'unit_amount or line_items[].quantity come from the request (critical), or whose line_items[].price id does (medium). ' +
    'Schema-validated values and allowlist lookups are not request data. One finding per call, at the first such field. ' +
    'Limitations: line items built with .map() over request data are not followed.',
  explanation:
    'The browser decides how much is charged, so a customer can edit the request and pay one cent, or a negative or ' +
    'fractional quantity, for anything in your shop.',
  fix: 'Send only a product or plan key from the client, look the Stripe price up on the server, and bound quantities with a schema (for example z.number().int().min(1).max(10)).',
  falsePositiveNote: 'A quantity validated by a schema in another module is still reported; bound it where it is used.',
  cwe: 'CWE-602',
  references: ['https://docs.stripe.com/payments/checkout/how-checkout-works', 'https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => /checkout\.sessions|paymentIntents/.test(text))) {
      for (const call of calls(ctx.getSourceFile(file))) {
        const text = calleeText(call);
        const intent = PAYMENT_INTENT.test(text);
        if (!intent && !CHECKOUT.test(text)) continue;
        const found = offenders(call.getArguments()[0], intent, entryFunctionOf(call));
        if (!found.length) continue;
        const amount = found.find((o) => o.kind === 'amount');
        const first = amount ?? found[0]!;
        const fields = [...new Set(found.map((o) => o.name))].join(', ');
        findings.push(
          findingAt(first.value, {
            ...(amount ? {} : { severity: 'medium' as const }),
            explanation: `Stripe is called with ${fields} taken from the request, so the customer controls what they are charged. ${integ003.explanation}`,
          }),
        );
      }
    }
    return findings;
  },
};
