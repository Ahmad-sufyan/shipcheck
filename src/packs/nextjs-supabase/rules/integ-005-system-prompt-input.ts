import { SyntaxKind } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { findingAt, objectProperty, sourceFiles, stringLiteral } from '../analysis/ast-utils.js';
import { entryFunctionOf, isUserInput } from '../analysis/taint.js';

export const integ005: Rule = {
  id: 'INTEG-005',
  title: 'User input in the system prompt',
  category: 'integrations',
  severity: 'medium',
  confidence: 'medium',
  advisory: true,
  stacks: ['nextjs-app-router'],
  description:
    "Reports { role: 'system', content } messages and `system:` parameters (AI SDK, Anthropic) whose value is built from " +
    'request input in a route handler or server action. Schema-validated strings still count as input here, because a ' +
    'valid string can still carry instructions. Advisory: values constrained to an enum or allowlist are fine.',
  explanation:
    'Text supplied by the user becomes part of the instructions the model treats as most trusted, which makes prompt ' +
    'injection easier: the user can override your rules or extract the hidden prompt.',
  fix: 'Keep system prompts constant (or chosen from an allowlist), pass user text only in user messages, and delimit it clearly.',
  falsePositiveNote: 'Inputs restricted to a fixed set of values (z.enum) before reaching the prompt are not a risk.',
  cwe: 'CWE-1427',
  references: ['https://genai.owasp.org/llmrisk/llm01-prompt-injection/'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => text.includes('system'))) {
      for (const object of ctx.getSourceFile(file).getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
        const role = stringLiteral(objectProperty(object, 'role'));
        const value = role === 'system' ? objectProperty(object, 'content') : role === undefined ? objectProperty(object, 'system') : undefined;
        if (value && isUserInput(value, entryFunctionOf(value), { trustSchemas: false })) findings.push(findingAt(value));
      }
    }
    return findings;
  },
};
