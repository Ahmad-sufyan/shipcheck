import { SyntaxKind } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeText, calls, findingAt } from '../analysis/ast-utils.js';
import { entries } from '../analysis/entries.js';
import { hasRateLimit } from '../analysis/rate-limit.js';

const AI_MODULES = /^(?:openai|@anthropic-ai\/sdk|ai|@ai-sdk\/[\w-]+|@google\/genai|@google\/generative-ai|groq-sdk|@mistralai\/mistralai|cohere-ai)$/;
const AI_METHODS = /(?:^|\.)(?:chat\.completions\.create|responses\.create|completions\.create|messages\.create|messages\.stream|generateContent|generateContentStream|embeddings\.create)$/;
const AI_SDK_FUNCTIONS = new Set(['generateText', 'streamText', 'generateObject', 'streamObject']);
const QUOTA = /usage|quota|credits?|budget|tokens?_?used|remaining/i;

export const rate002: Rule = {
  id: 'RATE-002',
  title: 'AI endpoint without rate limit or per-user cap',
  category: 'rate-limiting',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'In files that import an LLM SDK (openai, @anthropic-ai/sdk, ai, @ai-sdk/*, @google/genai, groq-sdk, ...), reports route ' +
    'handlers and server actions that call the model (chat.completions/responses/messages.create, generateContent, ' +
    'generateText/streamText/generateObject/streamObject) without a rate limiter and without any condition on usage, ' +
    'quota, credits or budget.',
  explanation:
    'Every call to this endpoint costs money, and nothing caps how often a user (or a script with one account) can call ' +
    'it, so a single person can run up a large bill or exhaust your provider limits.',
  fix: 'Add a per-user limiter (for example @upstash/ratelimit keyed by user id) and a token or credit budget checked before each model call.',
  falsePositiveNote: 'Spend caps configured in the provider dashboard limit the damage but are not visible to this rule.',
  cwe: 'CWE-770',
  references: ['https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      const sourceFile = entry.node.getSourceFile();
      if (!sourceFile.getImportDeclarations().some((d) => AI_MODULES.test(d.getModuleSpecifierValue()))) continue;
      const callsModel = calls(entry.node).some((call) => AI_METHODS.test(calleeText(call)) || AI_SDK_FUNCTIONS.has(calleeName(call)));
      if (!callsModel || hasRateLimit(entry.node, ctx, entry.routePath)) continue;
      const conditions = [...entry.node.getDescendantsOfKind(SyntaxKind.IfStatement).map((s) => s.getExpression()), ...entry.node.getDescendantsOfKind(SyntaxKind.ConditionalExpression).map((c) => c.getCondition())];
      if (conditions.some((condition) => QUOTA.test(condition.getText()))) continue;
      findings.push(findingAt(entry.node));
    }
    return findings;
  },
};
