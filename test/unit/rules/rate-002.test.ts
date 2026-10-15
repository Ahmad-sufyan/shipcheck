import { describe, expect, it } from 'vitest';
import { rate002 as rule } from '../../../src/packs/nextjs-supabase/rules/rate-002-ai-endpoint.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/chat/route.ts';
const chat = (imports: string, ...body: string[]) => code(imports, 'export async function POST(request: Request) {', ...body.map((l) => `  ${l}`), '}');

describe('RATE-002 AI endpoint without limit or per-user cap', () => {
  it('reports an OpenAI call with no limiter or quota', async () => {
    const text = chat("import OpenAI from 'openai'", "const reply = await openai.chat.completions.create({ model: 'm', messages })");
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([{ file: ROUTE, line: 2, evidence: 'export async function POST(request: Request) {' }]);
  });

  it('reports AI SDK streamText and Anthropic messages.create', async () => {
    expect(await runRule(rule, { [ROUTE]: chat("import { streamText } from 'ai'", 'return streamText({ model, prompt }).toTextStreamResponse()') })).toHaveLength(1);
    expect(await runRule(rule, { [ROUTE]: chat("import Anthropic from '@anthropic-ai/sdk'", "await anthropic.messages.create({ model: 'm', max_tokens: 10, messages })") })).toHaveLength(1);
  });

  it('accepts a rate limiter or a usage quota check', async () => {
    expect(await runRule(rule, { [ROUTE]: chat("import OpenAI from 'openai'", 'if (!(await ratelimit.limit(userId)).success) return new Response(null, { status: 429 })', 'await openai.responses.create({ model: "m", input })') })).toEqual([]);
    expect(await runRule(rule, { [ROUTE]: chat("import OpenAI from 'openai'", 'if (credits <= 0) return new Response(null, { status: 402 })', 'await openai.responses.create({ model: "m", input })') })).toEqual([]);
  });

  it('ignores non-AI messages.create calls such as Twilio', async () => {
    expect(await runRule(rule, { 'app/api/sms/route.ts': chat("import twilio from 'twilio'", "await client.messages.create({ to, from, body: 'hi' })") })).toEqual([]);
  });
});
