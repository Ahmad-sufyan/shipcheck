import { describe, expect, it } from 'vitest';
import { integ005 as rule } from '../../../src/packs/nextjs-supabase/rules/integ-005-system-prompt-input.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/chat/route.ts';
const post = (...body: string[]) => code('export async function POST(request: Request) {', '  const { message, persona } = Schema.parse(await request.json())', ...body.map((l) => `  ${l}`), '}');

describe('INTEG-005 User input in system prompt', () => {
  it('reports a system message built from request input, even after schema validation', async () => {
    const text = post('await openai.chat.completions.create({ model: "m", messages: [', '  { role: "system", content: `Speak as ${persona}.` },', '  { role: "user", content: message },', '] })');
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([{ file: ROUTE, line: 4, evidence: '{ role: "system", content: `Speak as ${persona}.` },' }]);
  });

  it('reports AI SDK and Anthropic system parameters built from input', async () => {
    expect(await runRule(rule, { [ROUTE]: post("const result = streamText({ model, system: 'You help ' + persona, prompt: message })") })).toHaveLength(1);
  });

  it('ignores constant system prompts with user text in user messages', async () => {
    const text = post("await anthropic.messages.create({ model: 'm', max_tokens: 100, system: 'You are a billing assistant.', messages: [{ role: 'user', content: message }] })");
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([]);
  });

  it('ignores system prompts picked from an allowlist', async () => {
    const text = code(
      "const PROMPTS = { friendly: 'Be warm.', formal: 'Be formal.' } as const",
      'export async function POST(request: Request) {',
      '  const { tone } = Schema.parse(await request.json())',
      "  await generateText({ model, system: PROMPTS[tone], prompt: 'hi' })",
      '}',
    );
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([]);
  });
});
