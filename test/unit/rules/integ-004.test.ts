import { describe, expect, it } from 'vitest';
import { integ004 as rule } from '../../../src/packs/nextjs-supabase/rules/integ-004-llm-key-client.js';
import { code, runRule } from '../../helpers/memory-context.js';

describe('INTEG-004 LLM key in client code', () => {
  it('reports dangerouslyAllowBrowser in a client file, at that line', async () => {
    const text = code("'use client'", "import OpenAI from 'openai'", 'const openai = new OpenAI({', '  apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY,', '  dangerouslyAllowBrowser: true,', '})');
    expect(await runRule(rule, { 'components/ai.tsx': text })).toEqual([{ file: 'components/ai.tsx', line: 5, evidence: 'dangerouslyAllowBrowser: true,' }]);
  });

  it('reports an LLM SDK imported by client code, directly or through a module it imports', async () => {
    expect(await runRule(rule, { 'components/ai.tsx': code("'use client'", "import Anthropic from '@anthropic-ai/sdk'") })).toEqual([expect.objectContaining({ line: 2 })]);
    const files = { 'components/ai.tsx': code("'use client'", "import { ask } from '../lib/ai'"), 'lib/ai.ts': code("import Groq from 'groq-sdk'", 'export const ask = () => new Groq()') };
    expect(await runRule(rule, files)).toEqual([expect.objectContaining({ file: 'lib/ai.ts', line: 1 })]);
  });

  it('reports NEXT_PUBLIC_ LLM keys anywhere', async () => {
    expect(await runRule(rule, { 'lib/config.ts': 'export const key = process.env.NEXT_PUBLIC_ANTHROPIC_API_KEY' })).toHaveLength(1);
  });

  it('ignores LLM SDKs on the server', async () => {
    expect(await runRule(rule, { 'app/api/chat/route.ts': code("import OpenAI from 'openai'", 'const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })') })).toEqual([]);
  });

  it('ignores client UI hooks from the AI SDK', async () => {
    expect(await runRule(rule, { 'components/chat.tsx': code("'use client'", "import { useChat } from '@ai-sdk/react'", 'export const Chat = () => useChat()') })).toEqual([]);
  });
});
