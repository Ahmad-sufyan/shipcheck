import { describe, expect, it } from 'vitest';
import { data001 as rule } from '../../../src/packs/nextjs-supabase/rules/data-001-sensitive-logs.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/signup/route.ts';
const post = (...body: string[]) => code('export async function POST(request: Request) {', '  const input = await request.json()', ...body.map((l) => `  ${l}`), '}');

describe('DATA-001 Sensitive data in logs', () => {
  it('reports a password written to the console', async () => {
    expect(await runRule(rule, { [ROUTE]: post("console.log('signup', { email: input.email, password: input.password })") })).toEqual([
      { file: ROUTE, line: 3, evidence: "console.log('signup', { email: input.email, password: input.password })" },
    ]);
  });

  it.each([
    ['a whole request body', "logger.info('body', input)"],
    ['request headers', "console.debug(request.headers)"],
    ['an authorization header value', "console.warn('auth', request.headers.get('authorization'))"],
    ['a token variable', 'const accessToken = input.token\n  winston.info(`token ${accessToken}`)'],
  ])('reports %s', async (_name, line) => {
    expect(await runRule(rule, { [ROUTE]: post(line) })).toHaveLength(1);
  });

  it('ignores ids and non-sensitive fields', async () => {
    expect(await runRule(rule, { [ROUTE]: post("console.info('signup', { userId: input.id, plan: input.plan })") })).toEqual([]);
  });

  it('ignores loggers configured with redaction', async () => {
    const text = code("const logger = pino({ redact: ['password', 'req.headers.authorization'] })", post("logger.info({ password: input.password }, 'signup')"));
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([]);
  });
});
