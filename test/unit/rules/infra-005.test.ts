import { describe, expect, it } from 'vitest';
import { infra005 as rule } from '../../../src/packs/nextjs-supabase/rules/infra-005-wrangler-config.js';
import { FAKE } from '../../helpers/fake-secrets.js';
import { code, lineOf, runRule } from '../../helpers/memory-context.js';

describe('INFRA-005 Wrangler configuration', () => {
  it('reports secret-looking vars without their values', async () => {
    const toml = code('name = "app"', '', '[vars]', 'SITE_URL = "https://app.example.com"', 'SESSION_SECRET = "dev-session-secret"', `BILLING = "${FAKE.stripe}"`);
    const findings = await runRule(rule, { 'wrangler.toml': toml });
    expect(findings).toEqual([
      { file: 'wrangler.toml', line: 5, evidence: 'vars.SESSION_SECRET = <redacted>' },
      { file: 'wrangler.toml', line: 6, evidence: 'vars.BILLING = <redacted>', confidence: 'high', explanation: expect.stringContaining('Stripe') },
    ]);
    expect(JSON.stringify(findings)).not.toContain('dev-session-secret');
  });

  it('checks per-environment vars and wrangler.jsonc', async () => {
    const toml = code('name = "app"', '[vars]', 'API_TOKEN = "a"', '[env.staging.vars]', 'API_TOKEN = "b"');
    expect((await runRule(rule, { 'wrangler.toml': toml })).map((f) => `${f.line} ${f.evidence}`)).toEqual(['3 vars.API_TOKEN = <redacted>', '5 env.staging.vars.API_TOKEN = <redacted>']);
    const jsonc = code('{', '  // comments are fine', '  "name": "app",', '  "vars": { "DB_PASSWORD": "x" }', '}');
    expect(await runRule(rule, { 'wrangler.jsonc': jsonc })).toEqual([expect.objectContaining({ file: 'wrangler.jsonc', evidence: 'vars.DB_PASSWORD = <redacted>' })]);
  });

  it('reports workers_dev = true next to routes as medium', async () => {
    const toml = code('name = "app"', 'workers_dev = true', 'routes = [{ pattern = "app.example.com/*", zone_name = "example.com" }]');
    expect(await runRule(rule, { 'wrangler.toml': toml })).toEqual([expect.objectContaining({ line: lineOf(toml, 'workers_dev'), severity: 'medium', evidence: 'workers_dev = true alongside routes' })]);
  });

  it('accepts secrets kept out of vars and workers_dev without routes', async () => {
    const toml = code('name = "app"', 'workers_dev = true', '[vars]', 'SITE_URL = "https://app.example.com"', 'PUBLIC_FLAG = "on"');
    expect(await runRule(rule, { 'wrangler.toml': toml })).toEqual([]);
    expect(await runRule(rule, { 'wrangler.toml': code('name = "app"', 'workers_dev = false', 'routes = ["app.example.com/*"]') })).toEqual([]);
  });
});
