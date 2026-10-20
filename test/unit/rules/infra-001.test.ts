import { describe, expect, it } from 'vitest';
import { infra001 } from '../../../src/packs/nextjs-supabase/rules/infra-001-cloudflare-tls.js';
import { infra002 } from '../../../src/packs/nextjs-supabase/rules/infra-002-always-use-https.js';
import { infra003 } from '../../../src/packs/nextjs-supabase/rules/infra-003-waf-rules.js';
import type { Rule, ShipcheckConfig } from '../../../src/types.js';
import { recordedFetch, TOKEN, ZONE_ID, zoneRoutes } from '../../helpers/cloudflare.js';
import { fakeExec } from '../../helpers/fake-exec.js';
import { memoryContext } from '../../helpers/memory-context.js';

const WRANGLER = { 'wrangler.toml': 'name = "app"\nroutes = [{ pattern = "app.example.com/*", zone_name = "example.com" }]\n' };
const LIVE: Partial<ShipcheckConfig> = { live: { url: 'https://app.example.com', protectedPaths: [], cookiePaths: [] } };

async function run(rule: Rule, files: Record<string, string>, options: { routes?: Record<string, [number, string]>; token?: string; flag?: boolean; offline?: boolean; config?: Partial<ShipcheckConfig> } = {}) {
  const { fetch, calls } = recordedFetch(options.routes ?? zoneRoutes());
  const cloudflare = options.flag === false ? {} : { cloudflare: { ...(options.token === '' ? {} : { token: options.token ?? TOKEN }), fetch } };
  const ctx = memoryContext(files, options.config ?? LIVE, { tools: { exec: fakeExec().exec, offline: options.offline ?? false, ...cloudflare } });
  const skipped: { check: string; reason: string }[] = [];
  ctx.skip = (check, reason) => skipped.push({ check, reason });
  return { findings: await rule.run(ctx), skipped, calls };
}

describe('INFRA-001 Cloudflare SSL/TLS mode', () => {
  it.each(['setting-ssl-flexible'])('reports %s', async (response) => {
    const { findings } = await run(infra001, WRANGLER, { routes: zoneRoutes({ [`/zones/${ZONE_ID}/settings/ssl`]: [200, response] }) });
    expect(findings).toEqual([{ evidence: 'Cloudflare zone example.com: SSL/TLS encryption mode is "flexible"' }]);
  });

  it('accepts Full (strict)', async () => {
    expect((await run(infra001, WRANGLER)).findings).toEqual([]);
  });

  it('finds the zone from the wrangler routes when there is no live.url', async () => {
    const { findings, calls } = await run(infra001, WRANGLER, { config: {}, routes: zoneRoutes({ [`/zones/${ZONE_ID}/settings/ssl`]: [200, 'setting-ssl-flexible'] }) });
    expect(findings).toHaveLength(1);
    expect(calls[0]?.url).toContain('/zones?name=example.com');
  });

  it('emits one info advisory for a Cloudflare project when the API is not consulted', async () => {
    for (const options of [{ flag: false }, { token: '' }]) {
      const { findings, calls } = await run(infra001, WRANGLER, options);
      expect(findings).toEqual([expect.objectContaining({ severity: 'info', advisory: true, evidence: expect.stringMatching(/^Cloudflare SSL\/TLS mode and Always Use HTTPS unverified/) })]);
      expect(calls).toEqual([]);
    }
  });

  it('stays silent for projects that are not on Cloudflare', async () => {
    expect((await run(infra001, {}, { flag: false })).findings).toEqual([]);
  });

  it('records why it could not check (offline, API errors) and never sends the token anywhere else', async () => {
    const offline = await run(infra001, WRANGLER, { offline: true });
    expect(offline.skipped).toEqual([{ check: 'INFRA-001', reason: '--offline: the Cloudflare API was not queried' }]);
    expect(offline.calls).toEqual([]);
    const denied = await run(infra001, WRANGLER, { routes: { '/zones?name=app.example.com&per_page=5': [403, 'error-invalid-token'] } });
    expect(denied.skipped).toEqual([{ check: 'INFRA-001', reason: expect.stringContaining('9109 Invalid access token') }]);
    expect(denied.calls.every((c) => c.url.startsWith('https://api.cloudflare.com/client/v4/') && c.method === 'GET')).toBe(true);
  });
});

describe('INFRA-002 Always Use HTTPS', () => {
  it('reports it off and accepts it on', async () => {
    const off = await run(infra002, WRANGLER, { routes: zoneRoutes({ [`/zones/${ZONE_ID}/settings/always_use_https`]: [200, 'setting-always-use-https-off'] }) });
    expect(off.findings).toEqual([{ evidence: 'Cloudflare zone example.com: Always Use HTTPS is off' }]);
    expect((await run(infra002, WRANGLER)).findings).toEqual([]);
  });

  it('is skipped without a token on a Cloudflare project', async () => {
    const { findings, skipped } = await run(infra002, WRANGLER, { flag: false });
    expect(findings).toEqual([]);
    expect(skipped).toEqual([{ check: 'INFRA-002', reason: expect.stringContaining('--cloudflare') }]);
  });
});

describe('INFRA-003 WAF and rate limiting rules', () => {
  it('reports phases without rules as an info advisory', async () => {
    const { findings } = await run(infra003, WRANGLER, {
      routes: zoneRoutes({ [`/zones/${ZONE_ID}/rulesets/phases/http_ratelimit/entrypoint`]: [404, 'ruleset-ratelimit-entrypoint-missing'] }),
    });
    expect(findings).toEqual([{ evidence: 'Cloudflare zone example.com has no rate limiting rules' }]);
    expect(infra003).toMatchObject({ severity: 'info', advisory: true });
  });

  it('accepts zones with both kinds of rules', async () => {
    expect((await run(infra003, WRANGLER)).findings).toEqual([]);
  });
});
