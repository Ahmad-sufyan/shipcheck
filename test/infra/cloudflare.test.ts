import { describe, expect, it } from 'vitest';
import { cloudflareZoneReport, zoneCandidates } from '../../src/infra/cloudflare.js';
import { recordedFetch, TOKEN, ZONE_ID, zoneRoutes } from '../helpers/cloudflare.js';

describe('cloudflareZoneReport', () => {
  it('finds the zone by walking up the hostname and reads settings and rule phases with GET only', async () => {
    const { fetch, calls } = recordedFetch(
      zoneRoutes({
        [`/zones/${ZONE_ID}/settings/ssl`]: [200, 'setting-ssl-flexible'],
        [`/zones/${ZONE_ID}/settings/always_use_https`]: [200, 'setting-always-use-https-off'],
        [`/zones/${ZONE_ID}/rulesets/phases/http_ratelimit/entrypoint`]: [404, 'ruleset-ratelimit-entrypoint-missing'],
      }),
    );
    expect(await cloudflareZoneReport('app.example.com', { token: TOKEN, fetch })).toEqual({
      ok: true,
      value: {
        zone: { id: ZONE_ID, name: 'example.com', status: 'active', paused: false },
        ssl: 'flexible',
        alwaysUseHttps: 'off',
        firewallRules: 1,
        rateLimitRules: 0,
        problems: [],
      },
    });
    expect(calls.map((c) => `${c.method} ${c.url.replace('https://api.cloudflare.com/client/v4', '')}`)).toEqual([
      'GET /zones?name=app.example.com&per_page=5',
      'GET /zones?name=example.com&per_page=5',
      `GET /zones/${ZONE_ID}/settings/ssl`,
      `GET /zones/${ZONE_ID}/settings/always_use_https`,
      `GET /zones/${ZONE_ID}/rulesets/phases/http_request_firewall_custom/entrypoint`,
      `GET /zones/${ZONE_ID}/rulesets/phases/http_ratelimit/entrypoint`,
    ]);
    expect(calls.every((c) => c.headers.authorization === `Bearer ${TOKEN}`)).toBe(true);
  });

  it('reports an invalid token without echoing it', async () => {
    const { fetch } = recordedFetch({ '/zones?name=app.example.com&per_page=5': [403, 'error-invalid-token'] });
    const run = await cloudflareZoneReport('app.example.com', { token: TOKEN, fetch });
    expect(run).toEqual({ ok: false, reason: 'Cloudflare API refused the zone lookup (HTTP 403: 9109 Invalid access token); the token needs Zone > Zone > Read' });
    expect(JSON.stringify(run)).not.toContain(TOKEN);
  });

  it('says when no zone matches', async () => {
    const { fetch } = recordedFetch({ '/zones?name=app.example.com&per_page=5': [200, 'zones-list-empty'], '/zones?name=example.com&per_page=5': [200, 'zones-list-empty'] });
    expect(await cloudflareZoneReport('app.example.com', { token: TOKEN, fetch })).toEqual({ ok: false, reason: 'no Cloudflare zone found for app.example.com (tried app.example.com, example.com)' });
  });

  it('keeps what it could read when one permission is missing', async () => {
    const { fetch } = recordedFetch(zoneRoutes({ [`/zones/${ZONE_ID}/rulesets/phases/http_ratelimit/entrypoint`]: [401, 'error-authentication'] }));
    const run = await cloudflareZoneReport('example.com', { token: TOKEN, fetch });
    expect(run).toEqual({
      ok: true,
      value: expect.objectContaining({ ssl: 'strict', alwaysUseHttps: 'on', firewallRules: 1, rateLimitRules: undefined, problems: ['http_ratelimit rules: HTTP 401: 10000 Authentication error (needs Zone > Zone WAF > Read)'] }),
    });
  });

  it('turns network errors into a reason', async () => {
    const run = await cloudflareZoneReport('example.com', {
      token: TOKEN,
      fetch: async () => {
        throw new Error('getaddrinfo ENOTFOUND api.cloudflare.com');
      },
    });
    expect(run).toEqual({ ok: false, reason: 'Cloudflare API request failed: getaddrinfo ENOTFOUND api.cloudflare.com' });
  });

  it('tries the hostname and each parent down to two labels', () => {
    expect(zoneCandidates('a.b.example.co.uk')).toEqual(['a.b.example.co.uk', 'b.example.co.uk', 'example.co.uk', 'co.uk']);
    expect(zoneCandidates('example.com')).toEqual(['example.com']);
  });
});
