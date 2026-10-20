import { readFileSync } from 'node:fs';
import type { FetchFn } from '../../src/infra/cloudflare.js';

export const API = 'https://api.cloudflare.com/client/v4';
export const ZONE_ID = '023e105f4ecef8ad9ca31a8372d0c353';
export const TOKEN = 'cf-test-token-FAKEFAKEFAKE';

export function cfResponse(name: string): unknown {
  return JSON.parse(readFileSync(new URL(`../cf-responses/${name}.json`, import.meta.url), 'utf8'));
}

export interface FetchCall {
  url: string;
  method: string;
  headers: Record<string, string>;
}

/** Answers Cloudflare API paths (relative to /client/v4) from test/cf-responses; unknown paths get a 404 envelope. */
export function recordedFetch(routes: Record<string, [status: number, response: string]>): { fetch: FetchFn; calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  const fetch: FetchFn = async (url, init) => {
    calls.push({ url, method: init.method, headers: init.headers });
    const route = routes[url.slice(API.length)];
    const body = route ? cfResponse(route[1]) : { success: false, errors: [{ code: 7003, message: 'Could not route' }], messages: [], result: null };
    return { status: route?.[0] ?? 404, json: async () => body };
  };
  return { fetch, calls };
}

/** A zone example.com with the given ssl / always_use_https values and both rule phases. */
export function zoneRoutes(overrides: Record<string, [number, string]> = {}): Record<string, [number, string]> {
  return {
    '/zones?name=app.example.com&per_page=5': [200, 'zones-list-empty'],
    '/zones?name=example.com&per_page=5': [200, 'zones-list'],
    [`/zones/${ZONE_ID}/settings/ssl`]: [200, 'setting-ssl-strict'],
    [`/zones/${ZONE_ID}/settings/always_use_https`]: [200, 'setting-always-use-https-on'],
    [`/zones/${ZONE_ID}/rulesets/phases/http_request_firewall_custom/entrypoint`]: [200, 'ruleset-firewall-custom-entrypoint'],
    [`/zones/${ZONE_ID}/rulesets/phases/http_ratelimit/entrypoint`]: [200, 'ruleset-ratelimit-entrypoint'],
    ...overrides,
  };
}
