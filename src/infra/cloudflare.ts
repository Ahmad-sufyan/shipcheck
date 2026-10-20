import type { ToolRun } from '../adapters/types.js';
import { USER_AGENT } from '../core/version.js';

export const CLOUDFLARE_API = 'https://api.cloudflare.com/client/v4';
export const CLOUDFLARE_TOKEN_ENV = 'CLOUDFLARE_API_TOKEN';
const TIMEOUT_MS = 10_000;

/** The subset of fetch the client uses; injected in tests to replay recorded responses. */
export type FetchFn = (url: string, init: { method: 'GET'; headers: Record<string, string>; signal: AbortSignal }) => Promise<{ status: number; json(): Promise<unknown> }>;

export const PERMISSIONS = {
  zone: 'Zone > Zone > Read',
  settings: 'Zone > Zone Settings > Read',
  waf: 'Zone > Zone WAF > Read',
} as const;

export interface CloudflareZoneReport {
  zone: { id: string; name: string; status: string; paused: boolean };
  /** off | flexible | full | strict */
  ssl?: string;
  /** on | off */
  alwaysUseHttps?: string;
  /** Enabled rules in the zone's custom firewall phase (0 when the phase has no ruleset). */
  firewallRules?: number;
  /** Enabled rules in the zone's rate limiting phase (0 when the phase has no ruleset). */
  rateLimitRules?: number;
  /** Parts that could not be read, usually for a missing token permission. */
  problems: string[];
}

interface Envelope {
  success?: boolean;
  errors?: { code?: number; message?: string }[];
  result?: unknown;
}

/** The hostname and each parent domain down to two labels, where the zone may be. */
export function zoneCandidates(hostname: string): string[] {
  const labels = hostname.toLowerCase().replace(/\.$/, '').split('.');
  const candidates: string[] = [];
  for (let i = 0; i <= labels.length - 2; i++) candidates.push(labels.slice(i).join('.'));
  return candidates;
}

function describe(status: number, body: Envelope): string {
  const errors = (body.errors ?? []).map((e) => `${e.code ?? '?'} ${e.message ?? ''}`.trim());
  return `HTTP ${status}${errors.length ? `: ${errors.join('; ')}` : ''}`;
}

class RequestFailed extends Error {}

/** One GET with the read-only token. The token is only ever put in the Authorization header. */
async function get(path: string, token: string, fetch: FetchFn): Promise<{ status: number; body: Envelope }> {
  let response;
  try {
    response = await fetch(`${CLOUDFLARE_API}${path}`, {
      method: 'GET',
      headers: { authorization: `Bearer ${token}`, accept: 'application/json', 'user-agent': USER_AGENT },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    throw new RequestFailed(`Cloudflare API request failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  let body: Envelope = {};
  try {
    body = (await response.json()) as Envelope;
  } catch {
    // keep the empty envelope; the status explains the failure
  }
  return { status: response.status, body };
}

const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);

async function settingValue(zoneId: string, setting: string, token: string, fetch: FetchFn, problems: string[]): Promise<string | undefined> {
  const { status, body } = await get(`/zones/${zoneId}/settings/${setting}`, token, fetch);
  if (body.success && isObject(body.result) && typeof body.result.value === 'string') return body.result.value;
  problems.push(`${setting} setting: ${describe(status, body)} (needs ${PERMISSIONS.settings})`);
  return undefined;
}

async function enabledRules(zoneId: string, phase: string, token: string, fetch: FetchFn, problems: string[]): Promise<number | undefined> {
  const { status, body } = await get(`/zones/${zoneId}/rulesets/phases/${phase}/entrypoint`, token, fetch);
  // No entrypoint ruleset yet means no rules in this phase.
  if (status === 404) return 0;
  if (body.success && isObject(body.result)) {
    const rules = Array.isArray(body.result.rules) ? body.result.rules : [];
    return rules.filter((rule) => !isObject(rule) || rule.enabled !== false).length;
  }
  problems.push(`${phase} rules: ${describe(status, body)} (needs ${PERMISSIONS.waf})`);
  return undefined;
}

/**
 * Reads, with GET requests only, the zone that serves `hostname`: its SSL/TLS mode, Always Use HTTPS,
 * and how many custom firewall and rate limiting rules it has. Needs a token with Zone Read, Zone
 * Settings Read and Zone WAF Read; parts the token cannot read are listed in `problems`.
 */
export async function cloudflareZoneReport(hostname: string, options: { token: string; fetch?: FetchFn }): Promise<ToolRun<CloudflareZoneReport>> {
  const fetch = options.fetch ?? (globalThis.fetch as unknown as FetchFn);
  const { token } = options;
  try {
    const candidates = zoneCandidates(hostname);
    let zone: CloudflareZoneReport['zone'] | undefined;
    for (const name of candidates) {
      const { status, body } = await get(`/zones?name=${encodeURIComponent(name)}&per_page=5`, token, fetch);
      if (!body.success) return { ok: false, reason: `Cloudflare API refused the zone lookup (${describe(status, body)}); the token needs ${PERMISSIONS.zone}` };
      const found = Array.isArray(body.result) ? body.result.find(isObject) : undefined;
      if (found) {
        zone = { id: String(found.id), name: String(found.name), status: String(found.status), paused: found.paused === true };
        break;
      }
    }
    if (!zone) return { ok: false, reason: `no Cloudflare zone found for ${hostname} (tried ${candidates.join(', ')})` };

    const problems: string[] = [];
    const report: CloudflareZoneReport = { zone, problems };
    const ssl = await settingValue(zone.id, 'ssl', token, fetch, problems);
    const alwaysUseHttps = await settingValue(zone.id, 'always_use_https', token, fetch, problems);
    const firewallRules = await enabledRules(zone.id, 'http_request_firewall_custom', token, fetch, problems);
    const rateLimitRules = await enabledRules(zone.id, 'http_ratelimit', token, fetch, problems);
    return { ok: true, value: { ...report, ssl, alwaysUseHttps, firewallRules, rateLimitRules } };
  } catch (error) {
    if (error instanceof RequestFailed) return { ok: false, reason: error.message };
    throw error;
  }
}
