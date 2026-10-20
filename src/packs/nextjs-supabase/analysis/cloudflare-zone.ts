import { cloudflareZoneReport, CLOUDFLARE_TOKEN_ENV, type CloudflareZoneReport } from '../../../infra/cloudflare.js';
import type { ScanContext } from '../../../types.js';

export type ZoneCheck =
  /** The API was not consulted: no --cloudflare flag or no token. */
  | { status: 'unverified'; reason: string }
  /** It was asked for but could not run (offline, no hostname, API error). */
  | { status: 'skipped'; reason: string }
  | { status: 'report'; report: CloudflareZoneReport };

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

/** A hostname served through Cloudflare: live.url, else the first zone_name or route pattern in the wrangler config. */
export function cloudflareHostname(ctx: ScanContext): string | undefined {
  if (ctx.config.live?.url) return new URL(ctx.config.live.url).hostname;
  const data = ctx.wranglerToml?.data;
  if (!isObject(data)) return undefined;
  const routes = [...(Array.isArray(data.routes) ? data.routes : []), ...(data.route ? [data.route] : [])];
  for (const route of routes) {
    if (isObject(route) && typeof route.zone_name === 'string') return route.zone_name;
    const pattern = typeof route === 'string' ? route : isObject(route) && typeof route.pattern === 'string' ? route.pattern : undefined;
    const host = pattern?.replace(/^\*?\.?/, '').split('/')[0];
    if (host && !host.includes('*')) return host;
  }
  return undefined;
}

const cache = new WeakMap<ScanContext, Promise<ZoneCheck>>();

async function check(ctx: ScanContext): Promise<ZoneCheck> {
  const cloudflare = ctx.tools?.cloudflare;
  if (!cloudflare) return { status: 'unverified', reason: `run \`shipcheck scan --cloudflare\` with a read-only ${CLOUDFLARE_TOKEN_ENV} to check them` };
  if (ctx.tools?.offline) return { status: 'skipped', reason: '--offline: the Cloudflare API was not queried' };
  if (!cloudflare.token) return { status: 'unverified', reason: `${CLOUDFLARE_TOKEN_ENV} is not set` };
  const hostname = cloudflareHostname(ctx);
  if (!hostname) return { status: 'skipped', reason: 'no hostname to look up: set live.url in shipcheck.config.json or add routes to the wrangler config' };
  const run = await cloudflareZoneReport(hostname, { token: cloudflare.token, ...(cloudflare.fetch ? { fetch: cloudflare.fetch } : {}) });
  return run.ok ? { status: 'report', report: run.value } : { status: 'skipped', reason: run.reason };
}

/** The zone settings INFRA-001..003 judge, fetched once per scan. */
export function cloudflareZone(ctx: ScanContext): Promise<ZoneCheck> {
  let zone = cache.get(ctx);
  if (!zone) cache.set(ctx, (zone = check(ctx)));
  return zone;
}
