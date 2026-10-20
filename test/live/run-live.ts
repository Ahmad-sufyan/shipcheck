import { runLive, type LiveRun, type LiveRunOptions } from '../../src/live/prober.js';
import { hashSecret } from '../../src/live/ownership.js';
import type { LiveResponse, Transport } from '../../src/live/transport.js';
import { ShipcheckConfigSchema } from '../../src/schema.js';
import type { LiveConfig, ShipcheckConfig } from '../../src/types.js';
import { tmpProject } from '../helpers/context.js';
import type { MockMode, MockServer } from './mock-server.js';

export const SECRET = 'c'.repeat(64);
export const DAY_MS = 86_400_000;

export function liveConfig(url: string, live: Partial<LiveConfig> = {}, rest: Partial<ShipcheckConfig> = {}): ShipcheckConfig {
  return ShipcheckConfigSchema.parse({ ...rest, live: { url, ...live } });
}

/** A full live run against the mock server, with the ownership file served and every wait skipped. */
export async function liveRun(server: MockServer, mode: MockMode, live: Partial<LiveConfig> = {}, options: Partial<LiveRunOptions> = {}): Promise<LiveRun> {
  server.mode = mode;
  server.wellKnown = `shipcheck-site-verification=${hashSecret(SECRET)}`;
  return runLive({
    url: server.url,
    config: liveConfig(server.url, live),
    root: tmpProject({}),
    env: { SHIPCHECK_ALLOW_LOCAL: '1', SHIPCHECK_LIVE_SECRET: SECRET },
    httpPort: server.httpPort,
    sleep: async () => {},
    resolveTxt: async () => {
      throw new Error('no TXT record');
    },
    ...options,
  });
}

/** A transport that answers from a table keyed by URL (404 otherwise); for https targets that cannot run locally. */
export function fakeSite(pages: Record<string, Partial<LiveResponse> | Error>): { transport: Transport; urls: string[] } {
  const urls: string[] = [];
  const transport: Transport = async (request) => {
    urls.push(`${request.method} ${request.url.href}`);
    const page = pages[request.url.href];
    if (page instanceof Error) throw page;
    const text = page?.text ?? '';
    return { url: request.url.href, status: 404, headers: {}, setCookie: [], body: Buffer.from(text), text, ...page };
  };
  return { transport, urls };
}

export const wellKnownPage = (secret = SECRET): Partial<LiveResponse> => ({ status: 200, text: `shipcheck-site-verification=${hashSecret(secret)}` });
