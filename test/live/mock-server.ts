import { createServer, type IncomingHttpHeaders, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * A local stand-in for a deployed app, on 127.0.0.1 only. Each mode models one kind of site:
 * - bare: framework defaults, no security headers, X-Powered-By and a versioned Server header, no redirects
 * - hardened: every header, HTTP redirects to HTTPS, rate limit after 5 hits, protected pages redirect to /login
 * - leaky: hardened, but .env, .git, a backup, .DS_Store and source maps are served
 * - soft404: hardened, but every unknown path answers 200 with an HTML "not found" page
 * - no-limit: hardened without a rate limit
 * - limit-10: hardened with the rate limit after 10 hits (429 + Retry-After)
 * - open-admin: hardened, but /admin answers 200 to anyone
 * - bad-cookie: hardened, but cookies lack HttpOnly, Secure and SameSite
 * - error: every response except the ownership file is a 500
 * A second listener (`httpUrl`) plays the plain-HTTP port of the same host.
 */
export type MockMode = 'bare' | 'hardened' | 'leaky' | 'soft404' | 'no-limit' | 'limit-10' | 'open-admin' | 'bad-cookie' | 'error';

export type WellKnown = string | { redirect: string } | null;

export interface RecordedRequest {
  listener: 'main' | 'http';
  method: string;
  path: string;
  headers: IncomingHttpHeaders;
}

export interface MockServer {
  /** http://127.0.0.1:<port> */
  url: string;
  port: number;
  /** The plain-HTTP listener of the same "site". */
  httpUrl: string;
  httpPort: number;
  requests: RecordedRequest[];
  /** Every request received by either listener. */
  readonly count: number;
  mode: MockMode;
  wellKnown: WellKnown;
  close(): Promise<void>;
}

const HARDENED_HEADERS: Record<string, string> = {
  'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-abc123'; frame-ancestors 'none'",
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
};

const HOME = '<!doctype html><html><head><script src="/_next/static/chunks/main-abc123.js" defer></script></head><body><h1>Demo</h1></body></html>';
const NOT_FOUND = '<!doctype html><html><body><h1>404: This page could not be found.</h1></body></html>';

const LEAKS: Record<string, { type: string; body: string | Buffer }> = {
  '/.env': { type: 'text/plain', body: 'DATABASE_URL=postgres://fake:fake@db.invalid/app\nAPI_KEY=FAKEFAKEFAKE\n' },
  '/.env.local': { type: 'text/plain', body: 'NEXT_PUBLIC_SITE_URL=https://fake.invalid\nSESSION_SECRET=FAKEFAKEFAKE\n' },
  '/.git/config': { type: 'text/plain', body: '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n' },
  '/.git/HEAD': { type: 'text/plain', body: 'ref: refs/heads/main\n' },
  '/backup.zip': { type: 'application/zip', body: Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(26)]) },
  '/.DS_Store': { type: 'application/octet-stream', body: Buffer.concat([Buffer.from([0, 0, 0, 1]), Buffer.from('Bud1'), Buffer.alloc(24)]) },
  '/_next/static/chunks/main-abc123.js.map': { type: 'application/json', body: JSON.stringify({ version: 3, sources: ['webpack://demo/./app/page.tsx'], mappings: 'AAAA' }) },
};

function send(res: ServerResponse, status: number, headers: Record<string, string | string[]>, body: string | Buffer = ''): void {
  res.writeHead(status, headers);
  res.end(body);
}

function rateLimit(mode: MockMode): number | undefined {
  if (mode === 'hardened' || mode === 'leaky' || mode === 'soft404' || mode === 'open-admin' || mode === 'bad-cookie') return 5;
  if (mode === 'limit-10') return 10;
  return undefined;
}

export async function startMockServer(options: { mode?: MockMode; wellKnown?: WellKnown } = {}): Promise<MockServer> {
  const requests: RecordedRequest[] = [];
  const hits = new Map<string, number>();
  let mainPort = 0;
  const state = { mode: options.mode ?? 'hardened', wellKnown: options.wellKnown ?? null } as { mode: MockMode; wellKnown: WellKnown };

  const handleMain = (req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url ?? '/', 'http://mock.invalid').pathname;
    requests.push({ listener: 'main', method: req.method ?? 'GET', path, headers: req.headers });
    const { mode } = state;
    const hardened = mode !== 'bare';
    const baseHeaders: Record<string, string | string[]> = { 'content-type': 'text/html; charset=utf-8', ...(hardened ? HARDENED_HEADERS : { 'x-powered-by': 'Next.js', server: 'nginx/1.25.3' }) };

    if (path === '/.well-known/shipcheck.txt') {
      const wellKnown = state.wellKnown;
      if (wellKnown === null) return send(res, 404, { 'content-type': 'text/plain' }, 'not found');
      if (typeof wellKnown === 'object') return send(res, 302, { location: wellKnown.redirect });
      return send(res, 200, { 'content-type': 'text/plain' }, wellKnown);
    }
    if (mode === 'error') return send(res, 500, { 'content-type': 'text/plain' }, 'Internal Server Error');

    const limit = rateLimit(mode);
    if (path === '/api/login') {
      const count = (hits.get(path) ?? 0) + 1;
      hits.set(path, count);
      if (limit !== undefined && count > limit) return send(res, 429, { ...baseHeaders, 'retry-after': '60' }, 'Too Many Requests');
      return send(res, 200, { ...baseHeaders, 'content-type': 'application/json' }, '{"ok":false}');
    }
    if (path === '/') {
      const cookies =
        mode === 'bad-cookie'
          ? ['session=FAKEFAKE; Path=/', '_ga=GA1.1.123; Path=/']
          : hardened
            ? ['session=FAKEFAKE; Path=/; HttpOnly; Secure; SameSite=Lax']
            : [];
      return send(res, 200, { ...baseHeaders, ...(cookies.length ? { 'set-cookie': cookies } : {}) }, HOME);
    }
    if (path === '/account') {
      const cookie = mode === 'bad-cookie' ? 'sid=FAKEFAKE; Path=/' : 'sid=FAKEFAKE; Path=/; HttpOnly; Secure; SameSite=Strict';
      return send(res, 200, { ...baseHeaders, 'set-cookie': [cookie] }, '<html><body>Account</body></html>');
    }
    if (path === '/admin' || path === '/dashboard') {
      if (!hardened || mode === 'open-admin') return send(res, 200, baseHeaders, '<html><body><h1>Admin dashboard</h1><table>users</table></body></html>');
      return send(res, 307, { ...baseHeaders, location: '/login?next=' + encodeURIComponent(path) });
    }
    if (path === '/api/admin') {
      if (!hardened || mode === 'open-admin') return send(res, 200, { ...baseHeaders, 'content-type': 'application/json' }, '{"users":[]}');
      return send(res, 401, { ...baseHeaders, 'content-type': 'application/json' }, '{"error":"unauthorized"}');
    }
    if (path === '/_next/static/chunks/main-abc123.js') return send(res, 200, { ...baseHeaders, 'content-type': 'application/javascript' }, 'console.log(1)');
    const leak = LEAKS[path];
    if (leak && mode === 'leaky') return send(res, 200, { ...baseHeaders, 'content-type': leak.type }, leak.body);
    if (mode === 'soft404') return send(res, 200, baseHeaders, NOT_FOUND);
    return send(res, 404, baseHeaders, NOT_FOUND);
  };

  const handleHttp = (req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url ?? '/', 'http://mock.invalid').pathname;
    requests.push({ listener: 'http', method: req.method ?? 'GET', path, headers: req.headers });
    if (state.mode === 'bare') return send(res, 200, { 'content-type': 'text/html' }, HOME);
    return send(res, 301, { location: `https://127.0.0.1:${mainPort}${path}` });
  };

  const listen = (server: Server) =>
    new Promise<number>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port));
    });

  const main = createServer(handleMain);
  const http = createServer(handleHttp);
  mainPort = await listen(main);
  const httpPort = await listen(http);
  const close = (server: Server) => new Promise<void>((resolve) => server.close(() => resolve()));

  return {
    url: `http://127.0.0.1:${mainPort}`,
    port: mainPort,
    httpUrl: `http://127.0.0.1:${httpPort}`,
    httpPort,
    requests,
    get count() {
      return requests.length;
    },
    get mode() {
      return state.mode;
    },
    set mode(mode: MockMode) {
      state.mode = mode;
      hits.clear();
    },
    get wellKnown() {
      return state.wellKnown;
    },
    set wellKnown(value: WellKnown) {
      state.wellKnown = value;
    },
    async close() {
      main.closeAllConnections();
      http.closeAllConnections();
      await Promise.all([close(main), close(http)]);
    },
  };
}
