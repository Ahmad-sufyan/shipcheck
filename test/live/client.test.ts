import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { USER_AGENT, VERSION } from '../../src/core/version.js';
import { LiveClient, type LiveClientOptions } from '../../src/live/client.js';
import { LiveAbort, LiveRefusal } from '../../src/live/errors.js';
import { nodeTransport, type Transport } from '../../src/live/transport.js';
import { startMockServer, type MockServer } from './mock-server.js';

let server: MockServer;
let waits: number[];
let clock: number;

beforeEach(async () => {
  server = await startMockServer({ mode: 'hardened' });
  waits = [];
  clock = 0;
});
afterEach(async () => {
  await server.close();
});

function client(options: Partial<LiveClientOptions> = {}): LiveClient {
  return new LiveClient({
    origin: new URL(server.url),
    allowLocal: true,
    // A fake clock that only moves when the client sleeps, so waits are exact.
    now: () => clock,
    sleep: async (ms) => {
      waits.push(ms);
      clock += ms;
    },
    ...options,
  });
}

describe('LiveClient', () => {
  it('identifies itself and never sends credentials', async () => {
    await client().request('GET', '/');
    const headers = server.requests[0]!.headers;
    expect(USER_AGENT).toBe(`shipcheck/${VERSION} (+https://github.com/Ahmad-sufyan/shipcheck)`);
    expect(headers['user-agent']).toBe(USER_AGENT);
    expect(Object.keys(headers).filter((h) => /cookie|authorization|proxy-authorization|x-api-key/i.test(h))).toEqual([]);
  });

  it('returns redirects as they are instead of following them', async () => {
    const response = await client().request('GET', '/admin');
    expect(response.status).toBe(307);
    expect(response.headers.location).toBe('/login?next=%2Fadmin');
    expect(server.count).toBe(1);
  });

  it('only sends GET and HEAD, plus the one configured rate-limit probe', async () => {
    const plain = client();
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']) {
      await expect(plain.request(method as 'GET', '/api/login')).rejects.toThrow(LiveRefusal);
    }
    const withProbe = client({ probe: { path: '/api/login', method: 'POST' } });
    expect((await withProbe.request('POST', '/api/login')).status).toBe(200);
    await expect(withProbe.request('POST', '/api/other')).rejects.toThrow(/only sends GET and HEAD/);
    expect(server.requests.map((r) => `${r.method} ${r.path}`)).toEqual(['POST /api/login']);
  });

  it('refuses other hosts and schemes', async () => {
    const c = client();
    await expect(c.request('GET', 'https://evil.example.com/')).rejects.toThrow(/only requests .*127\.0\.0\.1/);
    await expect(c.request('GET', 'ftp://127.0.0.1/')).rejects.toThrow(LiveRefusal);
    expect(server.count).toBe(0);
  });

  it('never exceeds its budget', async () => {
    const c = client({ maxRequests: 3 });
    for (let i = 0; i < 3; i++) await c.request('HEAD', '/');
    await expect(c.request('HEAD', '/')).rejects.toThrow(LiveAbort);
    await expect(c.request('HEAD', '/')).rejects.toThrow(/budget of 3 requests/);
    expect(server.count).toBe(3);
    expect(c.remaining).toBe(0);
  });

  it('defaults to 60 requests and caps any configured budget at 100', () => {
    expect(client().maxRequests).toBe(60);
    expect(client({ maxRequests: 1000 }).maxRequests).toBe(100);
  });

  it('waits at least 250 ms between requests, even when configured lower', async () => {
    const c = client({ delayMs: 10 });
    expect(c.delayMs).toBe(250);
    await c.request('HEAD', '/');
    await c.request('HEAD', '/');
    await c.request('HEAD', '/');
    expect(waits).toEqual([250, 250]);
  });

  it('lets only the rate-limit probe use 100 ms spacing', async () => {
    const c = client({ probe: { path: '/api/login', method: 'GET' } });
    await c.request('GET', '/api/login', { spacingMs: 100 });
    await c.request('GET', '/api/login', { spacingMs: 100 });
    await c.request('GET', '/', { spacingMs: 100 });
    expect(waits).toEqual([100, 250]);
  });

  it('sends one request at a time with a 10 s timeout', async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const timeouts: number[] = [];
    const counting: Transport = async (request) => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      timeouts.push(request.timeoutMs);
      try {
        return await nodeTransport(request);
      } finally {
        inFlight--;
      }
    };
    const c = client({ transport: counting });
    await Promise.all([c.request('GET', '/'), c.request('GET', '/account'), c.request('HEAD', '/')]);
    expect(maxInFlight).toBe(1);
    expect(timeouts).toEqual([10_000, 10_000, 10_000]);
  });

  it('aborts after 3 consecutive 5xx responses', async () => {
    server.mode = 'error';
    const c = client();
    for (let i = 0; i < 3; i++) expect((await c.request('GET', '/')).status).toBe(500);
    await expect(c.request('GET', '/')).rejects.toThrow(/3 consecutive 5xx/);
    expect(server.count).toBe(3);
  });

  it('resets the 5xx streak on any other response', async () => {
    server.mode = 'error';
    const c = client();
    await c.request('GET', '/');
    await c.request('GET', '/');
    server.mode = 'hardened';
    await c.request('GET', '/');
    server.mode = 'error';
    await c.request('GET', '/');
    await c.request('GET', '/');
    expect((await c.request('GET', '/')).status).toBe(500);
    expect(server.count).toBe(6);
  });

  it('refuses a loopback target without SHIPCHECK_ALLOW_LOCAL and sends nothing', async () => {
    await expect(client({ allowLocal: false }).request('GET', '/')).rejects.toThrow(LiveRefusal);
    expect(server.count).toBe(0);
  });

  it('pins the address it checked, so DNS cannot change between check and connect', async () => {
    const seen: string[] = [];
    const recording: Transport = async (request) => {
      seen.push(request.address.address);
      return nodeTransport(request);
    };
    let calls = 0;
    const c = new LiveClient({
      origin: new URL(`http://shipcheck-test.invalid:${server.port}`),
      allowLocal: true,
      sleep: async () => {},
      transport: recording,
      resolve: async () => {
        calls++;
        return [{ address: '127.0.0.1', family: 4 }];
      },
    });
    expect((await c.request('GET', '/')).status).toBe(200);
    expect(seen).toEqual(['127.0.0.1']);
    expect(calls).toBe(1);
  });
});
