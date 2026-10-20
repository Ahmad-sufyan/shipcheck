import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { USER_AGENT } from '../../src/core/version.js';
import { LiveRefusal } from '../../src/live/errors.js';
import { formatPlan, liveTarget, planLive, runLive } from '../../src/live/prober.js';
import { tmpProject } from '../helpers/context.js';
import { startMockServer, type MockServer } from './mock-server.js';
import { fakeSite, liveConfig, liveRun, SECRET } from './run-live.js';

let server: MockServer;
beforeAll(async () => {
  server = await startMockServer();
});
afterAll(async () => {
  await server.close();
});
beforeEach(() => {
  server.requests.length = 0;
});

describe('refusals before anything is sent', () => {
  it('refuses without a secret, with setup instructions', async () => {
    const run = runLive({ url: server.url, config: liveConfig(server.url), root: tmpProject({}), env: { SHIPCHECK_ALLOW_LOCAL: '1' } });
    await expect(run).rejects.toThrow(LiveRefusal);
    await expect(run).rejects.toThrow(/shipcheck live init/);
    expect(server.count).toBe(0);
  });

  it('refuses an IP-literal or loopback target without SHIPCHECK_ALLOW_LOCAL', async () => {
    await expect(runLive({ url: server.url, config: liveConfig(server.url), root: tmpProject({}), env: { SHIPCHECK_LIVE_SECRET: SECRET } })).rejects.toThrow(/IP address/);
    expect(server.count).toBe(0);
  });

  it('refuses a hostname that resolves to a private address, before connecting', async () => {
    const site = fakeSite({});
    const run = runLive({
      url: 'https://intranet.example.com',
      config: liveConfig('https://intranet.example.com'),
      root: tmpProject({}),
      env: { SHIPCHECK_LIVE_SECRET: SECRET },
      resolve: async () => [{ address: '10.0.0.7', family: 4 }],
      transport: site.transport,
      sleep: async () => {},
    });
    await expect(run).rejects.toThrow(/private, loopback or link-local address \(10\.0\.0\.7\)/);
    expect(site.urls).toEqual([]);
  });

  it('runs no check when ownership cannot be verified', async () => {
    server.wellKnown = null;
    const run = runLive({
      url: server.url,
      config: liveConfig(server.url),
      root: tmpProject({}),
      env: { SHIPCHECK_ALLOW_LOCAL: '1', SHIPCHECK_LIVE_SECRET: SECRET },
      resolveTxt: async () => [],
      sleep: async () => {},
    });
    await expect(run).rejects.toThrow(/Could not verify that you own 127\.0\.0\.1/);
    expect(server.requests.map((r) => r.path)).toEqual(['/.well-known/shipcheck.txt']);
  });
});

describe('budget and stop conditions', () => {
  const paths = (n: number) => Array.from({ length: n }, (_, i) => ({ path: `/p${i}` }));

  it('never sends more than the configured budget', async () => {
    const { result, requestsSent } = await liveRun(server, 'open-admin', { maxRequests: 10, protectedPaths: paths(40) });
    expect(server.count).toBe(10);
    expect(requestsSent).toBe(10);
    expect(result.skipped).toContainEqual({ check: 'LIVE-004', reason: 'the request budget of 10 requests is used up' });
  });

  it('caps any budget at 100 requests', async () => {
    await liveRun(server, 'open-admin', { maxRequests: 1000, protectedPaths: paths(150) });
    expect(server.count).toBe(100);
  });

  it('stops after 3 consecutive 5xx responses', async () => {
    const { result } = await liveRun(server, 'error', { protectedPaths: paths(5) });
    expect(server.count).toBe(4);
    expect(result.findings).toEqual([]);
    expect(result.skipped).toEqual(
      expect.arrayContaining([
        { check: 'LIVE-004', reason: 'stopped after 3 consecutive 5xx responses' },
        { check: 'LIVE-005', reason: 'stopped after 3 consecutive 5xx responses' },
      ]),
    );
  });
});

describe('what is sent', () => {
  it('only GET and HEAD plus the configured probe, with the shipcheck User-Agent and no credentials', async () => {
    await liveRun(server, 'no-limit', {
      protectedPaths: [{ path: '/admin', method: 'HEAD' }],
      cookiePaths: ['/account'],
      rateLimitProbe: { path: '/api/login', method: 'POST', maxRequests: 5 },
    });
    const methods = new Set(server.requests.map((r) => `${r.method} ${r.method === 'POST' ? r.path : ''}`.trim()));
    expect([...methods].sort()).toEqual(['GET', 'HEAD', 'POST /api/login']);
    expect(server.requests.every((r) => r.headers['user-agent'] === USER_AGENT)).toBe(true);
    expect(server.requests.filter((r) => r.headers.cookie || r.headers.authorization)).toEqual([]);
  });

  it('turns live checks off through config rules', async () => {
    server.mode = 'bare';
    const { result } = await liveRun(server, 'bare', {}, {});
    expect(result.findings.some((f) => f.ruleId === 'LIVE-001')).toBe(true);
  });
});

describe('--dry-run plan', () => {
  it('lists every request without sending or resolving anything', () => {
    const config = liveConfig('https://app.example.com/dashboard', {
      protectedPaths: [{ path: '/admin' }],
      cookiePaths: ['/account'],
      rateLimitProbe: { path: '/api/login', method: 'POST', maxRequests: 50 },
    });
    const target = liveTarget({ config, env: {} });
    const plan = formatPlan(target, planLive(target, config));
    expect(plan).toContain('Live check plan for https://app.example.com/ (dry run: nothing is sent, not even the ownership check)');
    expect(plan).toMatch(/^ {2}1\. GET {2}https:\/\/app\.example\.com\/\.well-known\/shipcheck\.txt$/m);
    expect(plan).toMatch(/^ {4} DNS {2}TXT _shipcheck\.app\.example\.com$/m);
    expect(plan).toMatch(/POST https:\/\/app\.example\.com\/api\/login \(up to 30 times\)/);
    expect(plan).toContain('GET  http://app.example.com/');
    expect(plan).toContain('TLS  app.example.com:443');
    expect(plan).toMatch(/At most \d+ requests/);
  });
});
