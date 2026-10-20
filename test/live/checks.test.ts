import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runLive } from '../../src/live/prober.js';
import type { Finding } from '../../src/types.js';
import { tmpProject } from '../helpers/context.js';
import { startMockServer, type MockServer } from './mock-server.js';
import { DAY_MS, fakeSite, liveConfig, liveRun, SECRET, wellKnownPage } from './run-live.js';

let server: MockServer;
beforeAll(async () => {
  server = await startMockServer();
});
afterAll(async () => {
  await server.close();
});

const only = (findings: Finding[], ruleId: string) => findings.filter((f) => f.ruleId === ruleId);
const HARDENED_CONFIG = {
  protectedPaths: [{ path: '/admin' }, { path: '/api/admin' }],
  cookiePaths: ['/account'],
  rateLimitProbe: { path: '/api/login', method: 'POST' as const, maxRequests: 10 },
};

describe('a hardened site', () => {
  it('produces no live findings', async () => {
    const { result, requestsSent } = await liveRun(server, 'hardened', HARDENED_CONFIG);
    expect(result.findings).toEqual([]);
    expect(result.skipped).toEqual([]);
    expect(requestsSent).toBeLessThanOrEqual(60);
  });
});

describe('LIVE-001 security headers', () => {
  it('reports missing headers and version leaks in one finding', async () => {
    const { result } = await liveRun(server, 'bare');
    expect(only(result.findings, 'LIVE-001')).toEqual([
      expect.objectContaining({
        severity: 'medium',
        source: 'live',
        category: 'live',
        file: null,
        url: `${server.url}/`,
        evidence:
          'GET / (HTTP 200): missing CSP, HSTS, X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy, Permissions-Policy; exposes X-Powered-By: Next.js, Server: nginx/1.25.3',
      }),
    ]);
  });
});

describe('LIVE-002 HTTPS enforcement', () => {
  it('reports plain HTTP that is served instead of redirected', async () => {
    const { result } = await liveRun(server, 'bare');
    expect(only(result.findings, 'LIVE-002')).toEqual([expect.objectContaining({ severity: 'high', url: `${server.httpUrl}/`, evidence: `GET ${server.httpUrl}/ → HTTP 200` })]);
  });

  const site = 'https://app.example.com/';
  const run = (pages: Parameters<typeof fakeSite>[0], validInDays = 90) =>
    runLive({
      url: site,
      config: liveConfig(site),
      root: tmpProject({}),
      env: { SHIPCHECK_LIVE_SECRET: SECRET },
      resolve: async () => [{ address: '93.184.215.14', family: 4 }],
      transport: fakeSite({ 'https://app.example.com/.well-known/shipcheck.txt': wellKnownPage(), ...pages }).transport,
      tlsProbe: async () => ({ validTo: new Date(Date.UTC(2026, 9, 20) + validInDays * DAY_MS) }),
      now: () => Date.UTC(2026, 9, 20),
      sleep: async () => {},
    });

  it('reports a temporary redirect, a short HSTS max-age and a certificate about to expire', async () => {
    const { result } = await run(
      {
        'http://app.example.com/': { status: 302, headers: { location: 'https://app.example.com/' } },
        [site]: { status: 200, headers: { 'strict-transport-security': 'max-age=300' } },
      },
      5,
    );
    expect(only(result.findings, 'LIVE-002').map((f) => `${f.severity} ${f.evidence}`)).toEqual([
      'high GET http://app.example.com/ → HTTP 302 (Location: https://app.example.com/)',
      'medium Strict-Transport-Security: max-age=300',
      'medium TLS certificate for app.example.com expires on 2026-10-25',
    ]);
  });

  it('accepts a permanent redirect to https on the same host and a closed port 80', async () => {
    const hsts = { [site]: { status: 200, headers: { 'strict-transport-security': 'max-age=63072000' } } };
    const redirect = await run({ 'http://app.example.com/': { status: 308, headers: { location: 'https://app.example.com/' } }, ...hsts });
    expect(only(redirect.result.findings, 'LIVE-002')).toEqual([]);
    const closed = await run({ 'http://app.example.com/': new Error('connect ECONNREFUSED'), ...hsts });
    expect(only(closed.result.findings, 'LIVE-002')).toEqual([]);
  });

  it('reports a permanent redirect to another host', async () => {
    const { result } = await run({ 'http://app.example.com/': { status: 301, headers: { location: 'https://www.example.net/' } } });
    expect(only(result.findings, 'LIVE-002')).toEqual([expect.objectContaining({ severity: 'high' })]);
  });
});

describe('LIVE-003 rate limit', () => {
  it('stops at the first 429 and reports nothing', async () => {
    server.requests.length = 0;
    const { result } = await liveRun(server, 'limit-10', { rateLimitProbe: { path: '/api/login', method: 'POST', maxRequests: 15 } });
    expect(only(result.findings, 'LIVE-003')).toEqual([]);
    expect(server.requests.filter((r) => r.path === '/api/login').map((r) => r.method)).toEqual(Array(11).fill('POST'));
  });

  it('reports a probe that never sees a 429, capped at 30 requests', async () => {
    server.requests.length = 0;
    const { result } = await liveRun(server, 'no-limit', { rateLimitProbe: { path: '/api/login', method: 'GET', maxRequests: 50 } });
    expect(only(result.findings, 'LIVE-003')).toEqual([expect.objectContaining({ severity: 'medium', evidence: '30 × GET /api/login in about 3 s: no 429 (last status 200)' })]);
    expect(server.requests.filter((r) => r.path === '/api/login')).toHaveLength(30);
  });

  it('is skipped without a probe or without enough budget', async () => {
    const none = await liveRun(server, 'no-limit');
    expect(none.result.skipped).toContainEqual({ check: 'LIVE-003', reason: 'no live.rateLimitProbe configured' });
    const tight = await liveRun(server, 'no-limit', { maxRequests: 15, rateLimitProbe: { path: '/api/login', method: 'GET', maxRequests: 30 } });
    expect(tight.result.skipped).toContainEqual({ check: 'LIVE-003', reason: expect.stringMatching(/needs 30 requests but only \d+ remain/) });
  });
});

describe('LIVE-004 protected endpoints', () => {
  it('reports protected paths that answer anonymous requests with content', async () => {
    const { result } = await liveRun(server, 'open-admin', { protectedPaths: [{ path: '/admin' }, { path: '/api/admin', method: 'HEAD' }] });
    expect(only(result.findings, 'LIVE-004').map((f) => `${f.severity} ${f.evidence}`)).toEqual([
      expect.stringMatching(/^high GET \/admin without credentials → HTTP 200 with a \d+-byte body$/),
      expect.stringMatching(/^high HEAD \/api\/admin without credentials → HTTP 200 with a \d+-byte body$/),
    ]);
  });

  it('accepts 401, 403 and redirects to a login page', async () => {
    const { result } = await liveRun(server, 'hardened', { protectedPaths: [{ path: '/admin' }, { path: '/dashboard' }, { path: '/api/admin' }] });
    expect(only(result.findings, 'LIVE-004')).toEqual([]);
  });
});

describe('LIVE-005 sensitive files', () => {
  it('reports exposed files by signature, without their contents', async () => {
    const { result } = await liveRun(server, 'leaky');
    const findings = only(result.findings, 'LIVE-005');
    expect(findings.map((f) => `${f.severity} ${f.evidence}`).sort()).toEqual(
      [
        'critical GET /.env → HTTP 200, an environment file with KEY=value lines',
        'critical GET /.env.local → HTTP 200, an environment file with KEY=value lines',
        'critical GET /.git/config → HTTP 200, a git config ([core] section)',
        'critical GET /.git/HEAD → HTTP 200, a git HEAD (ref: refs/...)',
        'critical GET /backup.zip → HTTP 200, a zip archive (PK header)',
        'medium GET /.DS_Store → HTTP 200, a macOS .DS_Store directory listing',
        'medium GET /_next/static/chunks/main-abc123.js.map → HTTP 200, a source map with the original sources',
      ].sort(),
    );
    expect(JSON.stringify(result)).not.toMatch(/FAKEFAKE|postgres:|repositoryformatversion/);
  });

  it('ignores soft 404 pages that answer 200 for everything', async () => {
    const { result } = await liveRun(server, 'soft404');
    expect(only(result.findings, 'LIVE-005')).toEqual([]);
  });
});

describe('LIVE-006 cookies', () => {
  it('reports session cookies without HttpOnly, Secure or SameSite, ignoring analytics cookies', async () => {
    const { result } = await liveRun(server, 'bad-cookie', { cookiePaths: ['/account'] });
    expect(only(result.findings, 'LIVE-006').map((f) => f.evidence)).toEqual([
      'Set-Cookie: session=<redacted> (path) is missing HttpOnly, Secure, SameSite',
      'Set-Cookie: sid=<redacted> (path) is missing HttpOnly, Secure, SameSite',
    ]);
    expect(JSON.stringify(result)).not.toContain('FAKEFAKE');
  });

  it('accepts cookies with all three flags', async () => {
    const { result } = await liveRun(server, 'hardened', { cookiePaths: ['/account'] });
    expect(only(result.findings, 'LIVE-006')).toEqual([]);
  });
});
