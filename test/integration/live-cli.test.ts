import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { hashSecret } from '../../src/live/ownership.js';
import { ScanResultSchema } from '../../src/schema.js';
import { shipcheck } from '../helpers/cli.js';
import { tmpProject } from '../helpers/context.js';
import { startMockServer, type MockServer } from '../live/mock-server.js';
import { SECRET } from '../live/run-live.js';

const WARNING = /may be illegal/;

let server: MockServer;
beforeAll(async () => {
  server = await startMockServer();
});
afterAll(async () => {
  await server.close();
});
beforeEach(() => {
  server.requests.length = 0;
  server.wellKnown = `shipcheck-site-verification=${hashSecret(SECRET)}`;
});

/** A project whose config points live checks at the mock server; LIVE-002 is off because the CLI cannot reach the mock's HTTP port. */
const project = () =>
  tmpProject({
    'shipcheck.config.json': JSON.stringify({ rules: { 'LIVE-002': 'off' }, live: { url: server.url, protectedPaths: [{ path: '/admin' }], cookiePaths: ['/account'] } }),
  });
const env = (extra: Record<string, string> = {}) => ({ SHIPCHECK_ALLOW_LOCAL: '1', SHIPCHECK_LIVE_SECRET: undefined, ...extra });

describe('shipcheck live', () => {
  it('--dry-run prints the plan and the warning and sends nothing', async () => {
    const { exitCode, stdout, stderr } = await shipcheck(['live', '--root', project(), '--dry-run'], env({ SHIPCHECK_LIVE_SECRET: SECRET }));
    expect(exitCode).toBe(0);
    expect(stderr).toMatch(WARNING);
    expect(stdout).toContain(`  1. GET  ${server.url}/.well-known/shipcheck.txt`);
    expect(stdout).toContain(`GET  ${server.url}/admin`);
    expect(server.count).toBe(0);
  });

  it('--dry-run works for a site that is not set up yet', async () => {
    const { exitCode, stdout, stderr } = await shipcheck(['live', 'https://example.com', '--dry-run'], { SHIPCHECK_LIVE_SECRET: undefined });
    expect(exitCode).toBe(0);
    expect(stderr).toMatch(WARNING);
    expect(stdout).toContain('Live check plan for https://example.com/');
  });

  it('refuses without a secret, with setup instructions, and sends nothing', async () => {
    const { exitCode, stderr } = await shipcheck(['live', '--root', project()], env());
    expect(exitCode).toBe(2);
    expect(stderr).toMatch(WARNING);
    expect(stderr).toContain('shipcheck live init');
    expect(server.count).toBe(0);
  });

  it('runs the checks after verifying ownership', async () => {
    server.mode = 'hardened';
    const { exitCode, stdout, stderr } = await shipcheck(['live', '--root', project(), '--format', 'json'], env({ SHIPCHECK_LIVE_SECRET: SECRET }));
    expect(stderr).toMatch(/ownership verified via the well-known file; \d+ requests sent/);
    expect(exitCode).toBe(0);
    const result = ScanResultSchema.parse(JSON.parse(stdout));
    expect(result.target.path).toBe(`${server.url}/`);
    expect(result.findings).toEqual([]);
    expect(server.requests[0]?.path).toBe('/.well-known/shipcheck.txt');
  });

  it('exits 1 on blocking live findings', async () => {
    server.mode = 'leaky';
    const { exitCode, stdout } = await shipcheck(['live', '--root', project(), '--format', 'json'], env({ SHIPCHECK_LIVE_SECRET: SECRET }));
    expect(exitCode).toBe(1);
    expect(JSON.parse(stdout).findings.filter((f: { ruleId: string }) => f.ruleId === 'LIVE-005').length).toBeGreaterThan(0);
  });
});

describe('shipcheck live init', () => {
  it('creates the secret, ignores it in git and prints the hash to serve', async () => {
    const root = tmpProject({});
    const { exitCode, stdout } = await shipcheck(['live', 'init', 'https://app.example.com', '--root', root]);
    expect(exitCode).toBe(0);
    const secret = readFileSync(join(root, '.shipcheck/live-secret'), 'utf8').trim();
    expect(stdout).toContain(`shipcheck-site-verification=${hashSecret(secret)}`);
    expect(stdout).toContain('https://app.example.com/.well-known/shipcheck.txt');
    expect(stdout).not.toContain(secret);
    expect(readFileSync(join(root, '.gitignore'), 'utf8')).toContain('.shipcheck/');
  });
});
