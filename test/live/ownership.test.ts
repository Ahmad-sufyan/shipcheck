import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { LiveClient } from '../../src/live/client.js';
import { LiveRefusal } from '../../src/live/errors.js';
import { hashSecret, initOwnership, loadSecret, verifyOwnership, type TxtResolver } from '../../src/live/ownership.js';
import { tmpProject } from '../helpers/context.js';
import { startMockServer, type MockServer } from './mock-server.js';

const SECRET = 'a'.repeat(64);
const HASH = createHash('sha256').update(SECRET).digest('hex');
const noTxt: TxtResolver = async () => {
  throw Object.assign(new Error('queryTxt ENOTFOUND'), { code: 'ENOTFOUND' });
};

let server: MockServer;
beforeEach(async () => {
  server = await startMockServer({ mode: 'hardened' });
});
afterEach(async () => {
  await server.close();
});

const client = () => new LiveClient({ origin: new URL(server.url), allowLocal: true, sleep: async () => {} });

describe('initOwnership', () => {
  it('stores a random 32-byte secret, ignores .shipcheck/ in git and explains what to serve', () => {
    const root = tmpProject({ '.gitignore': 'node_modules\n' });
    const setup = initOwnership(root, 'https://app.example.com/dashboard');
    const secret = readFileSync(join(root, '.shipcheck/live-secret'), 'utf8').trim();
    expect(secret).toMatch(/^[0-9a-f]{64}$/);
    expect(setup).toMatchObject({
      created: true,
      hash: hashSecret(secret),
      wellKnownUrl: 'https://app.example.com/.well-known/shipcheck.txt',
      wellKnownContent: `shipcheck-site-verification=${hashSecret(secret)}`,
      dnsName: '_shipcheck.app.example.com',
    });
    expect(setup.hash).not.toContain(secret);
    expect(readFileSync(join(root, '.gitignore'), 'utf8')).toBe('node_modules\n.shipcheck/\n');
  });

  it('keeps an existing secret unless forced, and creates .gitignore when missing', () => {
    const root = tmpProject({});
    const first = initOwnership(root, 'https://app.example.com');
    expect(readFileSync(join(root, '.gitignore'), 'utf8')).toBe('.shipcheck/\n');
    expect(initOwnership(root, 'https://app.example.com')).toMatchObject({ created: false, hash: first.hash });
    expect(initOwnership(root, 'https://app.example.com', { force: true }).hash).not.toBe(first.hash);
    expect(readFileSync(join(root, '.gitignore'), 'utf8')).toBe('.shipcheck/\n');
  });

  it('refuses IP addresses and non-https URLs', () => {
    const root = tmpProject({});
    expect(() => initOwnership(root, 'https://203.0.113.9')).toThrow(LiveRefusal);
    expect(() => initOwnership(root, 'http://app.example.com')).toThrow(/https/);
    expect(existsSync(join(root, '.shipcheck'))).toBe(false);
  });
});

describe('loadSecret', () => {
  it('prefers SHIPCHECK_LIVE_SECRET (CI), then .shipcheck/live-secret', () => {
    const root = tmpProject({ '.shipcheck/live-secret': `${SECRET}\n` });
    expect(loadSecret(root, {})).toBe(SECRET);
    expect(loadSecret(root, { SHIPCHECK_LIVE_SECRET: 'b'.repeat(64) })).toBe('b'.repeat(64));
  });

  it('refuses with setup instructions when there is no secret', () => {
    expect(() => loadSecret(tmpProject({}), {})).toThrow(/shipcheck live init/);
  });
});

describe('verifyOwnership', () => {
  it('passes when the well-known file serves sha256(secret)', async () => {
    server.wellKnown = `shipcheck-site-verification=${HASH}\n`;
    expect(await verifyOwnership(client(), SECRET, { resolveTxt: noTxt })).toEqual({ method: 'well-known' });
  });

  it('fails when the raw secret is served instead of its hash', async () => {
    server.wellKnown = `shipcheck-site-verification=${SECRET}\n`;
    await expect(verifyOwnership(client(), SECRET, { resolveTxt: noTxt })).rejects.toThrow(/raw secret/);
  });

  it('fails when the file is missing and there is no DNS record', async () => {
    server.wellKnown = null;
    await expect(verifyOwnership(client(), SECRET, { resolveTxt: noTxt })).rejects.toThrow(LiveRefusal);
    await expect(verifyOwnership(client(), SECRET, { resolveTxt: noTxt })).rejects.toThrow(/HTTP 404/);
  });

  it('fails on a wrong hash', async () => {
    server.wellKnown = `shipcheck-site-verification=${'0'.repeat(64)}`;
    await expect(verifyOwnership(client(), SECRET, { resolveTxt: noTxt })).rejects.toThrow(/does not match/);
  });

  it('does not follow a redirect to another host', async () => {
    const other = await startMockServer({ wellKnown: `shipcheck-site-verification=${HASH}` });
    try {
      server.wellKnown = { redirect: `http://localhost:${other.port}/.well-known/shipcheck.txt` };
      await expect(verifyOwnership(client(), SECRET, { resolveTxt: noTxt })).rejects.toThrow(/another host/);
      expect(other.count).toBe(0);
    } finally {
      await other.close();
    }
  });

  it('accepts a DNS TXT record at _shipcheck.<host>, joining split strings', async () => {
    server.wellKnown = null;
    const names: string[] = [];
    const resolveTxt: TxtResolver = async (name) => {
      names.push(name);
      return [['v=spf1 -all'], ['shipcheck-site-verification=', HASH]];
    };
    expect(await verifyOwnership(client(), SECRET, { resolveTxt })).toEqual({ method: 'dns' });
    expect(names).toEqual(['_shipcheck.127.0.0.1']);
  });

  it('rejects a DNS record that holds the raw secret', async () => {
    server.wellKnown = null;
    await expect(verifyOwnership(client(), SECRET, { resolveTxt: async () => [[`shipcheck-site-verification=${SECRET}`]] })).rejects.toThrow(/raw secret/);
  });

  it('counts its request against the budget', async () => {
    server.wellKnown = `shipcheck-site-verification=${HASH}`;
    const c = client();
    await verifyOwnership(c, SECRET, { resolveTxt: noTxt });
    expect(c.sent).toBe(1);
    expect(server.requests.map((r) => r.path)).toEqual(['/.well-known/shipcheck.txt']);
  });
});

