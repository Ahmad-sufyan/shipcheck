import { describe, expect, it } from 'vitest';
import { LiveRefusal } from '../../src/live/errors.js';
import { isNonPublicAddress, resolvePublicAddress, type HostResolver } from '../../src/live/guard.js';

const resolver =
  (table: Record<string, string[]>): HostResolver =>
  async (hostname) =>
    (table[hostname] ?? []).map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));

describe('isNonPublicAddress', () => {
  it.each([
    '127.0.0.1',
    '127.255.0.9',
    '10.1.2.3',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.1',
    '169.254.169.254',
    '0.0.0.0',
    '100.64.0.1',
    '224.0.0.1',
    '255.255.255.255',
    '::1',
    '::',
    'fe80::1',
    'fc00::1',
    'fd12:3456::1',
    '::ffff:127.0.0.1',
    '::ffff:10.0.0.1',
    '::ffff:a9fe:a9fe',
  ])('treats %s as non-public', (ip) => {
    expect(isNonPublicAddress(ip)).toBe(true);
  });

  it.each(['8.8.8.8', '1.1.1.1', '172.32.0.1', '100.128.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8'])('treats %s as public', (ip) => {
    expect(isNonPublicAddress(ip)).toBe(false);
  });
});

describe('resolvePublicAddress', () => {
  const dns = resolver({ 'app.example.com': ['93.184.215.14'], 'internal.example.com': ['10.0.0.5'], 'mixed.example.com': ['93.184.215.14', '192.168.0.10'], localhost: ['127.0.0.1', '::1'] });

  it('returns the first address of a public hostname', async () => {
    expect(await resolvePublicAddress('app.example.com', { resolve: dns, allowLocal: false })).toEqual({ address: '93.184.215.14', family: 4 });
  });

  it.each(['93.184.215.14', '127.0.0.1', '[::1]', '::1'])('refuses the IP literal %s', async (host) => {
    await expect(resolvePublicAddress(host, { resolve: dns, allowLocal: false })).rejects.toThrow(LiveRefusal);
    await expect(resolvePublicAddress(host, { resolve: dns, allowLocal: false })).rejects.toThrow(/IP address/);
  });

  it.each(['internal.example.com', 'mixed.example.com', 'localhost'])('refuses %s, which resolves to a private or loopback address', async (host) => {
    await expect(resolvePublicAddress(host, { resolve: dns, allowLocal: false })).rejects.toThrow(/private, loopback or link-local/);
  });

  it('refuses hostnames that do not resolve', async () => {
    await expect(resolvePublicAddress('nowhere.example.com', { resolve: dns, allowLocal: false })).rejects.toThrow(/could not be resolved/);
  });

  it('allows local targets only with allowLocal (SHIPCHECK_ALLOW_LOCAL=1, tests only)', async () => {
    expect(await resolvePublicAddress('127.0.0.1', { resolve: dns, allowLocal: true })).toEqual({ address: '127.0.0.1', family: 4 });
    expect(await resolvePublicAddress('internal.example.com', { resolve: dns, allowLocal: true })).toEqual({ address: '10.0.0.5', family: 4 });
  });
});
