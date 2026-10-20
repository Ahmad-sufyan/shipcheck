import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ShipcheckError } from '../../../src/core/errors.js';
import { loadUserConfig } from '../../../src/context/user-config.js';
import { tmpProject } from '../../helpers/context.js';

const defaults = { ignorePaths: [], authHelpers: [], rateLimitHelpers: [], publicPaths: [], webhookVerifiers: [], rules: {} };

describe('loadUserConfig', () => {
  it('returns defaults when there is no config file', () => {
    expect(loadUserConfig(tmpProject({ 'a.ts': '' }))).toEqual({ config: defaults, file: null });
  });

  it('loads shipcheck.config.json from the scan root', () => {
    const root = tmpProject({ 'shipcheck.config.json': '{"ignorePaths":["legacy/**"],"rules":{"HTTP-006":"off"}}' });
    const { config, file } = loadUserConfig(root);
    expect(config).toEqual({ ...defaults, ignorePaths: ['legacy/**'], rules: { 'HTTP-006': 'off' } });
    expect(file).toBe(join(root, 'shipcheck.config.json'));
  });

  it('loads an explicit config path instead of the default', () => {
    const root = tmpProject({ 'shipcheck.config.json': '{"authHelpers":["a"]}', 'custom.json': '{"authHelpers":["requireUser"]}' });
    expect(loadUserConfig(root, join(root, 'custom.json')).config.authHelpers).toEqual(['requireUser']);
  });

  it('fails clearly when an explicit config file is missing', () => {
    const root = tmpProject({});
    expect(() => loadUserConfig(root, join(root, 'nope.json'))).toThrow(ShipcheckError);
    expect(() => loadUserConfig(root, join(root, 'nope.json'))).toThrow(/Config file not found/);
  });

  it('fails clearly on invalid JSON', () => {
    const root = tmpProject({ 'shipcheck.config.json': '{ "ignorePaths": [' });
    expect(() => loadUserConfig(root)).toThrow(ShipcheckError);
    expect(() => loadUserConfig(root)).toThrow(/shipcheck\.config\.json.*not valid JSON/);
  });

  it('rejects ignorePaths that could exhaust brace expansion (GHSA-vfj7-8cjw-p6xm)', () => {
    const load = (pattern: string) => () => loadUserConfig(tmpProject({ 'shipcheck.config.json': JSON.stringify({ ignorePaths: [pattern] }) }));
    expect(load('legacy/**/*.{js,ts}')).not.toThrow();
    expect(load('{a,{b,c}}/**')).not.toThrow();
    expect(load('{a,{b,{c,d}}}')).toThrow(/at most 2 levels deep/);
    expect(load('{a,b}'.repeat(7))).toThrow(/at most 64 patterns/);
    expect(load('a'.repeat(257))).toThrow(/256 characters/);
  });

  it('fails clearly on schema violations, naming the offending key', () => {
    const root = tmpProject({ 'shipcheck.config.json': '{"rules":{"HTTP-006":"loud"}}' });
    expect(() => loadUserConfig(root)).toThrow(/rules\.HTTP-006/);
    const typo = tmpProject({ 'shipcheck.config.json': '{"ignorePath":[]}' });
    expect(() => loadUserConfig(typo)).toThrow(/ignorePath/);
  });
});
