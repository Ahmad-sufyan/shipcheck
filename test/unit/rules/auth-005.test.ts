import { describe, expect, it } from 'vitest';
import { auth005 as rule } from '../../../src/packs/nextjs-supabase/rules/auth-005-jwt-not-pinned.js';
import { code, runRule } from '../../helpers/memory-context.js';

const FILE = 'lib/auth/jwt.ts';
const lib = (...lines: string[]) => code("import jwt from 'jsonwebtoken'", 'const secret = process.env.JWT_SECRET!', ...lines);

describe('AUTH-005 JWT verification not pinned', () => {
  it('reports jwt.verify without algorithms with medium confidence (jsonwebtoken 9 limits defaults to the key type)', async () => {
    expect(await runRule(rule, { [FILE]: lib('export const read = (t: string) => jwt.verify(t, secret)') })).toEqual([
      expect.objectContaining({ line: 3, confidence: 'medium' }),
    ]);
  });

  it("reports algorithms that include 'none'", async () => {
    const findings = await runRule(rule, { [FILE]: lib("export const read = (t: string) => jwt.verify(t, secret, { algorithms: ['HS256', 'none'] })") });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.confidence).toBeUndefined();
  });

  it('reports jwt.sign without an expiry', async () => {
    expect(await runRule(rule, { [FILE]: lib('export const issue = (sub: string) => jwt.sign({ sub }, secret)') })).toEqual([expect.objectContaining({ line: 3 })]);
  });

  it('reports jwt.decode used to make a decision', async () => {
    const text = lib('export function isAdmin(t: string) {', '  const claims = jwt.decode(t) as { role?: string }', "  if (claims?.role === 'admin') return true", '  return false', '}');
    expect(await runRule(rule, { [FILE]: text })).toEqual([expect.objectContaining({ line: 4 })]);
  });

  it('reports jose SignJWT without setExpirationTime', async () => {
    const text = code("import { SignJWT } from 'jose'", "export const issue = (key: Uint8Array) => new SignJWT({ sub: '1' }).setProtectedHeader({ alg: 'HS256' }).sign(key)");
    expect(await runRule(rule, { [FILE]: text })).toHaveLength(1);
  });

  it('ignores pinned verification and expiring tokens', async () => {
    const text = lib(
      "export const read = (t: string) => jwt.verify(t, secret, { algorithms: ['HS256'] })",
      "export const issue = (sub: string) => jwt.sign({ sub }, secret, { algorithm: 'HS256', expiresIn: '1h' })",
      'export const issue2 = (sub: string) => jwt.sign({ sub, exp: Math.floor(Date.now() / 1000) + 3600 }, secret)',
    );
    expect(await runRule(rule, { [FILE]: text })).toEqual([]);
  });

  it('ignores jose tokens with an expiration and decode used only for display', async () => {
    const text = code(
      "import { SignJWT, decodeJwt } from 'jose'",
      "export const issue = (key: Uint8Array) => new SignJWT({}).setProtectedHeader({ alg: 'HS256' }).setExpirationTime('2h').sign(key)",
      'export const label = (t: string) => String(decodeJwt(t).sub)',
    );
    expect(await runRule(rule, { [FILE]: text })).toEqual([]);
  });
});
