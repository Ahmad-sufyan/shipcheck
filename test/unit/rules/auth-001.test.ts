import { describe, expect, it } from 'vitest';
import { auth001 as rule } from '../../../src/packs/nextjs-supabase/rules/auth-001-weak-password-hash.js';
import { code, runRule } from '../../helpers/memory-context.js';

const FILE = 'lib/auth/password.ts';
const fn = (...body: string[]) => code("import { createHash, scrypt } from 'node:crypto'", 'export function hashPassword(password: string, salt: string) {', ...body.map((l) => `  ${l}`), '}');

describe('AUTH-001 Weak password hashing', () => {
  it("reports createHash('md5') over a password", async () => {
    expect(await runRule(rule, { [FILE]: fn("return createHash('md5').update(password).digest('hex')") })).toEqual([
      { file: FILE, line: 3, evidence: "return createHash('md5').update(password).digest('hex')" },
    ]);
  });

  it('reports salted fast hashes and password-named properties', async () => {
    expect(await runRule(rule, { [FILE]: fn("return crypto.createHash('sha256').update(`${salt}${password}`).digest('hex')") })).toHaveLength(1);
    expect(await runRule(rule, { [FILE]: fn("return createHash('sha1').update(user.pwd).digest('hex')") })).toHaveLength(1);
  });

  it('ignores fast hashes over values that are not passwords', async () => {
    expect(await runRule(rule, { [FILE]: fn("return createHash('sha256').update(token).digest('hex')") })).toEqual([]);
  });

  it('ignores password hashing with slow KDFs', async () => {
    expect(await runRule(rule, { [FILE]: fn('return new Promise((r) => scrypt(password, salt, 64, (e, k) => r(k)))') })).toEqual([]);
  });
});
