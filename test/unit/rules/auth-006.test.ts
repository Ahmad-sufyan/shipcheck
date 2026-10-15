import { describe, expect, it } from 'vitest';
import { auth006 as rule } from '../../../src/packs/nextjs-supabase/rules/auth-006-weak-jwt-secret.js';
import { code, runRule } from '../../helpers/memory-context.js';

const FILE = 'lib/auth/jwt.ts';

describe('AUTH-006 Weak JWT secret', () => {
  it('reports a literal secret at its declaration, once for sign and verify', async () => {
    const text = code("import jwt from 'jsonwebtoken'", "const JWT_SECRET = 'secret123'", 'export const issue = () => jwt.sign({}, JWT_SECRET)', 'export const read = (t: string) => jwt.verify(t, JWT_SECRET)');
    expect(await runRule(rule, { [FILE]: text })).toEqual([{ file: FILE, line: 2, evidence: "const JWT_SECRET = 'secret123'" }]);
  });

  it('reports inline literals and env fallbacks', async () => {
    expect(await runRule(rule, { [FILE]: code("import { verify } from 'jsonwebtoken'", "export const read = (t: string) => verify(t, 'dev-secret')") })).toEqual([expect.objectContaining({ line: 2 })]);
    expect(await runRule(rule, { [FILE]: code("import jwt from 'jsonwebtoken'", "const key = process.env.JWT_SECRET ?? 'changeme'", 'export const issue = () => jwt.sign({}, key)') })).toEqual([expect.objectContaining({ line: 2 })]);
  });

  it('reports jose keys encoded from literals', async () => {
    const text = code("import { jwtVerify } from 'jose'", "const key = new TextEncoder().encode('super-secret')", 'export const read = (t: string) => jwtVerify(t, key)');
    expect(await runRule(rule, { [FILE]: text })).toEqual([expect.objectContaining({ line: 2 })]);
  });

  it('reports short or common secrets in env files, but not example files', async () => {
    expect(await runRule(rule, { '.env.local': 'JWT_SECRET=password\nNEXTAUTH_SECRET=0123456789abcdef0123456789abcdef' })).toEqual([{ file: '.env.local', line: 1, evidence: 'JWT_SECRET=<8 chars>' }]);
    expect(await runRule(rule, { '.env.example': 'JWT_SECRET=changeme' })).toEqual([]);
  });

  it('ignores secrets that come from the environment', async () => {
    expect(await runRule(rule, { [FILE]: code("import jwt from 'jsonwebtoken'", 'export const issue = () => jwt.sign({}, process.env.JWT_SECRET!)') })).toEqual([]);
  });

  it('ignores test directories', async () => {
    expect(await runRule(rule, { 'tests/jwt.test.ts': code("import jwt from 'jsonwebtoken'", "jwt.sign({}, 'test-secret')") })).toEqual([]);
  });
});
