import { describe, expect, it } from 'vitest';
import { auth007 as rule } from '../../../src/packs/nextjs-supabase/rules/auth-007-token-in-storage.js';
import { code, runRule } from '../../helpers/memory-context.js';

const FILE = 'components/token-store.ts';

describe('AUTH-007 Token in Web Storage', () => {
  it('reports tokens written to localStorage', async () => {
    expect(await runRule(rule, { [FILE]: code("'use client'", "export const save = (t: string) => localStorage.setItem('access_token', t)") })).toEqual([
      { file: FILE, line: 2, evidence: "export const save = (t: string) => localStorage.setItem('access_token', t)" },
    ]);
  });

  it('reports sessionStorage with a key held in a constant and direct property writes', async () => {
    expect(await runRule(rule, { [FILE]: code("const KEY = 'supabase.auth.session'", 'export const save = (t: string) => window.sessionStorage.setItem(KEY, t)') })).toHaveLength(1);
    expect(await runRule(rule, { [FILE]: 'export const save = (t: string) => { localStorage.jwt = t }' })).toHaveLength(1);
  });

  it('ignores non-sensitive keys', async () => {
    expect(await runRule(rule, { [FILE]: "export const save = (v: string) => localStorage.setItem('theme', v)" })).toEqual([]);
  });

  it('ignores reads and removals', async () => {
    expect(await runRule(rule, { [FILE]: code("export const read = () => localStorage.getItem('token')", "export const clear = () => localStorage.removeItem('token')") })).toEqual([]);
  });
});
