import { describe, expect, it } from 'vitest';
import { MIDDLEWARE_FILES, findMiddleware } from '../../../../src/stacks/nextjs/middleware.js';
import { memoryContext } from '../../../helpers/context.js';

function mw(files: Record<string, string>) {
  return findMiddleware(memoryContext(files));
}

describe('findMiddleware', () => {
  it('checks proxy (Next.js 16+) before the deprecated middleware name, at the root then under src/', () => {
    expect(MIDDLEWARE_FILES).toEqual([
      'proxy.ts',
      'proxy.js',
      'middleware.ts',
      'middleware.js',
      'src/proxy.ts',
      'src/proxy.js',
      'src/middleware.ts',
      'src/middleware.js',
    ]);
  });

  it('returns null when there is no proxy or middleware file', () => {
    expect(mw({ 'app/page.tsx': '' })).toBeNull();
  });

  it('reads a string matcher', () => {
    expect(mw({ 'proxy.ts': "export function proxy() {}\nexport const config = { matcher: '/about/:path*' }" })).toEqual({
      file: 'proxy.ts',
      matchers: ['/about/:path*'],
    });
  });

  it('reads an array matcher from middleware.ts', () => {
    expect(mw({ 'middleware.ts': "export function middleware() {}\nexport const config = { matcher: ['/dashboard/:path*', '/settings'] }" })).toEqual({
      file: 'middleware.ts',
      matchers: ['/dashboard/:path*', '/settings'],
    });
  });

  it('reads source from object matchers', () => {
    const text = "export default function proxy() {}\nexport const config = { matcher: [{ source: '/api/:path*', has: [{ type: 'header', key: 'x' }] }, '/a'] }";
    expect(mw({ 'src/proxy.js': text })?.matchers).toEqual(['/api/:path*', '/a']);
  });

  it('handles typed and satisfies config exports', () => {
    expect(mw({ 'proxy.ts': "import type { ProxyConfig } from 'next/server'\nexport const config: ProxyConfig = { matcher: ['/a'] }" })?.matchers).toEqual(['/a']);
    expect(mw({ 'proxy.ts': "export const config = { matcher: ['/b'] } satisfies Record<string, unknown>" })?.matchers).toEqual(['/b']);
  });

  it('returns null matchers when the proxy runs on every route', () => {
    expect(mw({ 'proxy.ts': 'export function proxy() {}' })).toEqual({ file: 'proxy.ts', matchers: null });
    expect(mw({ 'proxy.ts': "export function proxy() {}\nexport const config = { runtime: 'nodejs' }" })?.matchers).toBeNull();
  });

  it('treats a non-literal matcher as absent, as Next.js ignores dynamic values', () => {
    expect(mw({ 'proxy.ts': "const paths = ['/a']\nexport const config = { matcher: paths }" })?.matchers).toBeNull();
  });

  it('prefers proxy over middleware and the root over src/', () => {
    expect(mw({ 'middleware.ts': '', 'proxy.ts': '' })?.file).toBe('proxy.ts');
    expect(mw({ 'src/proxy.ts': '', 'middleware.ts': '' })?.file).toBe('middleware.ts');
  });
});
