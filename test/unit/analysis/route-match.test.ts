import { describe, expect, it } from 'vitest';
import { isCoveredByMatchers, matcherMatches, matchesGlob, samplePath } from '../../../src/packs/nextjs-supabase/analysis/route-match.js';

describe('samplePath', () => {
  it('fills dynamic segments with concrete values', () => {
    expect(samplePath('/api/invoices/[id]')).toBe('/api/invoices/param');
    expect(samplePath('/blog/[...slug]')).toBe('/blog/param/param');
    expect(samplePath('/docs/[[...slug]]')).toBe('/docs/param');
    expect(samplePath('/')).toBe('/');
  });
});

describe('matcherMatches (Next.js matcher semantics)', () => {
  it.each([
    ['/dashboard/:path*', '/dashboard', true],
    ['/dashboard/:path*', '/dashboard/a/b', true],
    ['/dashboard/:path*', '/api/dashboard', false],
    ['/api/:path+', '/api/x', true],
    ['/api/:path+', '/api', false],
    ['/about', '/about', true],
    ['/about', '/about/team', false],
    ['/((?!api|_next/static|_next/image|favicon.ico).*)', '/dashboard', true],
    ['/((?!api|_next/static|_next/image|favicon.ico).*)', '/api/x', false],
    ['/(api|trpc)(.*)', '/api/users', true],
  ])('%s against %s -> %s', (matcher, path, expected) => {
    expect(matcherMatches(matcher, path)).toBe(expected);
  });

  it('treats an unparseable matcher as matching nothing', () => {
    expect(matcherMatches('/((unclosed', '/x')).toBe(false);
  });
});

describe('isCoveredByMatchers', () => {
  it('covers everything when there are no matchers', () => {
    expect(isCoveredByMatchers('/api/x', null)).toBe(true);
  });

  it('uses a sample path for dynamic routes', () => {
    expect(isCoveredByMatchers('/dashboard/[id]', ['/dashboard/:path*'])).toBe(true);
    expect(isCoveredByMatchers('/api/admin/users', ['/dashboard/:path*'])).toBe(false);
  });
});

describe('matchesGlob', () => {
  it.each([
    ['/api/public/a/b', '/api/public/**', true],
    ['/api/public', '/api/public/**', true],
    ['/api/webhooks/stripe', '/api/webhooks/*', true],
    ['/api/webhooks/a/b', '/api/webhooks/*', false],
    ['/api/status', '/api/status', true],
    ['/api/statuses', '/api/status', false],
    ['/api/v1.2/x', '/api/v1.2/*', true],
    ['/api/v1x2/x', '/api/v1.2/*', false],
  ])('%s vs %s -> %s', (path, glob, expected) => {
    expect(matchesGlob(path, glob)).toBe(expected);
  });
});
