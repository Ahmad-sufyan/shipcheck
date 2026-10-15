import { parse, tokensToRegexp } from 'path-to-regexp';

const compiled = new Map<string, RegExp | null>();

/**
 * Compiles a proxy/middleware matcher the way Next.js does: path-to-regexp 6.3.0 (the version Next
 * pins), `tokensToRegexp(parse(source))` with default options (end: true, strict: false), then only
 * the regex source is kept, so matching is case-sensitive.
 */
function compile(matcher: string): RegExp | null {
  let regex = compiled.get(matcher);
  if (regex === undefined) {
    try {
      regex = new RegExp(tokensToRegexp(parse(matcher)).source);
    } catch {
      regex = null;
    }
    compiled.set(matcher, regex);
  }
  return regex;
}

export function matcherMatches(matcher: string, path: string): boolean {
  return compile(matcher)?.test(path) ?? false;
}

/** A concrete URL path for an App Router route path: dynamic segments become `param`. */
export function samplePath(routePath: string): string {
  return routePath
    .replace(/\[\[\.\.\.[^\]]+\]\]/g, 'param')
    .replace(/\[\.\.\.[^\]]+\]/g, 'param/param')
    .replace(/\[[^\]]+\]/g, 'param');
}

/** Whether a route path is matched by any of the matchers; null matchers mean the proxy runs everywhere. */
export function isCoveredByMatchers(routePath: string, matchers: readonly string[] | null): boolean {
  if (matchers === null) return true;
  const path = samplePath(routePath);
  return matchers.some((matcher) => matcherMatches(matcher, path));
}

const globs = new Map<string, RegExp>();

/** Route-path globs for publicPaths: `**` spans segments, `*` and `?` stay within one. */
export function matchesGlob(path: string, glob: string): boolean {
  let regex = globs.get(glob);
  if (!regex) {
    let source = '';
    for (let i = 0; i < glob.length; i++) {
      const ch = glob[i]!;
      if (glob.startsWith('/**', i) && i + 3 === glob.length) {
        source += '(?:/.*)?';
        i += 2;
      } else if (glob.startsWith('**', i)) {
        source += '.*';
        i += 1;
      } else if (ch === '*') {
        source += '[^/]*';
      } else if (ch === '?') {
        source += '[^/]';
      } else {
        source += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
      }
    }
    regex = new RegExp(`^${source}$`);
    globs.set(glob, regex);
  }
  return regex.test(path);
}
