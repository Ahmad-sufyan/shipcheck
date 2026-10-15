import { SECRET_PATTERNS, shannonEntropy } from '../../../core/redact.js';

// The redactor owns the regexes, so anything a rule detects is also masked in its evidence.
export { redactSecrets, shannonEntropy as entropy } from '../../../core/redact.js';

export interface SecretMatch {
  /** Pattern id, e.g. `stripe-secret-key` or `supabase-service-role-jwt`. */
  id: string;
  name: string;
  value: string;
  index: number;
}

interface Detector {
  id: string;
  name: string;
  regex: RegExp;
  accept?: (value: string) => boolean;
}

function jwtClaims(token: string): Record<string, unknown> | undefined {
  const payload = token.split('.')[1];
  if (!payload) return undefined;
  try {
    const claims: unknown = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return claims && typeof claims === 'object' ? (claims as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

/** The `role` claim of a JWT (Supabase keys carry `anon` or `service_role`), without verifying it. */
export function jwtRole(token: string): string | undefined {
  const role = jwtClaims(token)?.role;
  return typeof role === 'string' ? role : undefined;
}

/**
 * A Supabase service_role JWT. The well-known keys the Supabase CLI ships for local development
 * (issuer `supabase-demo`) are public, so they do not count.
 */
export function isSupabaseServiceJwt(token: string): boolean {
  const claims = jwtClaims(token);
  return claims?.role === 'service_role' && claims.iss !== 'supabase-demo';
}

const DETECTORS: readonly Detector[] = SECRET_PATTERNS.map((pattern) =>
  pattern.id === 'jwt' ? { id: 'supabase-service-role-jwt', name: 'Supabase service_role key', regex: pattern.regex, accept: isSupabaseServiceJwt } : pattern,
);

/** Pattern ids gitleaks' default rules do not cover; SECRET-004 always runs these itself. */
export const SUPABASE_PATTERN_IDS: ReadonlySet<string> = new Set(['supabase-secret-key', 'supabase-service-role-jwt']);

/** Secrets in `text`, in order of appearance. Public JWTs (anon keys) are ignored. */
export function findSecrets(text: string, ids?: ReadonlySet<string>): SecretMatch[] {
  const matches: SecretMatch[] = [];
  for (const { id, name, regex, accept } of DETECTORS) {
    if (ids && !ids.has(id)) continue;
    for (const match of text.matchAll(regex)) {
      if (!accept || accept(match[0])) matches.push({ id, name, value: match[0], index: match.index });
    }
  }
  return matches.sort((a, b) => a.index - b.index);
}

const PLACEHOLDER =
  /^<.*>$|^\[.*\]$|^\$\{.*\}$|^\{\{.*\}\}$|your[-_ ]|xxx|\*\*\*|\.\.\.|change[-_]?me|replace[-_]?(?:me|this)|placeholder|example|dummy|sample|todo|fixme|redacted|insert[-_]/i;

/** Values like `your-api-key`, `xxx`, `changeme` or `<secret>` that only show the expected shape. */
export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER.test(value.trim());
}

/** Long, random-looking values: at least `minLength` characters and more than `minEntropy` bits per character. */
export function looksRandom(value: string, minLength = 20, minEntropy = 3.5): boolean {
  return value.length >= minLength && shannonEntropy(value) > minEntropy;
}

/** Environment variable names that usually hold secrets. */
export const SECRET_ENV_NAME = /SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|PASSWD|API_KEY|TOKEN|CREDENTIAL/i;

const EXAMPLE_ENV_FILE = /^\.env\.(?:example|sample|template|dist|defaults)$|^\.dev\.vars\.(?:example|sample)$/i;

/** Example env files, which are meant to be committed with placeholder values. */
export function isExampleEnvFile(file: string): boolean {
  return EXAMPLE_ENV_FILE.test(file.slice(file.lastIndexOf('/') + 1));
}

/** URLs with an embedded password, e.g. postgres://user:pass@host/db. */
export function hasUrlCredentials(value: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:[^\s@/]+@/i.test(value);
}
