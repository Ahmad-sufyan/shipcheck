/**
 * Obviously fake values that still match the secret patterns. They are assembled at runtime so test
 * sources never contain a literal key; fixtures and recorded tool outputs hold literals instead and are
 * allowlisted in .gitleaks.toml.
 */
const fake = (length: number) => 'FAKE'.repeat(Math.ceil(length / 4)).slice(0, length);

const base64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const jwt = (claims: Record<string, unknown>) => [base64url({ alg: 'HS256', typ: 'JWT' }), base64url(claims), fake(43)].join('.');

export const FAKE = {
  stripe: ['sk', 'test', fake(24) + '00'].join('_'),
  stripePublishable: ['pk', 'test', fake(24) + '00'].join('_'),
  supabaseSecret: ['sb', 'secret', fake(24) + '00'].join('_'),
  supabasePublishable: ['sb', 'publishable', fake(24) + '00'].join('_'),
  supabaseServiceJwt: jwt({ iss: 'supabase', ref: 'fakefakefakefakefake', role: 'service_role', iat: 0, exp: 0 }),
  supabaseAnonJwt: jwt({ iss: 'supabase', ref: 'fakefakefakefakefake', role: 'anon', iat: 0, exp: 0 }),
  openai: ['sk', 'proj', fake(58) + 'T3Blbk' + 'FJ' + fake(58)].join('-'),
  anthropic: ['sk', 'ant', 'api03', fake(93) + 'AA'].join('-'),
  github: 'gh' + 'p_' + fake(36),
  aws: 'AK' + 'IA' + fake(16),
} as const;
