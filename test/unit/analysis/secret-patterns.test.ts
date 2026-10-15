import { describe, expect, it } from 'vitest';
import {
  entropy,
  findSecrets,
  isPlaceholder,
  isSupabaseServiceJwt,
  jwtRole,
  looksRandom,
  maskSpan,
  redactSecrets,
  SUPABASE_PATTERN_IDS,
} from '../../../src/packs/nextjs-supabase/analysis/secret-patterns.js';
import { FAKE } from '../../helpers/fake-secrets.js';

describe('findSecrets', () => {
  it.each([
    ['stripe-secret-key', FAKE.stripe],
    ['supabase-secret-key', FAKE.supabaseSecret],
    ['supabase-service-role-jwt', FAKE.supabaseServiceJwt],
    ['openai-api-key', FAKE.openai],
    ['anthropic-api-key', FAKE.anthropic],
    ['github-token', FAKE.github],
    ['aws-access-key-id', FAKE.aws],
  ])('detects %s and the redactor masks it to 4 characters', (id, value) => {
    const text = `const key = '${value}'`;
    expect(findSecrets(text)).toEqual([expect.objectContaining({ id, value, index: 13 })]);
    expect(redactSecrets(text)).toBe(`const key = '${value.slice(0, 4)}****'`);
  });

  it('ignores public keys', () => {
    for (const value of [FAKE.supabaseAnonJwt, FAKE.supabasePublishable, FAKE.stripePublishable]) expect(findSecrets(`key = "${value}"`)).toEqual([]);
  });

  it('ignores the Supabase CLI demo service_role key', () => {
    const demo = [Buffer.from('{"alg":"HS256"}').toString('base64url'), Buffer.from('{"iss":"supabase-demo","role":"service_role"}').toString('base64url'), 'FAKEFAKEFAKE'].join('.');
    expect(isSupabaseServiceJwt(demo)).toBe(false);
    expect(findSecrets(demo)).toEqual([]);
  });

  it('restricts to the given pattern ids, in order of appearance', () => {
    const text = `${FAKE.stripe} ${FAKE.supabaseSecret} ${FAKE.supabaseServiceJwt}`;
    expect(findSecrets(text).map((m) => m.id)).toEqual(['stripe-secret-key', 'supabase-secret-key', 'supabase-service-role-jwt']);
    expect(findSecrets(text, SUPABASE_PATTERN_IDS).map((m) => m.id)).toEqual(['supabase-secret-key', 'supabase-service-role-jwt']);
  });
});

describe('maskSpan', () => {
  const line = `key = '${FAKE.stripe}';`;
  const start = line.indexOf('sk_');

  it('keeps 4 characters and the closing delimiter', () => {
    expect(maskSpan(line, start, start + FAKE.stripe.length + 1)).toBe("key = 'sk_t****';");
  });

  it('swallows the tail of a token when the end column is off by one', () => {
    expect(maskSpan(line, start, start + FAKE.stripe.length - 1)).toBe("key = 'sk_t****';");
  });

  it('masks a whole generic match that starts with the key name', () => {
    expect(maskSpan('api_key = "Zx8q2LmT9vR4pW7nB1cY"', 0, 30)).toBe('api_****"');
  });
});

describe('jwtRole', () => {
  it('reads the role claim without verifying the token', () => {
    expect(jwtRole(FAKE.supabaseAnonJwt)).toBe('anon');
    expect(jwtRole(FAKE.supabaseServiceJwt)).toBe('service_role');
    expect(jwtRole('not.a.jwt')).toBeUndefined();
  });
});

describe('isPlaceholder', () => {
  it.each(['your-api-key', 'sk_test_xxxxxxxxxxxxxxxx', 'changeme', '<service-role-key>', '${SECRET}', 'replace-me', '***', 'sk_live_...'])('treats %s as a placeholder', (value) => {
    expect(isPlaceholder(value)).toBe(true);
  });

  it('does not treat real-looking values as placeholders', () => {
    expect(isPlaceholder(FAKE.stripe)).toBe(false);
    expect(isPlaceholder('q8Zr2Lm9Tv4Rp7Wn1BcY6kH3')).toBe(false);
  });
});

describe('entropy and looksRandom', () => {
  it('measures bits per character', () => {
    expect(entropy('aaaa')).toBe(0);
    expect(entropy('abcd')).toBe(2);
  });

  it('needs length and entropy', () => {
    expect(looksRandom('q8Zr2Lm9Tv4Rp7Wn1BcY6kH3')).toBe(true);
    expect(looksRandom('q8Zr2Lm9Tv')).toBe(false);
    expect(looksRandom('aaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe(false);
  });
});
