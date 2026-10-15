import { describe, expect, it } from 'vitest';
import { MAX_EVIDENCE_LENGTH, redactEvidence, redactSecrets, truncateEvidence } from '../../../src/core/redact.js';

// Secret-shaped test values are assembled at runtime so this file never contains a literal key.
const stripeLive = ['sk', 'live', '51FakeKeyForTests0000000000'].join('_');
const stripeTest = ['sk', 'test', '51FakeKeyForTests0000000000'].join('_');
const stripeRestricted = ['rk', 'live', '51FakeKeyForTests0000000000'].join('_');
const jwt = ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UifQ', 'c2lnbmF0dXJlLW5vdC1yZWFs'].join('.');
const aws = 'AKIA' + 'IOSFODNN7FAKEKEY';
const supabaseSecret = 'sb_secret_' + 'N7UND0UgjKTVK-Uodkm0Hg_xSvEMPvz';
const generic = 'Zx8' + 'q2LmT9vR4pW7nB1cY6kH3sJ0dF5gA8eU';

describe('redactSecrets', () => {
  it.each([
    ['stripe live', stripeLive, 'sk_l****'],
    ['stripe test', stripeTest, 'sk_t****'],
    ['stripe restricted', stripeRestricted, 'rk_l****'],
    ['jwt / supabase service_role', jwt, 'eyJh****'],
    ['aws access key', aws, 'AKIA****'],
    ['supabase secret key', supabaseSecret, 'sb_s****'],
    ['generic high-entropy token', generic, 'Zx8q****'],
  ])('masks %s', (_name, secret, masked) => {
    const out = redactSecrets(`const key = "${secret}";`);
    expect(out).toBe(`const key = "${masked}";`);
    expect(out).not.toContain(secret.slice(5));
  });

  it('masks several secrets in one string', () => {
    expect(redactSecrets(`${aws} and ${stripeLive}`)).toBe('AKIA**** and sk_l****');
  });

  it('leaves ordinary code alone', () => {
    const samples = [
      'const nextConfig = { productionBrowserSourceMaps: true }',
      "import { createServerClient } from '@supabase/ssr'",
      'src/packs/nextjs-supabase/rules/http-006-powered-by.ts',
      'NEXT_PUBLIC_SUPABASE_ANON_KEY_FOR_LOCAL_DEVELOPMENT_ONLY',
      'a'.repeat(64),
      'function handleIncomingWebhookRequestWithSignatureVerification()',
    ];
    for (const s of samples) expect(redactSecrets(s)).toBe(s);
  });
});

describe('truncateEvidence', () => {
  it('keeps short evidence unchanged', () => {
    expect(truncateEvidence('abc')).toBe('abc');
  });

  it('truncates to 200 characters', () => {
    const out = truncateEvidence('x'.repeat(500));
    expect(MAX_EVIDENCE_LENGTH).toBe(200);
    expect(out).toHaveLength(200);
    expect(out.endsWith('...')).toBe(true);
  });
});

describe('redactEvidence', () => {
  it('redacts before truncating, so a secret straddling the cut is still masked', () => {
    const text = 'x'.repeat(190) + ' ' + aws;
    const out = redactEvidence(text);
    expect(out.length).toBeLessThanOrEqual(200);
    expect(out).not.toContain('IOSFODNN');
  });
});
