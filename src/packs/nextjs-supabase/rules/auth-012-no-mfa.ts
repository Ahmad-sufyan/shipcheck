import type { Rule } from '../../../types.js';
import { sourceFiles } from '../analysis/ast-utils.js';

/** Supabase MFA calls, TOTP libraries and WebAuthn APIs. */
const MFA_USAGE = [
  /\.mfa\.(?:enroll|challenge|verify|challengeAndVerify|getAuthenticatorAssuranceLevel)\s*\(/,
  /\.mfa\.webauthn\b/,
  /from\s+['"](?:otplib|@otplib\/[\w-]+|speakeasy|otpauth|@simplewebauthn\/[\w-]+|@github\/webauthn-json)['"]/,
  /require\(\s*['"](?:otplib|speakeasy|otpauth)['"]\s*\)/,
  /navigator\.credentials\.(?:create|get)\s*\(/,
];

export const auth012: Rule = {
  id: 'AUTH-012',
  title: 'No multi-factor authentication',
  category: 'authentication',
  severity: 'info',
  confidence: 'medium',
  advisory: true,
  stacks: ['nextjs-app-router', 'supabase'],
  description:
    'Project-level check: reports once when no source file uses Supabase MFA (mfa.enroll/challenge/verify), a TOTP library ' +
    '(otplib, speakeasy, otpauth) or WebAuthn (navigator.credentials, @simplewebauthn). Advisory, because MFA may be ' +
    'enforced by an external identity provider.',
  explanation:
    'Accounts are protected by a password alone. Admin and other high-value accounts in particular are taken over easily ' +
    'once a password leaks or is reused.',
  fix: 'Offer TOTP with Supabase MFA (supabase.auth.mfa.enroll / challenge / verify) and require it at least for admin accounts (check the AAL with getAuthenticatorAssuranceLevel).',
  falsePositiveNote: 'MFA enforced by an external identity provider (SSO, Auth0, Clerk) is not visible to this rule.',
  cwe: 'CWE-308',
  references: ['https://supabase.com/docs/guides/auth/auth-mfa'],
  run(ctx) {
    const usesMfa = sourceFiles(ctx).some((file) => {
      const text = ctx.readText(file);
      return MFA_USAGE.some((pattern) => pattern.test(text));
    });
    return usesMfa ? [] : [{ evidence: 'No MFA, TOTP or WebAuthn usage found in the project' }];
  },
};
