import type { RawFinding, Rule } from '../../../types.js';
import { findSecrets, isPlaceholder, SECRET_ENV_NAME } from '../analysis/secret-patterns.js';

const PUBLIC_PREFIX = 'NEXT_PUBLIC_';
/** NEXT_PUBLIC_*SERVICE_ROLE* variables are reported by AUTHZ-007. */
const SERVICE_ROLE_NAME = /SERVICE_ROLE/i;
/** Names of keys that are public by design. */
const PUBLIC_NAME = /(?:_URL|ANON_KEY|PUBLISHABLE(?:_KEY)?|PUBLIC_KEY|SITE_KEY|FIREBASE_API_KEY|MAPS_API_KEY|POSTHOG_KEY|DSN|MEASUREMENT_ID)$/i;
/** Values of keys that are public by design: Stripe and Mapbox publishable keys, Supabase publishable keys. */
const PUBLIC_VALUE = /^(?:pk_(?:test|live)_|pk\.|sb_publishable_)/;

export const secret001: Rule = {
  id: 'SECRET-001',
  title: 'Secret in a NEXT_PUBLIC_ variable',
  category: 'secrets',
  severity: 'critical',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Next.js inlines every NEXT_PUBLIC_ variable into the browser bundle at build time. The rule reports NEXT_PUBLIC_ ' +
    'entries in .env files whose value matches a known secret format (Stripe secret, Supabase secret or service_role ' +
    'key, OpenAI, Anthropic, GitHub, AWS), with high confidence, and entries whose name says secret, private, password, ' +
    'api key or token, with medium confidence. Supabase URLs, anon and publishable keys, Stripe pk_ keys and similar ' +
    'public-by-design keys are exempt; NEXT_PUBLIC_*SERVICE_ROLE* names are reported by AUTHZ-007. Limitations: variables ' +
    'set only in the hosting dashboard are not visible.',
  explanation:
    'Anything in a NEXT_PUBLIC_ variable ends up in JavaScript that every visitor downloads, so the secret is effectively ' +
    'published and anyone can use it against the service it unlocks.',
  fix:
    'Rename the variable without the NEXT_PUBLIC_ prefix, read it only in server code (route handlers, server actions, ' +
    "modules that import 'server-only'), and rotate the key, since every deployed build has already exposed it.",
  falsePositiveNote: 'Some services issue keys that are meant to be public (restricted by domain or row level security); exempt them in shipcheck.config.json.',
  cwe: 'CWE-200',
  references: ['https://nextjs.org/docs/app/guides/environment-variables#bundling-environment-variables-for-the-browser'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const env of ctx.envFiles) {
      for (const { key, value, line } of env.entries) {
        if (!key.startsWith(PUBLIC_PREFIX) || SERVICE_ROLE_NAME.test(key)) continue;
        const trimmed = value.trim();
        const evidence = `${key}=${trimmed ? '<redacted>' : ''}`;
        const secret = trimmed && !isPlaceholder(trimmed) ? findSecrets(trimmed)[0] : undefined;
        if (secret) {
          findings.push({
            file: env.file,
            line,
            evidence,
            confidence: 'high',
            explanation: `${key} holds a ${secret.name}. Next.js copies NEXT_PUBLIC_ values into the browser bundle, so every visitor can read it.`,
          });
        } else if (!PUBLIC_NAME.test(key) && !PUBLIC_VALUE.test(trimmed) && SECRET_ENV_NAME.test(key.slice(PUBLIC_PREFIX.length))) {
          findings.push({ file: env.file, line, evidence, confidence: 'medium' });
        }
      }
    }
    return findings;
  },
};
