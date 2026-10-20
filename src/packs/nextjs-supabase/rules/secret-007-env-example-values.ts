import type { RawFinding, Rule } from '../../../types.js';
import { findSecrets, hasUrlCredentials, isExampleEnvFile, isPlaceholder, jwtRole, looksRandom } from '../analysis/secret-patterns.js';

/** Public by design: Stripe/Mapbox publishable keys, Supabase publishable keys. Anon JWTs are checked separately. */
const PUBLIC_VALUE = /^(?:pk_(?:test|live)_|pk\.|sb_publishable_)/;
const LOCAL_HOST = /@(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|host\.docker\.internal|db|postgres|redis|mongo)(?::\d+)?(?:\/|$)/i;

export const secret007: Rule = {
  id: 'SECRET-007',
  title: 'Real values in .env.example',
  category: 'secrets',
  severity: 'high',
  confidence: 'high',
  stacks: [],
  description:
    'Example env files (.env.example, .env.sample, .env.template) are committed on purpose, so they must only hold ' +
    'placeholders. The rule reports values that match a known secret format or are URLs with an embedded password (high ' +
    'confidence), and other values of 20+ characters with more than 3.5 bits of entropy per character (medium). ' +
    'Placeholders (your-..., xxx, changeme, <...>), plain URLs, public keys and local development defaults are ignored.',
  explanation:
    'Example files are meant to be shared, so a real key in one is published with the repository. These values are ' +
    'often copied from a working .env.local by accident.',
  fix: 'Replace the value with a placeholder such as `your-stripe-secret-key`, and rotate the key it held.',
  falsePositiveNote: 'Long non-secret defaults (public URLs without a scheme, build ids) can look random; use an obvious placeholder instead.',
  cwe: 'CWE-540',
  references: ['https://12factor.net/config'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const env of ctx.envFiles) {
      if (!isExampleEnvFile(env.file)) continue;
      for (const { key, value, line } of env.entries) {
        const trimmed = value.trim();
        if (!trimmed || isPlaceholder(trimmed) || PUBLIC_VALUE.test(trimmed) || jwtRole(trimmed) === 'anon') continue;
        const evidence = `${key}=<redacted>`;
        const secret = findSecrets(trimmed)[0];
        if (secret) {
          findings.push({ file: env.file, line, evidence, confidence: 'high', explanation: `${key} holds what looks like a real ${secret.name}, in a file that is meant to be committed and shared.` });
        } else if (hasUrlCredentials(trimmed)) {
          if (!LOCAL_HOST.test(trimmed)) findings.push({ file: env.file, line, evidence, confidence: 'high', explanation: `${key} is a URL with a password for a non-local host.` });
        } else if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) && looksRandom(trimmed)) {
          findings.push({ file: env.file, line, evidence, confidence: 'medium' });
        }
      }
    }
    return findings;
  },
};
