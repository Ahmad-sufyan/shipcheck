export const MAX_EVIDENCE_LENGTH = 200;

const KEEP = 4;
const MASK = '****';

export interface SecretPattern {
  readonly id: string;
  readonly name: string;
  /** Global regex; shapes follow gitleaks' default rules where one exists. */
  readonly regex: RegExp;
}

/** Specific secret shapes, checked before the generic entropy pass. Shared with the secret rules. */
export const SECRET_PATTERNS: readonly SecretPattern[] = [
  { id: 'stripe-secret-key', name: 'Stripe secret or restricted key', regex: /\b(?:sk|rk)_(?:live|test|prod)_[A-Za-z0-9]{8,99}/g },
  // The newer replacement for service_role JWTs
  { id: 'supabase-secret-key', name: 'Supabase secret key', regex: /\bsb_secret_[A-Za-z0-9_-]{16,}/g },
  {
    id: 'openai-api-key',
    name: 'OpenAI API key',
    regex: /\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{58,74}|[A-Za-z0-9]{20})T3BlbkFJ(?:[A-Za-z0-9_-]{58,74}|[A-Za-z0-9]{20})(?![A-Za-z0-9_-])/g,
  },
  { id: 'anthropic-api-key', name: 'Anthropic API key', regex: /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA(?![A-Za-z0-9_-])/g },
  { id: 'github-token', name: 'GitHub token', regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_\w{82})\b/g },
  { id: 'aws-access-key-id', name: 'AWS access key id', regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g },
  // Any JWT, including public Supabase anon keys; the secret rules only report service_role ones.
  { id: 'jwt', name: 'JSON Web Token', regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g },
];

const GENERIC_TOKEN = /[A-Za-z0-9+_=-]{32,}/g;
const MIN_GENERIC_ENTROPY = 3.5;

function mask(value: string): string {
  return value.slice(0, KEEP) + MASK;
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** A long run counts as a secret only if it mixes letters and digits and looks random. */
function looksLikeToken(value: string): boolean {
  return /[0-9]/.test(value) && /[A-Za-z]/.test(value) && shannonEntropy(value) >= MIN_GENERIC_ENTROPY;
}

/** Masks secret-looking values, keeping the first 4 characters followed by ****. */
export function redactSecrets(text: string): string {
  let out = text;
  for (const { regex } of SECRET_PATTERNS) out = out.replace(regex, mask);
  return out.replace(GENERIC_TOKEN, (match) => (looksLikeToken(match) ? mask(match) : match));
}

export function truncateEvidence(text: string, max = MAX_EVIDENCE_LENGTH): string {
  return text.length <= max ? text : text.slice(0, max - 3) + '...';
}

/** Redact first, then truncate, so a secret cut in half is never partially exposed. */
export function redactEvidence(text: string): string {
  return truncateEvidence(redactSecrets(text));
}
