export const MAX_EVIDENCE_LENGTH = 200;

const KEEP = 4;
const MASK = '****';

/** Specific secret shapes, checked before the generic entropy pass. */
const SECRET_PATTERNS: readonly RegExp[] = [
  // Stripe secret and restricted keys
  /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}/g,
  // Supabase secret API keys (the newer replacement for service_role JWTs)
  /\bsb_secret_[A-Za-z0-9_-]{16,}/g,
  // JWTs, including Supabase anon and service_role keys
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g,
  // AWS access key ids
  /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
];

const GENERIC_TOKEN = /[A-Za-z0-9+_=-]{32,}/g;
const MIN_GENERIC_ENTROPY = 3.5;

function mask(value: string): string {
  return value.slice(0, KEEP) + MASK;
}

function shannonEntropy(value: string): number {
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
  for (const pattern of SECRET_PATTERNS) out = out.replace(pattern, mask);
  return out.replace(GENERIC_TOKEN, (match) => (looksLikeToken(match) ? mask(match) : match));
}

export function truncateEvidence(text: string, max = MAX_EVIDENCE_LENGTH): string {
  return text.length <= max ? text : text.slice(0, max - 3) + '...';
}

/** Redact first, then truncate, so a secret cut in half is never partially exposed. */
export function redactEvidence(text: string): string {
  return truncateEvidence(redactSecrets(text));
}
