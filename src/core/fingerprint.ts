import { createHash } from 'node:crypto';

export interface FingerprintInput {
  ruleId: string;
  file?: string | null;
  url?: string | null;
  evidence: string;
}

/**
 * Stable finding id: first 16 hex chars of sha256(ruleId|file-or-url|evidence) with whitespace
 * collapsed. The line number is deliberately excluded so ids survive unrelated edits above.
 */
export function fingerprint({ ruleId, file, url, evidence }: FingerprintInput): string {
  const location = file ?? url ?? '';
  const collapsed = evidence.replace(/\s+/g, ' ').trim();
  return createHash('sha256').update(`${ruleId}|${location}|${collapsed}`).digest('hex').slice(0, 16);
}
