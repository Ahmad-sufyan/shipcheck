import { compareStrings, lineAt } from '../context/files.js';
import { RawFindingSchema, severityRank } from '../schema.js';
import type { Finding, RawFinding, Rule, ScanResult, SuppressedFinding } from '../types.js';
import { fingerprint } from './fingerprint.js';
import { redactEvidence } from './redact.js';
import type { RuleRun } from './runner.js';

const IGNORE_COMMENT = /shipcheck-ignore:?\s+([A-Z][A-Z0-9]*-\d+(?:\s*,\s*[A-Z][A-Z0-9]*-\d+)*)/;
/** `shipcheck-ignore-next-line RULE-ID[, RULE-ID]: reason`, honoured only with a reason. */
const NEXT_LINE_IGNORE = /shipcheck-ignore-next-line\s+([A-Z][A-Z0-9]*-\d+(?:\s*,\s*[A-Z][A-Z0-9]*-\d+)*)(.*)$/;
/** A line that holds only a comment (JS, JSX, SQL or shell style). */
const COMMENT_ONLY = /^\s*(?:\/\/|\/\*|\*|#|--|\{\s*\/\*)/;

export interface NormalizeOptions {
  /** Used to honour `shipcheck-ignore: RULE-ID` comments; without it nothing is suppressed. */
  readText?: (file: string) => string;
}

export interface NormalizedFindings {
  findings: Finding[];
  /** Hidden by ignore comments, with their reasons. */
  suppressed: SuppressedFinding[];
  suppressedCount: number;
  /** Ignore comments that could not be honoured. */
  warnings: string[];
  ruleErrors: ScanResult['ruleErrors'];
}

function normalizePath(file: string): string {
  return file.replace(/\\/g, '/').replace(/^(?:\.\/)+/, '');
}

export function toFinding(rule: Rule, raw: RawFinding): Finding {
  const file = raw.file === undefined ? null : normalizePath(raw.file);
  const url = raw.url ?? null;
  const evidence = redactEvidence(raw.evidence);
  return {
    id: fingerprint({ ruleId: rule.id, file, url, evidence }),
    ruleId: rule.id,
    title: rule.title,
    category: rule.category,
    severity: raw.severity ?? rule.severity,
    confidence: raw.confidence ?? rule.confidence,
    advisory: raw.advisory ?? rule.advisory ?? false,
    source: raw.source ?? rule.source ?? 'static',
    file,
    line: raw.line ?? null,
    column: raw.column ?? null,
    endLine: raw.endLine ?? null,
    url,
    evidence,
    explanation: raw.explanation ?? rule.explanation,
    fix: raw.fix ?? rule.fix,
    ...(rule.cwe ? { cwe: rule.cwe } : {}),
    references: [...(rule.references ?? [])],
  };
}

/** Severity (critical first), then file, line and rule id; the rest only break ties deterministically. */
export function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank(a.severity) - severityRank(b.severity) ||
    compareStrings(a.file ?? '', b.file ?? '') ||
    (a.line ?? 0) - (b.line ?? 0) ||
    compareStrings(a.ruleId, b.ruleId) ||
    (a.column ?? 0) - (b.column ?? 0) ||
    compareStrings(a.url ?? '', b.url ?? '') ||
    compareStrings(a.evidence, b.evidence) ||
    compareStrings(a.id, b.id)
  );
}

/** A suppressing comment: a reason to hide the finding, or a warning about a comment that cannot be honoured. */
type Suppression = { reason: string } | { warning: string };

function suppression(finding: Finding, readText: NormalizeOptions['readText']): Suppression | undefined {
  if (!readText || finding.file === null || finding.line === null) return undefined;
  let text: string;
  try {
    text = readText(finding.file);
  } catch {
    return undefined;
  }
  const above = lineAt(text, finding.line - 1);
  const nextLine = NEXT_LINE_IGNORE.exec(above);
  if (nextLine?.[1]?.split(/\s*,\s*/).includes(finding.ruleId)) {
    const reason = /^\s*:\s*(.*?)\s*(?:\*\/\s*\}?)?\s*$/.exec(nextLine[2] ?? '')?.[1] ?? '';
    if (reason) return { reason };
    return { warning: `${finding.file}:${finding.line - 1}: shipcheck-ignore-next-line without a reason is ignored; write \`shipcheck-ignore-next-line RULE-ID: reason\`` };
  }
  const ignores = (line: string) => IGNORE_COMMENT.exec(line)?.[1]?.split(/\s*,\s*/).includes(finding.ruleId) ?? false;
  if (ignores(lineAt(text, finding.line)) || (COMMENT_ONLY.test(above) && ignores(above))) return { reason: 'shipcheck-ignore comment' };
  return undefined;
}

/** Validates, redacts, fingerprints, applies ignore comments, sorts and dedupes rule output. */
export function normalizeFindings(runs: readonly RuleRun[], options: NormalizeOptions = {}): NormalizedFindings {
  const ruleErrors: NormalizedFindings['ruleErrors'] = [];
  const all: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  const warnings = new Set<string>();

  for (const { rule, findings } of runs) {
    for (const raw of findings) {
      const parsed = RawFindingSchema.safeParse(raw);
      if (!parsed.success) {
        const issues = parsed.error.issues.map((issue) => `${issue.path.map(String).join('.') || '(root)'}: ${issue.message}`).join('; ');
        ruleErrors.push({ ruleId: rule.id, message: `invalid finding dropped: ${issues}` });
        continue;
      }
      const finding = toFinding(rule, parsed.data);
      const hidden = suppression(finding, options.readText);
      if (hidden && 'reason' in hidden) {
        suppressed.push({ id: finding.id, ruleId: finding.ruleId, reason: hidden.reason });
        continue;
      }
      if (hidden) warnings.add(hidden.warning);
      all.push(finding);
    }
  }

  all.sort(compareFindings);
  const seen = new Set<string>();
  const findings = all.filter((finding) => !seen.has(finding.id) && seen.add(finding.id));
  return { findings, suppressed, suppressedCount: suppressed.length, ruleErrors, warnings: [...warnings] };
}
