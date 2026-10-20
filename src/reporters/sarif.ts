import { REPOSITORY_URL } from '../core/version.js';
import type { Confidence, Finding, Rule, ScanResult, Severity } from '../types.js';

export const SARIF_SCHEMA_URI = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json';

/** GitHub code scanning maps > 9.0 to critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low; 0.0 means no security severity. */
export const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' };
const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const PROBLEM_SEVERITY: Record<Severity, 'error' | 'warning' | 'recommendation'> = { critical: 'error', high: 'error', medium: 'warning', low: 'recommendation', info: 'recommendation' };
const PRECISION: Record<Confidence, string> = { high: 'high', medium: 'medium', low: 'low' };

/** GitHub limits: 1024 characters per description, 25,000 results per run. */
const MAX_TEXT = 1024;
const MAX_RESULTS = 25_000;

export type SarifRule = Pick<Rule, 'id' | 'title' | 'description' | 'fix' | 'severity' | 'confidence' | 'category'> & Partial<Pick<Rule, 'cwe' | 'references'>>;

export interface SarifOptions {
  /** Where live findings point, relative to the repository root. */
  liveConfigUri?: string;
}

function clip(text: string): string {
  return text.length <= MAX_TEXT ? text : `${text.slice(0, MAX_TEXT - 3)}...`;
}

function pascalCase(title: string): string {
  return title
    .replace(/[^A-Za-z0-9]+/g, ' ')
    .trim()
    .split(' ')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join('');
}

function reportingDescriptor(rule: SarifRule) {
  const tags = ['security', rule.category, ...(rule.cwe ? [`external/cwe/${rule.cwe.toLowerCase()}`] : [])];
  const references = rule.references?.length ? `\n\n${rule.references.map((r) => `- <${r}>`).join('\n')}` : '';
  return {
    id: rule.id,
    name: pascalCase(rule.title),
    shortDescription: { text: clip(rule.title) },
    fullDescription: { text: clip(rule.description) },
    help: { text: clip(rule.fix), markdown: `**Fix:** ${rule.fix}${references}` },
    ...(rule.references?.[0] ? { helpUri: rule.references[0] } : {}),
    defaultConfiguration: { level: LEVEL[rule.severity] },
    properties: { 'security-severity': SECURITY_SEVERITY[rule.severity], tags, precision: PRECISION[rule.confidence], 'problem.severity': PROBLEM_SEVERITY[rule.severity] },
  };
}

/** Percent-encodes each path segment, so Next.js paths like app/[id]/route.ts are valid URI references. */
function encodePath(path: string): string {
  return path.split('/').map(encodeURIComponent).join('/');
}

/** Joins the scan target (relative to the repository root) and a file into a SARIF uri. */
function artifactUri(target: string, file: string): string {
  if (/^(?:[A-Za-z]:)?\//.test(target)) return `file://${target.startsWith('/') ? '' : '/'}${encodePath(target.replace(/\/$/, ''))}/${encodePath(file)}`;
  return encodePath(target === '.' || target === '' ? file : `${target.replace(/\/$/, '')}/${file}`);
}

function location(finding: Finding, target: string, options: SarifOptions) {
  // Live findings have a URL instead of a file; they point at the config that defines the live checks.
  if (finding.url && !finding.file) return { uri: options.liveConfigUri ?? 'shipcheck.config.json', region: { startLine: 1 } };
  // Project-level findings (no file) point at package.json, since GitHub needs a location for every result.
  if (!finding.file) return { uri: artifactUri(target, 'package.json'), region: { startLine: 1 } };
  return {
    uri: artifactUri(target, finding.file),
    region: { startLine: finding.line ?? 1, ...(finding.column ? { startColumn: finding.column } : {}), ...(finding.endLine && finding.endLine !== finding.line ? { endLine: finding.endLine } : {}) },
  };
}

/**
 * SARIF 2.1.0 for GitHub code scanning: one run, every rule as a reporting descriptor with a
 * security-severity, and one result per finding with a repository-relative location and a stable
 * partial fingerprint (the finding id). Suppressed findings are left out.
 */
export function renderSarif(result: ScanResult, rules: readonly SarifRule[], options: SarifOptions = {}): string {
  const descriptors = [...rules].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const index = new Map(descriptors.map((rule, i) => [rule.id, i]));
  const live = /^https?:\/\//.test(result.target.path);
  const target = live ? '.' : result.target.path;
  const results = result.findings.slice(0, MAX_RESULTS).map((finding) => {
    const { uri, region } = location(finding, target, options);
    const ruleIndex = index.get(finding.ruleId);
    return {
      ruleId: finding.ruleId,
      ...(ruleIndex === undefined ? {} : { ruleIndex }),
      level: LEVEL[finding.severity],
      message: { text: finding.url && !finding.file ? `${finding.explanation} (${finding.url})` : finding.explanation },
      locations: [{ physicalLocation: { artifactLocation: { uri, uriBaseId: '%SRCROOT%' }, region } }],
      partialFingerprints: { 'shipcheck/v1': finding.id },
      properties: {
        severity: finding.severity,
        confidence: finding.confidence,
        advisory: finding.advisory,
        source: finding.source,
        evidence: finding.evidence,
        fix: finding.fix,
      },
    };
  });
  const document = {
    $schema: SARIF_SCHEMA_URI,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'shipcheck',
            version: result.tool.version,
            semanticVersion: result.tool.version,
            informationUri: REPOSITORY_URL,
            rules: descriptors.map(reportingDescriptor),
          },
        },
        results,
        properties: {
          target: result.target.path,
          score: result.score.value,
          grade: result.score.grade,
          suppressedCount: result.suppressedCount,
          ...(result.findings.length > MAX_RESULTS ? { truncatedResults: result.findings.length - MAX_RESULTS } : {}),
        },
      },
    ],
  };
  return `${JSON.stringify(document, null, 2)}\n`;
}
