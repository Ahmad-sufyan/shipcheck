import { SEVERITIES } from '../schema.js';
import type { Finding, Grade, ScanResult, Severity } from '../types.js';

export interface TextOptions {
  color: boolean;
}

const RESET = '\x1b[0m';
const SEVERITY_STYLES: Record<Severity, string> = {
  critical: '\x1b[1;31m',
  high: '\x1b[31m',
  medium: '\x1b[33m',
  low: '\x1b[36m',
  info: '\x1b[90m',
};
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';

function gradeStyle(grade: Grade): string {
  if (grade === 'A' || grade === 'B') return '\x1b[1;32m';
  if (grade === 'C') return '\x1b[1;33m';
  return '\x1b[1;31m';
}

/** NO_COLOR (any non-empty value) wins, then FORCE_COLOR, then whether the stream is a TTY. */
export function shouldUseColor(env: Record<string, string | undefined>, isTTY: boolean | undefined): boolean {
  if (env.NO_COLOR) return false;
  if (env.FORCE_COLOR !== undefined && env.FORCE_COLOR !== '') return env.FORCE_COLOR !== '0' && env.FORCE_COLOR !== 'false';
  return Boolean(isTTY);
}

const LABEL_WIDTH = Math.max(...SEVERITIES.map((s) => s.length));
const INDENT = ' '.repeat(LABEL_WIDTH + 2);

function renderFinding(finding: Finding, paint: (style: string, text: string) => string): string[] {
  const label = paint(SEVERITY_STYLES[finding.severity], finding.severity.toUpperCase().padEnd(LABEL_WIDTH));
  const tags = [finding.confidence !== 'high' ? `(confidence: ${finding.confidence})` : '', finding.advisory ? '[advisory]' : ''].filter(Boolean).join(' ');
  const lines = [`${label}  ${paint(BOLD, finding.ruleId)}  ${finding.title}${tags ? ` ${paint(DIM, tags)}` : ''}`];
  const where = finding.file ? (finding.line ? `${finding.file}:${finding.line}` : finding.file) : finding.url;
  if (where) lines.push(`${INDENT}${where}`);
  lines.push(`${INDENT}${paint(DIM, `> ${finding.evidence}`)}`);
  lines.push(`${INDENT}Fix: ${finding.fix}`);
  return lines;
}

export function renderText(result: ScanResult, options: TextOptions): string {
  const paint = (style: string, text: string) => (options.color ? `${style}${text}${RESET}` : text);
  const lines: string[] = [];

  lines.push(`${paint(BOLD, `shipcheck ${result.tool.version}`)}  ${result.target.path}`);
  lines.push(`Stack: ${result.stack.length ? result.stack.join(', ') : 'none detected'}`);
  lines.push(`Score: ${paint(gradeStyle(result.score.grade), `${result.score.value}/100 (${result.score.grade})`)}`);
  lines.push('');

  if (!result.findings.length) lines.push('No findings.', '');
  for (const finding of result.findings) lines.push(...renderFinding(finding, paint), '');

  const counts = SEVERITIES.map((s) => `${result.findings.filter((f) => f.severity === s).length} ${s}`).join(', ');
  const total = result.findings.length;
  lines.push(`${total} finding${total === 1 ? '' : 's'}: ${counts}; ${result.suppressedCount} suppressed`);
  if (result.skipped.length) lines.push(`Skipped: ${result.skipped.map((s) => `${s.check} (${s.reason})`).join('; ')}`);
  if (result.ruleErrors.length) lines.push(paint(SEVERITY_STYLES.high, `Rule errors: ${result.ruleErrors.map((e) => `${e.ruleId}: ${e.message}`).join('; ')}`));

  return `${lines.join('\n')}\n`;
}
