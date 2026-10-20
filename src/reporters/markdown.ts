import { CATEGORIES, SEVERITIES } from '../schema.js';
import type { Finding, ScanResult, Severity } from '../types.js';

const SEVERITY_HEADINGS: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

const FENCE_LANGUAGES: Record<string, string> = {
  ts: 'ts',
  tsx: 'tsx',
  mts: 'ts',
  cts: 'ts',
  js: 'js',
  jsx: 'jsx',
  mjs: 'js',
  cjs: 'js',
  sql: 'sql',
  json: 'json',
  jsonc: 'jsonc',
  toml: 'toml',
  yaml: 'yaml',
  yml: 'yaml',
};

function fenceLanguage(file: string | null): string {
  if (!file) return 'text';
  const ext = file.slice(file.lastIndexOf('.') + 1).toLowerCase();
  return FENCE_LANGUAGES[ext] ?? 'text';
}

function codeBlock(text: string, language: string): string {
  const longestRun = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  const fence = '`'.repeat(Math.max(3, longestRun + 1));
  return `${fence}${language}\n${text}\n${fence}`;
}

function inlineCode(text: string): string {
  return text.includes('`') ? `\`\` ${text} \`\`` : `\`${text}\``;
}

function location(finding: Finding): string | null {
  if (finding.file) return inlineCode(finding.line ? `${finding.file}:${finding.line}` : finding.file);
  return finding.url ? inlineCode(finding.url) : null;
}

function renderFinding(finding: Finding): string {
  const meta = [location(finding), `id: ${inlineCode(finding.id)}`, `confidence: ${finding.confidence}`, finding.cwe, finding.advisory ? 'advisory' : null, finding.source !== 'static' ? `source: ${finding.source}` : null]
    .filter(Boolean)
    .join(' · ');
  const parts = [`#### ${finding.ruleId}: ${finding.title}`, meta, codeBlock(finding.evidence, fenceLanguage(finding.file)), finding.explanation, `**Fix:** ${finding.fix}`];
  if (finding.references.length) parts.push(`References: ${finding.references.map((r) => `<${r}>`).join(', ')}`);
  return parts.join('\n\n');
}

export function renderMarkdown(result: ScanResult): string {
  const out: string[] = ['# shipcheck report'];
  out.push(
    [
      `**Score: ${result.score.value}/100 (${result.score.grade})**`,
      `Target: ${inlineCode(result.target.path)}`,
      `Stack: ${result.stack.length ? result.stack.join(', ') : 'none detected'}`,
      `shipcheck ${result.tool.version}`,
    ].join(' · '),
  );

  out.push(['| Category | Score |', '| --- | ---: |', ...CATEGORIES.map((c) => `| ${c} | ${result.score.byCategory[c]} |`)].join('\n'));

  out.push(`## Findings (${result.findings.length})`);
  if (!result.findings.length) out.push('No findings.');
  if (result.suppressedCount) out.push(`${result.suppressedCount} finding(s) suppressed by the baseline or ignore comments.`);
  for (const severity of SEVERITIES) {
    const group = result.findings.filter((f) => f.severity === severity);
    if (!group.length) continue;
    out.push(`### ${SEVERITY_HEADINGS[severity]}`);
    for (const finding of group) out.push(renderFinding(finding));
  }

  if (result.warnings.length) {
    out.push('## Warnings');
    out.push(result.warnings.map((w) => `- ${w}`).join('\n'));
  }

  out.push('## Skipped checks');
  out.push(result.skipped.length ? result.skipped.map((s) => `- ${inlineCode(s.check)}: ${s.reason}`).join('\n') : 'None.');
  out.push('## Rule errors');
  out.push(result.ruleErrors.length ? result.ruleErrors.map((e) => `- ${inlineCode(e.ruleId)}: ${e.message}`).join('\n') : 'None.');

  return `${out.join('\n\n')}\n`;
}
