import { findVulnerabilities, type Vulnerability } from '../../../adapters/index.js';
import type { FindingSource, RawFinding, Rule, Severity } from '../../../types.js';
import { compareVersions, lockedPackages } from '../analysis/lockfile.js';

const LOWER: Record<Severity, Severity> = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };
const FROM_LABEL: Record<NonNullable<Vulnerability['severity']>, Severity> = { critical: 'critical', high: 'high', moderate: 'medium', low: 'low' };

/** CVSS >= 9 critical, >= 7 high, >= 4 medium, else low; the advisory's own label when there is no score. */
function baseSeverity(vulnerability: Vulnerability): Severity {
  const { cvss } = vulnerability;
  if (cvss !== undefined) return cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : 'low';
  return vulnerability.severity ? FROM_LABEL[vulnerability.severity] : 'medium';
}

/** The lowest fixed version above the installed one (advisories list one fix per release line). */
function fixedVersion(vulnerability: Vulnerability, installed: string): string | undefined {
  const candidates = vulnerability.fixedVersions.filter((v) => !installed || compareVersions(v, installed) > 0).sort(compareVersions);
  return candidates[0];
}

export const dep001: Rule = {
  id: 'DEP-001',
  title: 'Known vulnerable dependency',
  category: 'dependencies',
  severity: 'high',
  confidence: 'high',
  source: 'tool:osv',
  stacks: [],
  timeoutMs: 250_000,
  description:
    'Checks the lockfile against vulnerability databases with osv-scanner (`osv-scanner scan source --lockfile ... ' +
    '--format json`), falling back to `npm audit --json --package-lock-only` or `pnpm audit --json` when osv-scanner is ' +
    'not installed. Severity follows the CVSS score (9+ critical, 7+ high, 4+ medium, else low) or the advisory label, ' +
    'one level lower for packages only used in development. This is the only check that needs the network; --offline ' +
    'skips it and records the skip.',
  explanation: 'A dependency in the lockfile has a published vulnerability, and attackers scan for known vulnerable versions.',
  fix: 'Upgrade the package to a fixed version (or the parent package that pulls it in), then re-run the scan.',
  falsePositiveNote: 'The vulnerable code path may be unused in your app; check the advisory before dismissing it.',
  cwe: 'CWE-1395',
  references: ['https://google.github.io/osv-scanner/', 'https://docs.npmjs.com/cli/commands/npm-audit'],
  async run(ctx) {
    if (!ctx.lockfile || !ctx.tools) return [];
    if (ctx.tools.offline) {
      ctx.skip?.('DEP-001', 'offline mode (--offline): vulnerability database lookups were not run');
      return [];
    }
    const scan = await findVulnerabilities(ctx.root, ctx.lockfile, ctx.tools);
    if (!scan.ok) {
      ctx.skip?.('DEP-001', scan.reason);
      return [];
    }
    const locked = lockedPackages(ctx);
    const source: FindingSource = scan.value.tool === 'osv-scanner' ? 'tool:osv' : 'tool:npm-audit';
    const findings: RawFinding[] = [];
    const seen = new Set<string>();
    for (const vulnerability of scan.value.vulnerabilities) {
      const { package: name, ids, title, url, cvss } = vulnerability;
      const versions = vulnerability.version ? [vulnerability.version] : [...new Set(locked.filter((p) => p.name === name).map((p) => p.version))];
      for (const version of versions.length ? versions : ['']) {
        const key = `${name}@${version}\0${ids[0]}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const entries = locked.filter((p) => p.name === name && (!version || p.version === version));
        const dev = vulnerability.dev ?? (entries.length > 0 && entries.every((p) => p.dev));
        const base = baseSeverity(vulnerability);
        const fixed = fixedVersion(vulnerability, version);
        const label = `${name}${version ? `@${version}` : ''}`;
        const rating = cvss !== undefined ? `CVSS ${cvss}` : `rated ${vulnerability.severity ?? 'unknown'}`;
        const finding: RawFinding = {
          file: ctx.lockfile.file,
          evidence: `${label}: ${ids[0]}${ids.length > 1 ? ` (${ids.slice(1).join(', ')})` : ''} ${title}`,
          severity: dev ? LOWER[base] : base,
          explanation:
            `${title} (${rating}, reported by ${scan.value.tool}).` +
            (dev ? ` ${name} is only a development dependency, so the severity is lowered one level.` : ''),
          fix: fixed ? `Upgrade ${name} to ${fixed} or later (${url}).` : `No fixed version is listed; see ${url} for workarounds, or replace ${name}.`,
          source,
        };
        const line = entries[0]?.line;
        findings.push(line ? { ...finding, line } : finding);
      }
    }
    return findings;
  },
};
