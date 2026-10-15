import { runJsonTool, type ToolContext } from './exec.js';
import type { AdvisorySeverity, ToolRun, Vulnerability } from './types.js';

export const OSV_INSTALL_HINT = 'install osv-scanner v2: https://google.github.io/osv-scanner/installation/';

/** osv-scanner v2 exit codes: 0 no vulnerabilities, 1 vulnerabilities found, 128 no packages found. */
const NO_PACKAGES = 128;

export function osvArgs(lockfile: string): string[] {
  return ['scan', 'source', '--lockfile', lockfile, '--format', 'json'];
}

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json => !!value && typeof value === 'object' && !Array.isArray(value);
const objects = (value: unknown): Json[] => (Array.isArray(value) ? value.filter(isObject) : []);
const strings = (value: unknown): string[] => (Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : []);
const text = (value: unknown) => (typeof value === 'string' ? value : '');

const SEVERITY_ORDER: readonly AdvisorySeverity[] = ['critical', 'high', 'moderate', 'low'];

export function advisorySeverity(label: unknown): AdvisorySeverity | undefined {
  const value = text(label).toLowerCase();
  if (value === 'medium') return 'moderate';
  return SEVERITY_ORDER.find((s) => s === value);
}

/** GHSA ids first (they carry the most context for npm), then the rest in report order. */
export function orderIds(ids: Iterable<string>): string[] {
  const unique = [...new Set(ids)];
  return [...unique.filter((id) => id.startsWith('GHSA-')), ...unique.filter((id) => !id.startsWith('GHSA-'))];
}

export function advisoryUrl(id: string): string {
  return id.startsWith('GHSA-') ? `https://github.com/advisories/${id}` : `https://osv.dev/vulnerability/${id}`;
}

function fixedVersions(vulns: Json[], name: string): string[] {
  const fixed = new Set<string>();
  for (const vuln of vulns) {
    for (const affected of objects(vuln.affected)) {
      if (isObject(affected.package) && text(affected.package.name) !== name) continue;
      for (const range of objects(affected.ranges)) {
        for (const event of objects(range.events)) if (text(event.fixed)) fixed.add(text(event.fixed));
      }
    }
  }
  return [...fixed];
}

/** Normalizes `osv-scanner --format json` output: one entry per package version and advisory group. */
export function parseOsvReport(report: unknown): Vulnerability[] | undefined {
  if (!isObject(report)) return undefined;
  const found: Vulnerability[] = [];
  for (const result of objects(report.results)) {
    for (const entry of objects(result.packages)) {
      const pkg = isObject(entry.package) ? entry.package : {};
      if (text(pkg.ecosystem) && text(pkg.ecosystem) !== 'npm') continue;
      const name = text(pkg.name);
      if (!name) continue;
      const vulns = objects(entry.vulnerabilities);
      const groups = objects(entry.groups);
      // Older reports have no groups: treat each vulnerability as its own group.
      const grouped = groups.length ? groups : vulns.map((v) => ({ ids: [text(v.id)], aliases: strings(v.aliases), max_severity: '' }));
      for (const group of grouped) {
        const groupIds = strings(group.ids);
        const members = vulns.filter((v) => groupIds.includes(text(v.id)));
        const ids = orderIds([...groupIds, ...strings(group.aliases), ...members.flatMap((v) => strings(v.aliases))]);
        if (!ids.length) continue;
        const cvss = Number.parseFloat(text(group.max_severity));
        const severities = members.map((v) => advisorySeverity(isObject(v.database_specific) ? v.database_specific.severity : undefined)).filter((s) => s !== undefined);
        const primary = members.find((v) => text(v.id) === ids[0]) ?? members[0];
        const vulnerability: Vulnerability = {
          package: name,
          version: text(pkg.version),
          ids,
          title: text(primary?.summary) || ids[0]!,
          url: advisoryUrl(ids[0]!),
          fixedVersions: fixedVersions(members, name),
          tool: 'osv-scanner',
        };
        if (Number.isFinite(cvss)) vulnerability.cvss = cvss;
        const severity = SEVERITY_ORDER.find((s) => severities.includes(s));
        if (severity) vulnerability.severity = severity;
        const depGroups = strings(entry.dependency_groups);
        if (Array.isArray(entry.dependency_groups)) vulnerability.dev = depGroups.length > 0 && depGroups.every((g) => g === 'dev');
        found.push(vulnerability);
      }
    }
  }
  return found;
}

/** Scans `lockfile` (relative to `root`) with osv-scanner. Needs the network for osv.dev lookups. */
export async function runOsvScanner(root: string, lockfile: string, tools: ToolContext): Promise<ToolRun<Vulnerability[]>> {
  const run = await runJsonTool(tools, { command: 'osv-scanner', args: osvArgs(lockfile), cwd: root, installHint: OSV_INSTALL_HINT });
  if (run.exitCode === NO_PACKAGES) return { ok: true, value: [] };
  if (!run.ok) return { ok: false, reason: run.reason };
  if (run.exitCode !== 0 && run.exitCode !== 1) return { ok: false, reason: `osv-scanner failed (exit code ${run.exitCode ?? 'none'})` };
  const vulnerabilities = parseOsvReport(run.json);
  return vulnerabilities ? { ok: true, value: vulnerabilities } : { ok: false, reason: 'osv-scanner printed an unexpected report format' };
}
