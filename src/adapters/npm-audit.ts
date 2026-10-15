import { redactEvidence } from '../core/redact.js';
import { runJsonTool, type ToolContext } from './exec.js';
import { advisorySeverity, advisoryUrl, orderIds } from './osv.js';
import type { ToolRun, Vulnerability } from './types.js';

export type AuditManager = 'npm' | 'pnpm';

const INSTALL_HINT: Record<AuditManager, string> = {
  npm: 'npm ships with Node.js: https://nodejs.org/',
  pnpm: 'install pnpm: https://pnpm.io/installation',
};

/** `--package-lock-only` audits package-lock.json without needing node_modules; pnpm audit always reads pnpm-lock.yaml. */
export function auditArgs(manager: AuditManager): string[] {
  return manager === 'npm' ? ['audit', '--json', '--package-lock-only'] : ['audit', '--json'];
}

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json => !!value && typeof value === 'object' && !Array.isArray(value);
const objects = (value: unknown): Json[] => (Array.isArray(value) ? value.filter(isObject) : []);
const text = (value: unknown) => (typeof value === 'string' ? value : '');
const GHSA = /GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}/;

function idsFrom(url: string, extra: unknown[] = []): string[] {
  const ghsa = GHSA.exec(url)?.[0];
  return orderIds([...(ghsa ? [ghsa] : []), ...extra.filter((v): v is string => typeof v === 'string' && v !== '')]);
}

/**
 * Normalizes `npm audit --json` (auditReportVersion 2). Only advisory objects in `via` describe the
 * vulnerable package itself; string entries just point at a vulnerable dependency. npm does not report
 * installed versions, so `version` stays empty.
 */
export function parseNpmAudit(report: unknown): Vulnerability[] | undefined {
  if (!isObject(report) || !isObject(report.vulnerabilities)) return undefined;
  const found: Vulnerability[] = [];
  for (const [name, entry] of Object.entries(report.vulnerabilities)) {
    if (!isObject(entry)) continue;
    const fix = isObject(entry.fixAvailable) && text(entry.fixAvailable.name) === name ? [text(entry.fixAvailable.version)].filter(Boolean) : [];
    for (const via of objects(entry.via)) {
      if (text(via.name) && text(via.name) !== name) continue;
      const url = text(via.url);
      const ids = idsFrom(url);
      if (!ids.length) continue;
      const vulnerability: Vulnerability = { package: name, version: '', ids, title: text(via.title) || ids[0]!, url: url || advisoryUrl(ids[0]!), fixedVersions: fix, tool: 'npm audit' };
      const score = isObject(via.cvss) ? via.cvss.score : undefined;
      // npm reports a score of 0 when an advisory has no CVSS vector.
      if (typeof score === 'number' && score > 0) vulnerability.cvss = score;
      const severity = advisorySeverity(via.severity);
      if (severity) vulnerability.severity = severity;
      found.push(vulnerability);
    }
  }
  return found;
}

/** Normalizes `pnpm audit --json`: one entry per advisory and installed version. pnpm reports no CVSS scores. */
export function parsePnpmAudit(report: unknown): Vulnerability[] | undefined {
  if (!isObject(report) || !isObject(report.advisories)) return undefined;
  const found: Vulnerability[] = [];
  for (const advisory of Object.values(report.advisories)) {
    if (!isObject(advisory)) continue;
    const name = text(advisory.module_name);
    const url = text(advisory.url);
    const ids = idsFrom(url, [text(advisory.github_advisory_id), ...(Array.isArray(advisory.cves) ? advisory.cves : [])]);
    if (!name || !ids.length) continue;
    const fixedVersions = [...text(advisory.patched_versions).matchAll(/>=\s*([0-9][^\s|]*)/g)].map((m) => m[1]!);
    const byVersion = new Map<string, boolean>();
    for (const finding of objects(advisory.findings)) {
      const version = text(finding.version);
      // A version is dev-only when every path to it is a dev path.
      byVersion.set(version, (byVersion.get(version) ?? true) && finding.dev === true);
    }
    for (const [version, dev] of byVersion) {
      const vulnerability: Vulnerability = { package: name, version, ids, title: text(advisory.title) || ids[0]!, url: url || advisoryUrl(ids[0]!), fixedVersions, dev, tool: 'pnpm audit' };
      const severity = advisorySeverity(advisory.severity);
      if (severity) vulnerability.severity = severity;
      found.push(vulnerability);
    }
  }
  return found;
}

/** Audits the lockfile with the package manager's registry audit. Needs the network. */
export async function runPackageAudit(root: string, manager: AuditManager, tools: ToolContext): Promise<ToolRun<Vulnerability[]>> {
  const run = await runJsonTool(tools, { command: manager, args: auditArgs(manager), cwd: root, installHint: INSTALL_HINT[manager] });
  if (!run.ok) return { ok: false, reason: run.reason };
  // npm and pnpm both print {"error": {...}} and exit 1 when the audit itself fails.
  if (isObject(run.json) && isObject(run.json.error)) {
    const error = run.json.error;
    return { ok: false, reason: redactEvidence(`${manager} audit failed: ${text(error.summary) || text(error.message) || text(error.code) || 'unknown error'}`) };
  }
  const vulnerabilities = manager === 'npm' ? parseNpmAudit(run.json) : parsePnpmAudit(run.json);
  return vulnerabilities ? { ok: true, value: vulnerabilities } : { ok: false, reason: `${manager} audit printed an unexpected report format` };
}
