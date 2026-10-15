import type { ToolContext } from './exec.js';
import { runPackageAudit } from './npm-audit.js';
import { runOsvScanner } from './osv.js';
import type { ToolRun, Vulnerability } from './types.js';

export type { AdvisorySeverity, GitleaksLeak, ToolRun, Vulnerability } from './types.js';
export { defaultExec, findExecutable, runJsonTool, TOOL_TIMEOUT_MS, type ExecFn, type ExecOptions, type ExecResult, type ToolContext } from './exec.js';
export { gitIgnored, gitRepo, gitTracked, type GitRepo } from './git.js';
export { GITLEAKS_INSTALL_HINT, gitleaksArgs, parseGitleaksReport, runGitleaks, type GitleaksMode } from './gitleaks.js';
export { OSV_INSTALL_HINT, osvArgs, parseOsvReport, runOsvScanner } from './osv.js';
export { auditArgs, parseNpmAudit, parsePnpmAudit, runPackageAudit, type AuditManager } from './npm-audit.js';

export interface VulnerabilityScan {
  tool: Vulnerability['tool'];
  vulnerabilities: Vulnerability[];
}

/**
 * Known vulnerabilities in the lockfile: osv-scanner when it works, otherwise the package manager's
 * own audit (npm or pnpm). Both query online databases, so callers honour `tools.offline` first.
 */
export async function findVulnerabilities(root: string, lockfile: { kind: 'npm' | 'pnpm' | 'yarn' | 'bun'; file: string }, tools: ToolContext): Promise<ToolRun<VulnerabilityScan>> {
  const osv = await runOsvScanner(root, lockfile.file, tools);
  if (osv.ok) return { ok: true, value: { tool: 'osv-scanner', vulnerabilities: osv.value } };
  if (lockfile.kind !== 'npm' && lockfile.kind !== 'pnpm') return { ok: false, reason: `${osv.reason}; there is no audit fallback for ${lockfile.kind} lockfiles` };
  const audit = await runPackageAudit(root, lockfile.kind, tools);
  if (audit.ok) return { ok: true, value: { tool: `${lockfile.kind} audit`, vulnerabilities: audit.value } };
  return { ok: false, reason: `${osv.reason}; ${audit.reason}` };
}
