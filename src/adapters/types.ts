/** The outcome of running an external tool: a value, or why the check could not run (becomes a skipped entry). */
export type ToolRun<T> = { ok: true; value: T } | { ok: false; reason: string };

/** A gitleaks finding without the secret: shipcheck never reads the Match or Secret fields. */
export interface GitleaksLeak {
  ruleId: string;
  description: string;
  /** Relative to the scan root, with forward slashes. */
  file: string;
  startLine: number;
  endLine: number;
  /** 1-based, inclusive. */
  startColumn: number;
  endColumn: number;
  /** Set for git-history findings. */
  commit?: string;
  date?: string;
}

export type AdvisorySeverity = 'critical' | 'high' | 'moderate' | 'low';

/** One advisory affecting one installed package version, normalized from osv-scanner, npm audit or pnpm audit. */
export interface Vulnerability {
  package: string;
  /** Empty when the tool does not report it (npm audit); callers fill it from the lockfile. */
  version: string;
  /** Advisory ids, GHSA first, then aliases such as CVE ids. */
  ids: string[];
  title: string;
  /** Highest CVSS base score, when the tool reports one. */
  cvss?: number;
  severity?: AdvisorySeverity;
  url: string;
  /** Versions that fix the advisory, as reported by the tool. */
  fixedVersions: string[];
  /** Only reached through devDependencies; undefined when the tool does not say. */
  dev?: boolean;
  tool: 'osv-scanner' | 'npm audit' | 'pnpm audit';
}
