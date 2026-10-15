import type { Node, SourceFile } from 'ts-morph';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export type Category =
  | 'authentication'
  | 'authorization'
  | 'rate-limiting'
  | 'input-validation'
  | 'secrets'
  | 'dependencies'
  | 'http-config'
  | 'data-protection'
  | 'integrations'
  | 'infra'
  | 'live';
export type FindingSource = 'static' | 'tool:gitleaks' | 'tool:osv' | 'tool:npm-audit' | 'live';
export type StackId = 'nextjs-app-router' | 'supabase' | 'vercel' | 'cloudflare';

/** What a rule returns. The normalizer turns it into a {@link Finding}. */
export interface RawFinding {
  /** Repo-relative, forward slashes. */
  file?: string;
  line?: number;
  column?: number;
  endLine?: number;
  /** Live findings only. */
  url?: string;
  /** Short snippet; the normalizer redacts and truncates it. */
  evidence: string;
  /** Overrides the rule default when context matters. */
  explanation?: string;
  fix?: string;
  /** Override, e.g. escalate to critical on DB writes. */
  severity?: Severity;
  confidence?: Confidence;
}

/** What the report contains. */
export interface Finding {
  /** Fingerprint, see core/fingerprint.ts. */
  id: string;
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  advisory: boolean;
  source: FindingSource;
  file: string | null;
  line: number | null;
  column: number | null;
  endLine: number | null;
  url: string | null;
  evidence: string;
  explanation: string;
  fix: string;
  cwe?: string;
  references: string[];
}

export interface Rule {
  /** e.g. 'AUTHZ-001' */
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  advisory?: boolean;
  /** The rule runs only if every listed stack is detected. */
  stacks: StackId[];
  /** Default 'static'. */
  source?: FindingSource;
  /** What and why, including known limitations. */
  description: string;
  /** Default plain-language explanation. */
  explanation: string;
  /** Default fix guidance. */
  fix: string;
  falsePositiveNote: string;
  cwe?: string;
  references?: string[];
  run(ctx: ScanContext): RawFinding[] | Promise<RawFinding[]>;
}

/** A named group of rules for one stack combination. */
export interface RulePack {
  id: string;
  title: string;
  rules: Rule[];
}

export interface RouteHandler {
  file: string;
  routePath: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';
  /** FunctionDeclaration, or the initializer of an exported const (arrow, function expression or wrapper call). */
  node: Node;
}

export interface ServerAction {
  file: string;
  name: string;
  node: Node;
}

export interface NextConfigOption {
  /** Literal value; undefined when dynamic. */
  value: unknown;
  line: number;
  dynamic: boolean;
}

export interface NextConfigInfo {
  file: string;
  objectLine: number;
  options: Record<string, NextConfigOption>;
  hasHeadersFn: boolean;
  /** True when the object literal contains a spread (`...base`) that may set options we cannot see. */
  hasSpread?: boolean;
}

export interface MiddlewareInfo {
  file: string;
  /** null = runs on every route. */
  matchers: string[] | null;
}

export interface ScanContext {
  root: string;
  stacks: ReadonlySet<StackId>;
  /** Repo-relative, after ignores. */
  files: readonly string[];
  /** Cached. */
  readText(file: string): string;
  /** Lazy, cached, no type-check. */
  getSourceFile(file: string): SourceFile;
  packageJson: { file: string; data: Record<string, unknown> } | null;
  lockfile: { kind: 'pnpm' | 'npm' | 'yarn' | 'bun'; file: string } | null;
  envFiles: { file: string; entries: { key: string; value: string; line: number }[] }[];
  sqlMigrations: { file: string; text: string }[];
  nextConfig: NextConfigInfo | null;
  vercelJson: { file: string; data: unknown } | null;
  /** Populated from wrangler.toml, or from wrangler.jsonc / wrangler.json when no TOML file exists. */
  wranglerToml: { file: string; data: unknown } | null;
  gitignore: { file: string; patterns: string[] } | null;
  next: {
    routeHandlers(): RouteHandler[];
    serverActions(): ServerAction[];
    /** null matchers = runs on every route. */
    middleware(): MiddlewareInfo | null;
    /** 'use client' directive. */
    isClientFile(file: string): boolean;
  };
  config: ShipcheckConfig;
}

/** From shipcheck.config.json, zod-validated, all optional. */
export interface ShipcheckConfig {
  ignorePaths: string[];
  /** Extra function names that count as auth checks. */
  authHelpers: string[];
  rateLimitHelpers: string[];
  rules: Record<string, 'off' | Severity>;
}

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface ScanResult {
  schemaVersion: '1.0';
  tool: { name: 'shipcheck'; version: string };
  target: { path: string };
  stack: StackId[];
  score: { value: number; grade: Grade; byCategory: Record<Category, number> };
  findings: Finding[];
  suppressedCount: number;
  skipped: { check: string; reason: string }[];
  ruleErrors: { ruleId: string; message: string }[];
  durationMs: number;
}
