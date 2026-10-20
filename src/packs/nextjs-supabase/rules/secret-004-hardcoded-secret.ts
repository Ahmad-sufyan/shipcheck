import { runGitleaks } from '../../../adapters/gitleaks.js';
import { fileSetOf, lineAt } from '../../../context/files.js';
import type { RawFinding, Rule, ScanContext } from '../../../types.js';
import { findSecrets, isPlaceholder, maskSpan, SUPABASE_PATTERN_IDS } from '../analysis/secret-patterns.js';

/** .env files are covered by SECRET-001, SECRET-002 and SECRET-007. */
const ENV_FILE = /(?:^|\/)(?:\.env(?:\..+)?|\.dev\.vars(?:\..+)?)$/;
const LOCKFILE = /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$/;
const TEXT_FILE = /\.(?:[cm]?[jt]sx?|json5?|jsonc|ya?ml|toml|sql|sh|bash|html?|vue|svelte|astro|py|rb|go|php|ini|cfg|conf|properties|xml|txt|mdx?)$/i;
const MAX_FILE_BYTES = 1_000_000;

function scannable(file: string): boolean {
  return !ENV_FILE.test(file) && !LOCKFILE.test(file);
}

/** shipcheck's own patterns, line by line. `ids` limits them (the Supabase ones gitleaks lacks). */
function builtInFindings(ctx: ScanContext, ids?: ReadonlySet<string>): RawFinding[] {
  const findings: RawFinding[] = [];
  for (const file of ctx.files) {
    if (!scannable(file) || !TEXT_FILE.test(file)) continue;
    const text = ctx.readText(file);
    if (text.length > MAX_FILE_BYTES) continue;
    text.split(/\r?\n/).forEach((line, index) => {
      const secret = findSecrets(line, ids).find((match) => !isPlaceholder(match.value));
      if (!secret) return;
      findings.push({
        file,
        line: index + 1,
        column: secret.index + 1,
        evidence: maskSpan(line, secret.index, secret.index + secret.value.length).trim(),
        explanation: `A ${secret.name} is written into the source. Anyone with access to the code, its git history or (for client code) the browser bundle can use it.`,
        source: 'static',
      });
    });
  }
  return findings;
}

export const secret004: Rule = {
  id: 'SECRET-004',
  title: 'Hardcoded secret',
  category: 'secrets',
  severity: 'high',
  confidence: 'high',
  source: 'tool:gitleaks',
  stacks: [],
  timeoutMs: 130_000,
  description:
    'Runs `gitleaks dir` over the working tree (with --redact) and reports each finding outside .env files and lockfiles, ' +
    'with the secret masked. gitleaks has no Supabase rules, so shipcheck always adds its own Supabase secret-key and ' +
    'service_role JWT patterns; when gitleaks is not installed it falls back to its built-in patterns (Stripe, Supabase, ' +
    'OpenAI, Anthropic, GitHub, AWS) and records the skip. A .gitleaks.toml in the project is honoured.',
  explanation:
    'A secret written into the code travels with every copy of the repository, its history and, for client code, the ' +
    'browser bundle. It cannot be rotated without a code change, and it is easy to leak by accident.',
  fix:
    'Move the value to an environment variable read on the server, rotate the key (it is in git history already), and ' +
    'add gitleaks to a pre-commit hook or CI so new secrets are caught before they land.',
  falsePositiveNote: 'Test fixtures and documentation can contain fake keys; allowlist their paths in a .gitleaks.toml at the project root.',
  cwe: 'CWE-798',
  references: ['https://github.com/gitleaks/gitleaks', 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password'],
  async run(ctx) {
    const findings: RawFinding[] = [];
    let builtIn: ReadonlySet<string> | undefined;
    if (ctx.tools) {
      const run = await runGitleaks(ctx.root, 'dir', ctx.tools);
      if (run.ok) {
        builtIn = SUPABASE_PATTERN_IDS;
        const scanned = fileSetOf(ctx.files);
        for (const leak of run.value) {
          if (!scanned.has(leak.file) || !scannable(leak.file)) continue;
          const line = lineAt(ctx.readText(leak.file), leak.startLine);
          const start = Math.max(0, leak.startColumn - 1);
          const evidence = leak.startLine === leak.endLine && line ? maskSpan(line, start, leak.endColumn).trim() : `${leak.ruleId} (multi-line match)`;
          findings.push({
            file: leak.file,
            line: leak.startLine,
            column: leak.startColumn,
            evidence,
            explanation: `gitleaks rule ${leak.ruleId}: ${leak.description || 'a secret'} The value is in the source, so anyone with the code can use it.`,
            source: 'tool:gitleaks',
          });
        }
      } else {
        ctx.skip?.('SECRET-004', `${run.reason}; used shipcheck's built-in patterns instead`);
      }
    }
    const reported = new Set(findings.map((f) => `${f.file}:${f.line}`));
    for (const finding of builtInFindings(ctx, builtIn)) {
      if (!reported.has(`${finding.file}:${finding.line}`)) findings.push(finding);
    }
    return findings;
  },
};
