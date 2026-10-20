#!/usr/bin/env node
import { appendFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { Command, CommanderError, Option } from 'commander';
import { loadUserConfig } from './context/user-config.js';
import { BASELINE_FILE, baselineEntry, loadBaseline, loadBaselineIfPresent, pruneBaseline, today, writeBaseline } from './core/baseline.js';
import { ShipcheckError } from './core/errors.js';
import { filterFindings, hasBlockingFindings, scan, VERSION, type ScanOptions } from './core/scan.js';
import { formatSetup, initOwnership } from './live/ownership.js';
import { formatPlan, LEGAL_WARNING, liveTarget, planLive, runLive } from './live/prober.js';
import { renderJson } from './reporters/json.js';
import { renderMarkdown } from './reporters/markdown.js';
import { renderText, shouldUseColor } from './reporters/text.js';
import { SEVERITIES } from './schema.js';
import type { ScanResult, Severity } from './types.js';

/** Exit codes: 0 = nothing at or above --fail-on, 1 = blocking findings, 2 = usage or runtime error. */
const EXIT_OK = 0;
const EXIT_FINDINGS = 1;
const EXIT_ERROR = 2;

const FORMATS = ['text', 'json', 'md'] as const;

interface ReportFlags {
  format: (typeof FORMATS)[number];
  out?: string;
  failOn: Severity | 'none';
  minSeverity: Severity;
  config?: string;
  /** A path, false for --no-baseline, undefined for the default file. */
  baseline?: string | false;
  mdSummary?: string;
}

interface ScanFlags extends ReportFlags {
  offline?: boolean;
  cloudflare?: boolean;
}

interface LiveFlags extends ReportFlags {
  root: string;
  dryRun?: boolean;
}

interface BaselineFlags {
  file?: string;
  config?: string;
  offline?: boolean;
  reason?: string;
  expires?: string;
  acceptedBy?: string;
  force?: boolean;
}

/** --format, --out, --fail-on, --min-severity, --config and the baseline flags, shared by scan and live. */
function addReportOptions(command: Command, configHelp: string, baselineHelp: string): Command {
  return command
    .addOption(new Option('-f, --format <format>', 'output format').choices([...FORMATS]).default('text'))
    .option('-o, --out <file>', 'write the report to a file instead of stdout')
    .option('--md-summary <file>', 'also append the Markdown report to this file (for $GITHUB_STEP_SUMMARY)')
    .addOption(new Option('--fail-on <severity>', 'exit 1 when a non-advisory finding is at or above this severity').choices([...SEVERITIES, 'none']).default('high'))
    .addOption(
      new Option('--min-severity <severity>', 'only show findings at or above this severity (display only; does not change the exit code)').choices([...SEVERITIES]).default('info'),
    )
    .option('-c, --config <file>', configHelp)
    .option('--baseline <file>', baselineHelp)
    .option('--no-baseline', 'report every finding, ignoring the baseline file');
}

function emitReport(result: ScanResult, flags: ReportFlags): number {
  for (const warning of result.warnings) process.stderr.write(`shipcheck: warning: ${warning}\n`);
  const shown = filterFindings(result, flags.minSeverity);
  let report: string;
  if (flags.format === 'json') report = renderJson(shown);
  else if (flags.format === 'md') report = renderMarkdown(shown);
  else report = renderText(shown, { color: !flags.out && shouldUseColor(process.env, process.stdout.isTTY) });

  if (flags.out) {
    const file = resolve(flags.out);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, report);
    process.stderr.write(`shipcheck: wrote ${flags.format} report to ${flags.out} (score ${result.score.value}/100 ${result.score.grade}, ${result.findings.length} findings)\n`);
  } else {
    process.stdout.write(report);
  }
  if (flags.mdSummary) appendFileSync(resolve(flags.mdSummary), renderMarkdown(shown));
  return hasBlockingFindings(result, flags.failOn) ? EXIT_FINDINGS : EXIT_OK;
}

async function runScan(path: string, flags: ScanFlags): Promise<number> {
  const result = await scan(path, {
    ...(flags.config === undefined ? {} : { configFile: flags.config }),
    ...(flags.baseline === undefined ? {} : { baseline: flags.baseline }),
    offline: flags.offline === true,
    cloudflare: flags.cloudflare === true,
  });
  return emitReport(result, flags);
}

async function runLiveCommand(url: string | undefined, flags: LiveFlags): Promise<number> {
  process.stderr.write(`${LEGAL_WARNING}\n`);
  const root = resolve(flags.root);
  const { config } = loadUserConfig(root, flags.config);
  if (flags.dryRun) {
    const target = liveTarget({ ...(url === undefined ? {} : { url }), config, env: process.env });
    process.stdout.write(formatPlan(target, planLive(target, config)));
    return EXIT_OK;
  }
  const { result, verifiedBy, requestsSent } = await runLive({
    ...(url === undefined ? {} : { url }),
    ...(flags.baseline === undefined ? {} : { baseline: flags.baseline }),
    config,
    root,
    env: process.env,
  });
  process.stderr.write(`shipcheck: ownership verified via ${verifiedBy === 'dns' ? 'DNS TXT record' : 'the well-known file'}; ${requestsSent} requests sent\n`);
  return emitReport(result, flags);
}

// ---------------------------------------------------------------------------------------------
// baseline create | add | prune

function baselinePath(path: string, flags: BaselineFlags): string {
  return flags.file ? resolve(flags.file) : join(resolve(path), BASELINE_FILE);
}

/** A scan with the baseline switched off, so every current finding is visible. */
function scanForBaseline(path: string, flags: BaselineFlags): Promise<ScanResult> {
  const options: ScanOptions = { baseline: false, offline: flags.offline === true, ...(flags.config === undefined ? {} : { configFile: flags.config }) };
  return scan(path, options);
}

function checkExpiry(expires: string | undefined): void {
  if (expires === undefined) return;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(expires) || Number.isNaN(Date.parse(`${expires}T00:00:00Z`))) throw new ShipcheckError(`--expires must be a date like 2026-12-31; got ${expires}`);
  if (expires < today()) throw new ShipcheckError(`--expires ${expires} is already in the past`);
}

async function baselineCreate(path: string, flags: BaselineFlags): Promise<number> {
  const file = baselinePath(path, flags);
  if (existsSync(file) && !flags.force) throw new ShipcheckError(`${file} already exists; use --force to replace it, or \`baseline add\` / \`baseline prune\` to change it`);
  checkExpiry(flags.expires);
  const result = await scanForBaseline(path, flags);
  const date = today();
  const entries = result.findings.map((finding) =>
    baselineEntry(finding, { reason: flags.reason ?? '', today: date, ...(flags.acceptedBy ? { acceptedBy: flags.acceptedBy } : {}), ...(flags.expires ? { expires: flags.expires } : {}) }),
  );
  if (!entries.length && !flags.reason?.trim()) throw new ShipcheckError('A baseline needs a reason (--reason "<why these findings are accepted>").');
  writeBaseline(file, { version: 1, entries });
  process.stdout.write(`Wrote ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'} to ${file}. Commit it; scans now fail only on new findings.\n`);
  return EXIT_OK;
}

async function baselineAdd(findingId: string, path: string, flags: BaselineFlags): Promise<number> {
  checkExpiry(flags.expires);
  const file = baselinePath(path, flags);
  const baseline = loadBaselineIfPresent(file) ?? { version: 1 as const, entries: [] };
  if (baseline.entries.some((entry) => entry.id === findingId)) throw new ShipcheckError(`${findingId} is already in ${file}`);
  const finding = (await scanForBaseline(path, flags)).findings.find((f) => f.id === findingId);
  if (!finding) throw new ShipcheckError(`No current finding has the id ${findingId}; the text and JSON reports show each finding's id`);
  const entry = baselineEntry(finding, { reason: flags.reason ?? '', today: today(), ...(flags.acceptedBy ? { acceptedBy: flags.acceptedBy } : {}), ...(flags.expires ? { expires: flags.expires } : {}) });
  writeBaseline(file, { version: 1, entries: [...baseline.entries, entry] });
  process.stdout.write(`Added ${finding.ruleId} ${finding.file ?? finding.url ?? '(project)'}${finding.line ? `:${finding.line}` : ''} to ${file}${entry.expires ? ` until ${entry.expires}` : ''}.\n`);
  return EXIT_OK;
}

async function baselinePrune(path: string, flags: BaselineFlags): Promise<number> {
  const file = baselinePath(path, flags);
  if (!existsSync(file)) throw new ShipcheckError(`Baseline file not found: ${file}`);
  const { baseline, removed } = pruneBaseline(loadBaseline(file), (await scanForBaseline(path, flags)).findings);
  writeBaseline(file, baseline);
  process.stdout.write(`Removed ${removed} entr${removed === 1 ? 'y' : 'ies'} that match no current finding; ${baseline.entries.length} remain in ${file}.\n`);
  return EXIT_OK;
}

function addBaselineScanOptions(command: Command): Command {
  return command
    .option('--file <file>', `baseline file (default: <path>/${BASELINE_FILE})`)
    .option('-c, --config <file>', 'path to a shipcheck.config.json (default: <path>/shipcheck.config.json)')
    .option('--offline', 'skip checks that need the network (DEP-001)');
}

// ---------------------------------------------------------------------------------------------

async function main(argv: string[]): Promise<number> {
  let exitCode = EXIT_OK;
  const program = new Command()
    .name('shipcheck')
    .description('Deterministic security auditor for Next.js (App Router) + Supabase apps on Vercel or Cloudflare.')
    .version(VERSION)
    .exitOverride();

  addReportOptions(
    program.command('scan').description('scan a project directory and report security findings').argument('[path]', 'project directory to scan', '.'),
    'path to a shipcheck.config.json (default: <path>/shipcheck.config.json)',
    `baseline file of accepted findings (default: <path>/${BASELINE_FILE} when present)`,
  )
    .option('--offline', 'skip checks that need the network (vulnerability database lookups for DEP-001)')
    .option('--cloudflare', 'read Cloudflare zone settings for INFRA-001..003 with a read-only CLOUDFLARE_API_TOKEN (GET requests only)')
    .action(async (path: string, flags: ScanFlags) => {
      exitCode = await runScan(path, flags);
    });

  const live = addReportOptions(
    program
      .command('live')
      .description('check a deployed site you own: ownership-verified, read-only, rate-limited (run `live init <url>` first)')
      .argument('[url]', 'https URL of the site (default: live.url from shipcheck.config.json)'),
    'path to a shipcheck.config.json (default: <root>/shipcheck.config.json)',
    `baseline file of accepted findings (default: <root>/${BASELINE_FILE} when present)`,
  )
    .option('--root <dir>', 'project directory holding shipcheck.config.json and .shipcheck/', '.')
    .option('--dry-run', 'print the numbered request plan and send nothing, not even the ownership check')
    .action(async (url: string | undefined, flags: LiveFlags) => {
      exitCode = await runLiveCommand(url, flags);
    });

  live
    .command('init')
    .description('create the ownership secret and print the value to serve at /.well-known/shipcheck.txt or in DNS')
    .argument('<url>', 'https URL of the site')
    .option('--force', 'replace an existing secret')
    .action((url: string, flags: { force?: boolean }) => {
      // --root belongs to `live`, so `live init <url> --root <dir>` reads it from there.
      const { root } = live.opts<{ root: string }>();
      process.stderr.write(`${LEGAL_WARNING}\n`);
      process.stdout.write(`${formatSetup(initOwnership(resolve(root), url, { force: flags.force === true }))}\n`);
    });

  const baseline = program.command('baseline').description('accept current findings so that only new ones fail the build');
  addBaselineScanOptions(baseline.command('create').description('accept every current finding').argument('[path]', 'project directory', '.'))
    .requiredOption('--reason <text>', 'why these findings are accepted (required)')
    .option('--accepted-by <name>', 'who accepted them')
    .option('--expires <date>', 'last day the entries suppress their findings (YYYY-MM-DD)')
    .option('--force', 'replace an existing baseline file')
    .action(async (path: string, flags: BaselineFlags) => {
      exitCode = await baselineCreate(path, flags);
    });
  addBaselineScanOptions(baseline.command('add').description('accept one finding by its id').argument('<findingId>', 'the id shown in the report').argument('[path]', 'project directory', '.'))
    .requiredOption('--reason <text>', 'why this finding is accepted (required)')
    .option('--accepted-by <name>', 'who accepted it')
    .option('--expires <date>', 'last day the entry suppresses its finding (YYYY-MM-DD)')
    .action(async (findingId: string, path: string, flags: BaselineFlags) => {
      exitCode = await baselineAdd(findingId, path, flags);
    });
  addBaselineScanOptions(baseline.command('prune').description('drop entries that match no current finding').argument('[path]', 'project directory', '.')).action(
    async (path: string, flags: BaselineFlags) => {
      exitCode = await baselinePrune(path, flags);
    },
  );

  try {
    await program.parseAsync(argv);
    return exitCode;
  } catch (error) {
    if (error instanceof CommanderError) return error.exitCode === 0 ? EXIT_OK : EXIT_ERROR;
    if (error instanceof ShipcheckError) {
      process.stderr.write(`shipcheck: ${error.message}\n`);
    } else {
      process.stderr.write(`shipcheck: unexpected error: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`);
    }
    return EXIT_ERROR;
  }
}

process.exitCode = await main(process.argv);
