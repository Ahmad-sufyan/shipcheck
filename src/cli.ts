#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { Command, CommanderError, Option } from 'commander';
import { loadUserConfig } from './context/user-config.js';
import { ShipcheckError } from './core/errors.js';
import { filterFindings, hasBlockingFindings, scan, VERSION } from './core/scan.js';
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
}

interface ScanFlags extends ReportFlags {
  offline?: boolean;
  cloudflare?: boolean;
}

interface LiveFlags extends ReportFlags {
  root: string;
  dryRun?: boolean;
}

/** --format, --out, --fail-on, --min-severity and --config, shared by scan and live. */
function addReportOptions(command: Command, configHelp: string): Command {
  return command
    .addOption(new Option('-f, --format <format>', 'output format').choices([...FORMATS]).default('text'))
    .option('-o, --out <file>', 'write the report to a file instead of stdout')
    .addOption(new Option('--fail-on <severity>', 'exit 1 when a non-advisory finding is at or above this severity').choices([...SEVERITIES, 'none']).default('high'))
    .addOption(
      new Option('--min-severity <severity>', 'only show findings at or above this severity (display only; does not change the exit code)').choices([...SEVERITIES]).default('info'),
    )
    .option('-c, --config <file>', configHelp);
}

function emitReport(result: ScanResult, flags: ReportFlags): number {
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
  return hasBlockingFindings(result, flags.failOn) ? EXIT_FINDINGS : EXIT_OK;
}

async function runScan(path: string, flags: ScanFlags): Promise<number> {
  const result = await scan(path, { ...(flags.config === undefined ? {} : { configFile: flags.config }), offline: flags.offline === true, cloudflare: flags.cloudflare === true });
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
  const { result, verifiedBy, requestsSent } = await runLive({ ...(url === undefined ? {} : { url }), config, root, env: process.env });
  process.stderr.write(`shipcheck: ownership verified via ${verifiedBy === 'dns' ? 'DNS TXT record' : 'the well-known file'}; ${requestsSent} requests sent\n`);
  return emitReport(result, flags);
}

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
