#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { Command, CommanderError, Option } from 'commander';
import { ShipcheckError } from './core/errors.js';
import { filterFindings, hasBlockingFindings, scan, VERSION } from './core/scan.js';
import { renderJson } from './reporters/json.js';
import { renderMarkdown } from './reporters/markdown.js';
import { renderText, shouldUseColor } from './reporters/text.js';
import { SEVERITIES } from './schema.js';
import type { Severity } from './types.js';

/** Exit codes: 0 = nothing at or above --fail-on, 1 = blocking findings, 2 = usage or runtime error. */
const EXIT_OK = 0;
const EXIT_FINDINGS = 1;
const EXIT_ERROR = 2;

interface ScanFlags {
  format: 'text' | 'json' | 'md';
  out?: string;
  failOn: Severity | 'none';
  minSeverity: Severity;
  config?: string;
}

async function runScan(path: string, flags: ScanFlags): Promise<number> {
  const result = await scan(path, flags.config === undefined ? {} : { configFile: flags.config });
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

async function main(argv: string[]): Promise<number> {
  let exitCode = EXIT_OK;
  const program = new Command()
    .name('shipcheck')
    .description('Deterministic security auditor for Next.js (App Router) + Supabase apps on Vercel or Cloudflare.')
    .version(VERSION)
    .exitOverride();

  program
    .command('scan')
    .description('scan a project directory and report security findings')
    .argument('[path]', 'project directory to scan', '.')
    .addOption(new Option('-f, --format <format>', 'output format').choices(['text', 'json', 'md']).default('text'))
    .option('-o, --out <file>', 'write the report to a file instead of stdout')
    .addOption(
      new Option('--fail-on <severity>', 'exit 1 when a non-advisory finding is at or above this severity')
        .choices([...SEVERITIES, 'none'])
        .default('high'),
    )
    .addOption(
      new Option('--min-severity <severity>', 'only show findings at or above this severity (display only; does not change the exit code)')
        .choices([...SEVERITIES])
        .default('info'),
    )
    .option('-c, --config <file>', 'path to a shipcheck.config.json (default: <path>/shipcheck.config.json)')
    .action(async (path: string, flags: ScanFlags) => {
      exitCode = await runScan(path, flags);
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
