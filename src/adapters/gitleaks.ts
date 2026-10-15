import { runJsonTool, type ToolContext } from './exec.js';
import { gitRepo } from './git.js';
import type { GitleaksLeak, ToolRun } from './types.js';

export const GITLEAKS_INSTALL_HINT = 'install gitleaks 8.19 or newer: https://github.com/gitleaks/gitleaks#installing';

/** `dir` scans the working tree, `git` the commit history (gitleaks 8.19+; older versions used `detect --no-git`). */
export type GitleaksMode = 'dir' | 'git';

/**
 * JSON report on stdout, secrets redacted by gitleaks itself (`--redact` defaults to 100%), no banner and
 * only errors on stderr. gitleaks loads `<root>/.gitleaks.toml` when present, so project allowlists apply.
 */
export function gitleaksArgs(mode: GitleaksMode): string[] {
  return [mode, '.', '--report-format', 'json', '--report-path', '-', '--redact=100', '--no-banner', '--log-level', 'error'];
}

const text = (value: unknown) => (typeof value === 'string' ? value : '');
const int = (value: unknown) => (typeof value === 'number' && Number.isFinite(value) ? Math.max(0, Math.trunc(value)) : 0);

/**
 * gitleaks counts columns from the newline before the line instead of the line's first character, so on
 * every line but the first of the text it scanned both columns come out one too high (8.30.1). `dir` scans
 * a file as one piece up to 100 KB, which makes line 1 the only exact one. Where this guesses wrong (the
 * first line of a later piece or of a diff hunk), the column is one too early, and maskSpan then hides
 * one more character instead of showing one.
 */
const column = (value: unknown, line: number) => Math.max(0, int(value) - (line > 1 ? 1 : 0));

/**
 * Normalizes a gitleaks JSON report. Match and Secret are never read, so an unredacted report cannot leak
 * into findings. In git mode, paths are relative to the repository; `prefix` keeps the leaks under the
 * scan root and makes them relative to it. Returns undefined for an unexpected report shape.
 */
export function parseGitleaksReport(report: unknown, prefix = ''): GitleaksLeak[] | undefined {
  if (!Array.isArray(report)) return undefined;
  const leaks: GitleaksLeak[] = [];
  for (const item of report) {
    if (!item || typeof item !== 'object') continue;
    const raw = item as Record<string, unknown>;
    let file = text(raw.File).replaceAll('\\', '/').replace(/^\.\//, '');
    if (prefix) {
      if (!file.startsWith(prefix)) continue;
      file = file.slice(prefix.length);
    }
    if (!file) continue;
    const startLine = int(raw.StartLine);
    const endLine = int(raw.EndLine);
    const leak: GitleaksLeak = {
      ruleId: text(raw.RuleID),
      description: text(raw.Description),
      file,
      startLine,
      endLine,
      startColumn: column(raw.StartColumn, startLine),
      endColumn: column(raw.EndColumn, endLine),
    };
    if (text(raw.Commit)) leak.commit = text(raw.Commit);
    if (text(raw.Date)) leak.date = text(raw.Date);
    leaks.push(leak);
  }
  return leaks.sort((a, b) => a.file.localeCompare(b.file) || a.startLine - b.startLine || a.ruleId.localeCompare(b.ruleId) || (a.commit ?? '').localeCompare(b.commit ?? ''));
}

async function scanWithGitleaks(root: string, mode: GitleaksMode, tools: ToolContext): Promise<ToolRun<GitleaksLeak[]>> {
  let prefix = '';
  if (mode === 'git') {
    const repo = await gitRepo(root, tools);
    if (!repo) return { ok: false, reason: 'not a git repository (or git is not installed), so there is no history to scan' };
    prefix = repo.prefix;
  }
  const run = await runJsonTool(tools, { command: 'gitleaks', args: gitleaksArgs(mode), cwd: root, installHint: GITLEAKS_INSTALL_HINT });
  if (!run.ok) {
    return /unknown command/i.test(run.reason) ? { ok: false, reason: `gitleaks is older than 8.19 and has no "${mode}" command; ${GITLEAKS_INSTALL_HINT}` } : { ok: false, reason: run.reason };
  }
  const leaks = parseGitleaksReport(run.json, prefix);
  return leaks ? { ok: true, value: leaks } : { ok: false, reason: 'gitleaks printed an unexpected report format' };
}

const runs = new WeakMap<ToolContext, Map<string, Promise<ToolRun<GitleaksLeak[]>>>>();

/** Runs gitleaks once per scan and mode; SECRET-003 and SECRET-004 share the working-tree scan. */
export function runGitleaks(root: string, mode: GitleaksMode, tools: ToolContext): Promise<ToolRun<GitleaksLeak[]>> {
  let byKey = runs.get(tools);
  if (!byKey) runs.set(tools, (byKey = new Map()));
  const key = `${mode}\0${root}`;
  let run = byKey.get(key);
  if (!run) byKey.set(key, (run = scanWithGitleaks(root, mode, tools)));
  return run;
}
