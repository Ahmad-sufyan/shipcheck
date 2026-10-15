import { parse as parseToml } from 'smol-toml';
import type { ScanContext } from '../types.js';
import type { ProjectSource } from './files.js';

export type Skipped = { check: string; reason: string };

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function basename(file: string): string {
  return file.slice(file.lastIndexOf('/') + 1);
}

// ---------------------------------------------------------------------------------------------
// JSON / JSONC

/** Parses JSON with comments and trailing commas (wrangler.jsonc, tsconfig-style files). */
export function parseJsonc(text: string): unknown {
  let stripped = '';
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === '"') {
      const end = endOfString(text, i);
      stripped += text.slice(i, end);
      i = end;
    } else if (ch === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
    } else if (ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end === -1 ? text.length : end + 2;
    } else {
      stripped += ch;
      i++;
    }
  }

  let out = '';
  i = 0;
  while (i < stripped.length) {
    const ch = stripped[i]!;
    if (ch === '"') {
      const end = endOfString(stripped, i);
      out += stripped.slice(i, end);
      i = end;
      continue;
    }
    if (ch === ',') {
      let next = i + 1;
      while (next < stripped.length && /\s/.test(stripped[next]!)) next++;
      if (stripped[next] === '}' || stripped[next] === ']') {
        i++;
        continue;
      }
    }
    out += ch;
    i++;
  }
  return JSON.parse(out);
}

/** Index just past the closing quote of the string literal starting at `start`. */
function endOfString(text: string, start: number): number {
  let i = start + 1;
  while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
  return Math.min(i + 1, text.length);
}

function readJson(source: ProjectSource, file: string, skipped: Skipped[], jsonc = false): { file: string; data: unknown } | null {
  if (!source.has(file)) return null;
  try {
    const text = source.readText(file);
    return { file, data: jsonc ? parseJsonc(text) : JSON.parse(text) };
  } catch (error) {
    skipped.push({ check: file, reason: `invalid JSON: ${message(error)}` });
    return null;
  }
}

// ---------------------------------------------------------------------------------------------
// package.json and lockfiles

export function readPackageJson(source: ProjectSource, skipped: Skipped[]): ScanContext['packageJson'] {
  const result = readJson(source, 'package.json', skipped);
  if (!result) return null;
  if (typeof result.data !== 'object' || result.data === null || Array.isArray(result.data)) {
    skipped.push({ check: 'package.json', reason: 'invalid JSON: expected an object at the top level' });
    return null;
  }
  return { file: result.file, data: result.data as Record<string, unknown> };
}

const LOCKFILES: readonly [string, NonNullable<ScanContext['lockfile']>['kind']][] = [
  ['pnpm-lock.yaml', 'pnpm'],
  ['package-lock.json', 'npm'],
  ['npm-shrinkwrap.json', 'npm'],
  ['yarn.lock', 'yarn'],
  ['bun.lock', 'bun'],
  ['bun.lockb', 'bun'],
];

export function detectLockfile(source: ProjectSource): ScanContext['lockfile'] {
  for (const [file, kind] of LOCKFILES) if (source.has(file)) return { kind, file };
  return null;
}

// ---------------------------------------------------------------------------------------------
// .env files

const ENV_FILE = /^(?:\.env(?:\..+)?|\.dev\.vars(?:\..+)?)$/;
const ENV_LINE = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/;

/** dotenv-style parser: KEY=value, `export` prefixes, quotes and inline comments. Single-line values only. */
export function parseEnv(text: string): ScanContext['envFiles'][number]['entries'] {
  const entries: ScanContext['envFiles'][number]['entries'] = [];
  text.split(/\r?\n/).forEach((rawLine, index) => {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) return;
    const match = ENV_LINE.exec(line);
    if (!match) return;
    let value = match[2] ?? '';
    const quote = value[0];
    if (quote === '"' || quote === "'" || quote === '`') {
      const end = value.indexOf(quote, 1);
      value = end === -1 ? value.slice(1) : value.slice(1, end);
    } else {
      const comment = value.search(/\s#/);
      if (comment !== -1) value = value.slice(0, comment);
      value = value.trim();
    }
    entries.push({ key: match[1]!, value, line: index + 1 });
  });
  return entries;
}

/** Every .env* and Cloudflare .dev.vars* file in the project. */
export function parseEnvFiles(source: ProjectSource): ScanContext['envFiles'] {
  return source.files.filter((file) => ENV_FILE.test(basename(file))).map((file) => ({ file, entries: parseEnv(source.readText(file)) }));
}

// ---------------------------------------------------------------------------------------------
// SQL, platform configs, .gitignore

/** Every .sql file (Supabase migrations, seeds and declarative schemas), in path order. */
export function collectSqlMigrations(source: ProjectSource): ScanContext['sqlMigrations'] {
  return source.files.filter((file) => file.toLowerCase().endsWith('.sql')).map((file) => ({ file, text: source.readText(file) }));
}

export function readVercelJson(source: ProjectSource, skipped: Skipped[]): ScanContext['vercelJson'] {
  return readJson(source, 'vercel.json', skipped);
}

/** wrangler.toml, else wrangler.jsonc, else wrangler.json. */
export function readWranglerConfig(source: ProjectSource, skipped: Skipped[]): ScanContext['wranglerToml'] {
  if (source.has('wrangler.toml')) {
    try {
      return { file: 'wrangler.toml', data: parseToml(source.readText('wrangler.toml')) };
    } catch (error) {
      skipped.push({ check: 'wrangler.toml', reason: `invalid TOML: ${message(error).split('\n')[0]}` });
      return null;
    }
  }
  return readJson(source, 'wrangler.jsonc', skipped, true) ?? readJson(source, 'wrangler.json', skipped, true);
}

export function readGitignore(source: ProjectSource): ScanContext['gitignore'] {
  if (!source.has('.gitignore')) return null;
  const patterns = source
    .readText('.gitignore')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
  return { file: '.gitignore', patterns };
}
