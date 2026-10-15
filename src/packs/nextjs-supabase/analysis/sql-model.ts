import type { ScanContext } from '../../../types.js';

export type PolicyCommand = 'all' | 'select' | 'insert' | 'update' | 'delete';

export interface SqlTable {
  schema: string;
  name: string;
  file: string;
  line: number;
}

export interface SqlPolicy {
  /** Table key: bare name for the public schema, `schema.name` otherwise. */
  table: string;
  name: string;
  command: PolicyCommand;
  roles: string[];
  using: string | null;
  withCheck: string | null;
  permissive: boolean;
  file: string;
  line: number;
}

export interface SqlModel {
  tables: SqlTable[];
  /** Table keys whose final state (after all migrations, in path order) has RLS enabled. */
  rlsEnabled: Set<string>;
  /** `disable row level security` statements that leave a table without RLS. */
  rlsDisabled: { table: string; file: string; line: number }[];
  /** Tables revoked from both `anon` and `authenticated`, so the Data API cannot reach them. */
  revokedFromApi: Set<string>;
  policies: SqlPolicy[];
}

interface Statement {
  sql: string;
  line: number;
}

/** Splits SQL into statements, blanking comments and respecting quotes and dollar-quoted bodies. */
export function splitStatements(text: string): Statement[] {
  const statements: Statement[] = [];
  let current = '';
  let start = -1;
  let line = 1;
  let i = 0;
  const flush = () => {
    if (start !== -1 && current.trim()) statements.push({ sql: current.trim(), line: start });
    current = '';
    start = -1;
  };
  const emit = (chunk: string) => {
    if (start === -1 && chunk.trim()) start = line;
    current += chunk;
    line += (chunk.match(/\n/g) ?? []).length;
  };

  while (i < text.length) {
    const ch = text[i]!;
    const rest = text.slice(i);
    if (rest.startsWith('--')) {
      const end = text.indexOf('\n', i);
      i = end === -1 ? text.length : end;
      emit(' ');
      continue;
    }
    if (rest.startsWith('/*')) {
      const end = text.indexOf('*/', i + 2);
      const comment = text.slice(i, end === -1 ? text.length : end + 2);
      emit(comment.replace(/[^\n]/g, ' '));
      i += comment.length;
      continue;
    }
    if (ch === "'" || ch === '"') {
      let j = i + 1;
      while (j < text.length) {
        if (text[j] === ch && text[j + 1] === ch) j += 2;
        else if (text[j] === ch) break;
        else j++;
      }
      emit(text.slice(i, j + 1));
      i = j + 1;
      continue;
    }
    const dollar = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(rest);
    if (dollar) {
      const tag = dollar[0];
      const end = text.indexOf(tag, i + tag.length);
      const body = text.slice(i, end === -1 ? text.length : end + tag.length);
      emit(body);
      i += body.length;
      continue;
    }
    if (ch === ';') {
      flush();
      i++;
      continue;
    }
    emit(ch);
    i++;
  }
  flush();
  return statements;
}

const IDENT = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][\w$]*)`;
const QNAME = String.raw`(${IDENT}(?:\s*\.\s*${IDENT})?)`;

function unquote(part: string): string {
  const trimmed = part.trim();
  return trimmed.startsWith('"') ? trimmed.slice(1, -1).replace(/""/g, '"') : trimmed.toLowerCase();
}

/** `public.Foo` -> { schema: 'public', name: 'foo' }; quoted identifiers keep their case. */
function qualifiedName(raw: string): { schema: string; name: string; key: string } {
  const parts = raw.match(new RegExp(IDENT, 'g')) ?? [raw];
  const name = unquote(parts.at(-1)!);
  const schema = parts.length > 1 ? unquote(parts[0]!) : 'public';
  return { schema, name, key: schema === 'public' ? name : `${schema}.${name}` };
}

function collapse(sql: string): string {
  return sql.replace(/\s+/g, ' ').trim();
}

/** Contents of the parenthesised expression that starts at `open` (the index of '('). */
function balanced(sql: string, open: number): string | null {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < sql.length; i++) {
    const ch = sql[i];
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') quote = ch;
    else if (ch === '(') depth++;
    else if (ch === ')' && --depth === 0) return collapse(sql.slice(open + 1, i));
  }
  return null;
}

const CREATE_TABLE = new RegExp(String.raw`^create\s+(?:(?:global|local)\s+)?(?:(temporary|temp)\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?${QNAME}`, 'i');
const ALTER_TABLE = new RegExp(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${QNAME}([\s\S]*)$`, 'i');
const REVOKE = /^revoke\s+[\s\S]+?\s+on\s+(?:table\s+)?([\s\S]+?)\s+from\s+([\s\S]+?)(?:\s+(?:cascade|restrict))?$/i;
const CREATE_POLICY = new RegExp(String.raw`^create\s+policy\s+(${IDENT})\s+on\s+${QNAME}([\s\S]*)$`, 'i');

export function buildSqlModel(migrations: readonly { file: string; text: string }[]): SqlModel {
  const tables: SqlTable[] = [];
  const policies: SqlPolicy[] = [];
  const rls = new Map<string, { enabled: boolean; file: string; line: number }>();
  const revokedRoles = new Map<string, Set<string>>();

  for (const { file, text } of migrations) {
    for (const { sql, line } of splitStatements(text)) {
      const table = CREATE_TABLE.exec(sql);
      if (table) {
        if (!table[1]) {
          const { schema, name } = qualifiedName(table[2]!);
          tables.push({ schema, name, file, line });
        }
        continue;
      }

      const alter = ALTER_TABLE.exec(sql);
      if (alter) {
        const { key } = qualifiedName(alter[1]!);
        const action = /\b(enable|disable)\s+row\s+level\s+security\b/i.exec(alter[2]!);
        if (action) rls.set(key, { enabled: action[1]!.toLowerCase() === 'enable', file, line });
        continue;
      }

      const revoke = REVOKE.exec(sql);
      if (revoke && !/^all\s+tables\s+in\s+schema/i.test(revoke[1]!.trim())) {
        const roles = revoke[2]!.split(',').map((role) => unquote(role));
        for (const target of revoke[1]!.split(',')) {
          const { key } = qualifiedName(target);
          const set = revokedRoles.get(key) ?? new Set<string>();
          roles.forEach((role) => set.add(role));
          revokedRoles.set(key, set);
        }
        continue;
      }

      const policy = CREATE_POLICY.exec(sql);
      if (policy) {
        const rest = policy[3]!;
        const usingAt = rest.search(/\busing\s*\(/i);
        const checkAt = rest.search(/\bwith\s+check\s*\(/i);
        const headEnd = Math.min(...[usingAt, checkAt].filter((n) => n !== -1), rest.length);
        const head = rest.slice(0, headEnd);
        const command = (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(head)?.[1]?.toLowerCase() ?? 'all') as PolicyCommand;
        const to = /\bto\s+([\s\S]+)$/i.exec(head.replace(/\bfor\s+(?:all|select|insert|update|delete)\b/i, ''))?.[1];
        policies.push({
          table: qualifiedName(policy[2]!).key,
          name: unquote(policy[1]!).replace(/^"|"$/g, ''),
          command,
          roles: to ? to.split(',').map((role) => unquote(role)) : ['public'],
          using: usingAt === -1 ? null : balanced(rest, rest.indexOf('(', usingAt)),
          withCheck: checkAt === -1 ? null : balanced(rest, rest.indexOf('(', checkAt)),
          permissive: !/\bas\s+restrictive\b/i.test(head),
          file,
          line,
        });
      }
    }
  }

  const rlsEnabled = new Set<string>();
  const rlsDisabled: SqlModel['rlsDisabled'] = [];
  for (const [table, state] of rls) {
    if (state.enabled) rlsEnabled.add(table);
    else rlsDisabled.push({ table, file: state.file, line: state.line });
  }
  const revokedFromApi = new Set([...revokedRoles].filter(([, roles]) => roles.has('anon') && roles.has('authenticated')).map(([table]) => table));
  return { tables, rlsEnabled, rlsDisabled, revokedFromApi, policies };
}

const models = new WeakMap<ScanContext, SqlModel>();

/** The SQL model for a scan, built once from ctx.sqlMigrations (already in path order). */
export function sqlModel(ctx: ScanContext): SqlModel {
  let model = models.get(ctx);
  if (!model) {
    model = buildSqlModel(ctx.sqlMigrations);
    models.set(ctx, model);
  }
  return model;
}

/** Whether any policy on `table` scopes rows to the signed-in user via auth.uid() or auth.jwt(). */
export function hasOwnerPolicy(model: SqlModel, table: string): boolean {
  return model.policies.some((p) => p.table === table && /auth\.(?:uid|jwt)\s*\(\s*\)/i.test(`${p.using ?? ''} ${p.withCheck ?? ''}`));
}
