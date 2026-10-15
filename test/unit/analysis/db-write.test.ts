import { Node, SyntaxKind } from 'ts-morph';
import { describe, expect, it } from 'vitest';
import { isDbWrite, supabaseTable, touchesData } from '../../../src/packs/nextjs-supabase/analysis/db-write.js';
import { code, memoryContext } from '../../helpers/memory-context.js';

/** The outermost call or tagged template on the single expression line `expr`. */
function outerCall(expr: string) {
  const sf = memoryContext({ 'lib/a.ts': `async function f() {\n  await ${expr}\n}` }).getSourceFile('lib/a.ts');
  const awaited = sf.getFirstDescendantByKindOrThrow(SyntaxKind.AwaitExpression).getExpression();
  if (!Node.isCallExpression(awaited) && !Node.isTaggedTemplateExpression(awaited)) throw new Error('not a call');
  return awaited;
}

describe('isDbWrite', () => {
  it.each([
    "supabase.from('users').insert(body)",
    "supabase.from('users').update({ name }).eq('id', id)",
    "supabase.from('users').upsert(rows)",
    "supabase.from('users').delete().eq('id', id)",
    'prisma.user.create({ data })',
    'prisma.user.updateMany({ where, data })',
    'prisma.post.deleteMany({ where })',
    'db.user.upsert({ where, create, update })',
    "pool.query('INSERT INTO users (email) VALUES ($1)', [email])",
    'pool.query(`update users set name = $1`, [name])',
    "client.execute('  DELETE FROM sessions WHERE id = ?', [id])",
    'sql`delete from sessions where id = ${id}`',
    'orders.insertOne(doc)',
    'orders.updateMany(filter, update)',
  ])('%s is a write', (expr) => {
    expect(isDbWrite(outerCall(expr))).toBe(true);
  });

  it.each([
    "supabase.from('users').select('*').eq('id', id)",
    'prisma.user.findMany()',
    "pool.query('select * from users where id = $1', [id])",
    'sql`select 1`',
    'orders.find(filter).toArray()',
    "fetch('https://example.com', { method: 'POST' })",
    'list.push(item)',
  ])('%s is not a write', (expr) => {
    expect(isDbWrite(outerCall(expr))).toBe(false);
  });
});

describe('supabaseTable', () => {
  it('reads the table name from .from() in the chain', () => {
    expect(supabaseTable(outerCall("supabase.from('profiles').update({ a: 1 }).eq('id', id)"))).toBe('profiles');
    expect(supabaseTable(outerCall('prisma.user.create({ data })'))).toBeUndefined();
  });
});

describe('touchesData', () => {
  function data(...body: string[]) {
    const sf = memoryContext({ 'lib/a.ts': code('async function f() {', ...body, '}') }).getSourceFile('lib/a.ts');
    return touchesData(sf.getFunctionOrThrow('f'));
  }

  it('detects database, filesystem and network access', () => {
    expect(data("await supabase.from('posts').select('*')")).toMatchObject({ db: true, fs: false, fetch: false, write: false });
    expect(data("await supabase.from('posts').insert({ a: 1 })")).toMatchObject({ db: true, write: true });
    expect(data("await readFile('/tmp/x')")).toMatchObject({ fs: true });
    expect(data("await fs.promises.writeFile('/tmp/x', 'a')")).toMatchObject({ fs: true });
    expect(data("await fetch('https://example.com')")).toMatchObject({ fetch: true });
    expect(data("await axios.get('https://example.com')")).toMatchObject({ fetch: true });
  });

  it('reports nothing for pure computation', () => {
    expect(data('const a = [1, 2].map((n) => n * 2)', 'return a')).toEqual({ db: false, fs: false, fetch: false, write: false });
  });
});
