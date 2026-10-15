import { Node, SyntaxKind } from 'ts-morph';
import { describe, expect, it } from 'vitest';
import { createAstCache, directivePrologue, hasDirective } from '../../../src/context/ast.js';

function cache(files: Record<string, string>) {
  return createAstCache((file) => {
    const text = files[file];
    if (text === undefined) throw new Error(`not found: ${file}`);
    return text;
  });
}

describe('createAstCache', () => {
  it('parses TS, TSX, JS and MJS from text and caches the result', () => {
    const get = cache({
      'a.ts': 'export const a: number = 1',
      'b.tsx': 'export default function B() { return <div /> }',
      'c.js': 'module.exports = { a: 1 }',
      'd.mjs': 'export default {}',
    });
    const a = get('a.ts');
    expect(a.getVariableDeclarationOrThrow('a').getStartLineNumber()).toBe(1);
    expect(get('a.ts')).toBe(a);
    expect(get('b.tsx').getDescendantsOfKind(SyntaxKind.JsxSelfClosingElement)).toHaveLength(1);
    expect(get('c.js').getStatements()).toHaveLength(1);
    expect(get('d.mjs').getExportAssignments()).toHaveLength(1);
  });

  it('tolerates syntax errors', () => {
    const get = cache({ 'broken.ts': 'export function x( {' });
    expect(() => get('broken.ts')).not.toThrow();
  });
});

describe('directivePrologue', () => {
  it('reads directives at the top of a file, after comments', () => {
    const get = cache({
      'a.tsx': "// comment\n/* block */\n'use client'\nimport x from 'y'\n",
      'b.ts': '"use strict";\n"use server";\nexport async function x() {}',
      'c.ts': "import x from 'y'\n'use client'\n",
    });
    expect(directivePrologue(get('a.tsx'))).toEqual(['use client']);
    expect(directivePrologue(get('b.ts'))).toEqual(['use strict', 'use server']);
    expect(hasDirective(get('b.ts'), 'use server')).toBe(true);
    expect(hasDirective(get('c.ts'), 'use client')).toBe(false);
  });

  it('reads directives at the top of a function body', () => {
    const get = cache({ 'a.ts': "async function save() {\n  'use server'\n  return 1\n}\n" });
    const fn = get('a.ts').getFunctionOrThrow('save');
    const body = fn.getBody();
    expect(body && Node.isBlock(body) && hasDirective(body, 'use server')).toBe(true);
  });
});
