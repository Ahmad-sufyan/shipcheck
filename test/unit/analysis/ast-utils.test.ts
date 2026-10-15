import { SyntaxKind } from 'ts-morph';
import { describe, expect, it } from 'vitest';
import { calleeText, findingAt, numericValue, resolveExpression, sourceFiles } from '../../../src/packs/nextjs-supabase/analysis/ast-utils.js';
import { code, memoryContext } from '../../helpers/memory-context.js';

describe('sourceFiles', () => {
  it('lists script files, skipping tests, declarations and non-script files', () => {
    const ctx = memoryContext({
      'app/page.tsx': 'x',
      'lib/a.ts': 'useThing()',
      'lib/a.test.ts': 'x',
      'lib/b.spec.js': 'x',
      'tests/e2e.ts': 'x',
      '__tests__/c.ts': 'x',
      'types/env.d.ts': 'x',
      'styles/site.css': 'x',
    });
    expect(sourceFiles(ctx)).toEqual(['app/page.tsx', 'lib/a.ts']);
    expect(sourceFiles(ctx, (text) => text.includes('useThing'))).toEqual(['lib/a.ts']);
  });
});

describe('expression helpers', () => {
  const sf = memoryContext({
    'lib/a.ts': code(
      'const DAY = 60 * 60 * 24',
      'const options = { maxAge: DAY * 30 + 1, label: "x" }',
      'async function f() {',
      '  await supabase.auth.getUser()',
      '  await (createClient()).from("t").select()',
      '}',
    ),
  }).getSourceFile('lib/a.ts');

  it('folds numeric constants through identifiers', () => {
    const maxAge = sf.getVariableDeclarationOrThrow('options').getInitializerOrThrow().getFirstDescendantByKindOrThrow(SyntaxKind.PropertyAssignment);
    expect(numericValue(maxAge.getInitializerOrThrow())).toBe(60 * 60 * 24 * 30 + 1);
  });

  it('resolves identifiers to their initializers', () => {
    const ref = sf.getDescendantsOfKind(SyntaxKind.Identifier).find((id) => id.getText() === 'DAY' && id.getParent()?.getKind() === SyntaxKind.BinaryExpression)!;
    expect(resolveExpression(ref).getText()).toBe('60 * 60 * 24');
  });

  it('normalises callee text', () => {
    const calls = sf.getFunctionOrThrow('f').getDescendantsOfKind(SyntaxKind.CallExpression).map(calleeText);
    expect(calls).toContain('supabase.auth.getUser');
    expect(calls).toContain('createClient().from("t").select');
  });

  it('builds a finding at a node with its source line as evidence', () => {
    const call = sf.getFunctionOrThrow('f').getFirstDescendantByKindOrThrow(SyntaxKind.CallExpression);
    expect(findingAt(call, { confidence: 'low' })).toEqual({ file: 'lib/a.ts', line: 4, evidence: 'await supabase.auth.getUser()', confidence: 'low' });
  });
});
