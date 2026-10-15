import { describe, expect, it } from 'vitest';
import { findServerActions } from '../../../../src/stacks/nextjs/server-actions.js';
import { memoryContext } from '../../../helpers/context.js';

function actions(files: Record<string, string>) {
  return findServerActions(memoryContext(files)).map((a) => `${a.file}:${a.node.getStartLineNumber()} ${a.name}`);
}

describe('findServerActions', () => {
  it("finds exported async functions in files starting with 'use server'", () => {
    expect(
      actions({
        'app/actions.ts': [
          '// server actions',
          "'use server'",
          "import { db } from '@/lib/db'",
          'export async function createPost(formData: FormData) {}',
          'export const deletePost = async (id: string) => {}',
          'export const archivePost = async function (id: string) {}',
          'export default async function () {}',
          'async function internalHelper() {}',
          'export function notAnAction() {}',
        ].join('\n'),
      }),
    ).toEqual([
      'app/actions.ts:4 createPost',
      'app/actions.ts:5 deletePost',
      'app/actions.ts:6 archivePost',
      'app/actions.ts:7 default',
    ]);
  });

  it("ignores 'use server' that is not the first statement", () => {
    expect(actions({ 'lib/x.ts': "import x from 'y'\n'use server'\nexport async function a() {}" })).toEqual([]);
  });

  it("finds inline functions whose body starts with 'use server'", () => {
    expect(
      actions({
        'app/posts/[id]/page.tsx': [
          'export default async function Page() {',
          '  async function updatePost(formData: FormData) {',
          "    'use server'",
          '    await save(formData)',
          '  }',
          '  const removePost = async () => {',
          '    "use server"',
          '  }',
          '  return <form action={async () => {',
          "    'use server'",
          '  }} />',
          '}',
        ].join('\n'),
      }),
    ).toEqual([
      'app/posts/[id]/page.tsx:2 updatePost',
      'app/posts/[id]/page.tsx:6 removePost',
      'app/posts/[id]/page.tsx:9 <inline@9>',
    ]);
  });

  it('does not treat a plain string statement later in the body as a directive', () => {
    expect(actions({ 'app/page.tsx': "export default async function P() {\n  await x()\n  'use server'\n}" })).toEqual([]);
  });

  it('returns results sorted by file and line', () => {
    expect(
      actions({
        'b/actions.ts': "'use server'\nexport async function b() {}",
        'a/actions.ts': "'use server'\nexport async function a() {}",
      }),
    ).toEqual(['a/actions.ts:2 a', 'b/actions.ts:2 b']);
  });
});
