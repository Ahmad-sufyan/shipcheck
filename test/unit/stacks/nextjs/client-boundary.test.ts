import { describe, expect, it } from 'vitest';
import { isClientFile } from '../../../../src/stacks/nextjs/client-boundary.js';
import { memoryContext } from '../../../helpers/context.js';

describe('isClientFile', () => {
  const ctx = memoryContext({
    'components/a.tsx': "'use client'\nexport function A() {}",
    'components/b.tsx': '/** docs */\n"use client";\nexport function B() {}',
    'components/c.tsx': "import x from 'y'\n'use client'\n",
    'components/d.tsx': "export const label = 'use client'",
    'app/page.tsx': 'export default function Page() {}',
    'styles/site.css': "'use client'",
  });

  it.each([
    ['components/a.tsx', true],
    ['components/b.tsx', true],
    ['components/c.tsx', false],
    ['components/d.tsx', false],
    ['app/page.tsx', false],
    ['styles/site.css', false],
    ['missing.tsx', false],
  ])('%s -> %s', (file, expected) => {
    expect(isClientFile(ctx, file)).toBe(expected);
  });
});
