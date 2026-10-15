import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterAll } from 'vitest';

export { memoryContext } from './memory-context.js';

const created: string[] = [];

afterAll(() => {
  while (created.length) rmSync(created.pop()!, { recursive: true, force: true });
});

/** Writes the file map to a fresh temp directory (removed after the test file) and returns its path. */
export function tmpProject(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'shipcheck-test-'));
  created.push(root);
  for (const [file, text] of Object.entries(files)) {
    const abs = join(root, file);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, text);
  }
  return root;
}
