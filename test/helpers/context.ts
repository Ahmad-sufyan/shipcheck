import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterAll } from 'vitest';
import { createContext } from '../../src/context/build-context.js';
import { createMemorySource } from '../../src/context/files.js';
import { ShipcheckConfigSchema } from '../../src/schema.js';
import type { ScanContext, ShipcheckConfig } from '../../src/types.js';

/** A full ScanContext built from an in-memory file map; nothing touches the disk. */
export function memoryContext(files: Record<string, string>, config: Partial<ShipcheckConfig> = {}): ScanContext {
  return createContext(createMemorySource(files), ShipcheckConfigSchema.parse(config)).ctx;
}

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
