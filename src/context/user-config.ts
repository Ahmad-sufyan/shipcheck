import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { ShipcheckError } from '../core/errors.js';
import { ShipcheckConfigSchema } from '../schema.js';
import type { ShipcheckConfig } from '../types.js';

export const CONFIG_FILE_NAME = 'shipcheck.config.json';

/**
 * Loads shipcheck.config.json from the scan root, or `explicitPath` when given. A missing default
 * file means defaults; a missing explicit file, invalid JSON or a schema violation is an error.
 */
export function loadUserConfig(root: string, explicitPath?: string): { config: ShipcheckConfig; file: string | null } {
  const file = explicitPath ? resolve(explicitPath) : join(root, CONFIG_FILE_NAME);
  if (!existsSync(file)) {
    if (explicitPath) throw new ShipcheckError(`Config file not found: ${explicitPath}`);
    return { config: ShipcheckConfigSchema.parse({}), file: null };
  }

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, 'utf8').replace(/^﻿/, ''));
  } catch (error) {
    throw new ShipcheckError(`${file} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }

  const parsed = ShipcheckConfigSchema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((issue) => `  - ${issue.path.map(String).join('.') || '(root)'}: ${issue.message}`);
    throw new ShipcheckError(`Invalid config in ${file}:\n${issues.join('\n')}`);
  }
  return { config: parsed.data, file };
}
