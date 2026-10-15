import { detectStacks } from '../stacks/detect.js';
import { isClientFile } from '../stacks/nextjs/client-boundary.js';
import { findMiddleware } from '../stacks/nextjs/middleware.js';
import { findRouteHandlers } from '../stacks/nextjs/routes.js';
import { findServerActions } from '../stacks/nextjs/server-actions.js';
import type { ToolContext } from '../adapters/exec.js';
import type { ScanContext, ShipcheckConfig } from '../types.js';
import { createAstCache } from './ast.js';
import {
  collectSqlMigrations,
  detectLockfile,
  parseEnvFiles,
  readGitignore,
  readPackageJson,
  readVercelJson,
  readWranglerConfig,
  type Skipped,
} from './configs.js';
import { createDiskSource, listFiles, type ProjectSource } from './files.js';
import { readNextConfig } from './next-config.js';

export interface BuiltContext {
  ctx: ScanContext;
  /** Inputs that could not be read (invalid JSON, unresolvable next.config, ...). */
  skipped: Skipped[];
}

function once<T>(compute: () => T): () => T {
  let done = false;
  let value: T;
  return () => {
    if (!done) {
      value = compute();
      done = true;
    }
    return value;
  };
}

/** Lists files under `root` (honouring ignores) and builds the scan context from disk. */
export interface ContextOptions {
  tools?: ToolContext;
}

export async function buildContext(root: string, config: ShipcheckConfig, options: ContextOptions = {}): Promise<BuiltContext> {
  const files = await listFiles(root, config.ignorePaths);
  return createContext(createDiskSource(root, files), config, options);
}

export function createContext(source: ProjectSource, config: ShipcheckConfig, options: ContextOptions = {}): BuiltContext {
  const skipped: Skipped[] = [];
  const readText = (file: string) => source.readText(file);
  const getSourceFile = createAstCache(readText);
  const nextSource = { files: source.files, readText, getSourceFile };
  const packageJson = readPackageJson(source, skipped);
  const clientFiles = new Map<string, boolean>();

  const ctx: ScanContext = {
    root: source.root,
    stacks: detectStacks(source, packageJson),
    files: source.files,
    readText,
    getSourceFile,
    packageJson,
    lockfile: detectLockfile(source),
    envFiles: parseEnvFiles(source),
    sqlMigrations: collectSqlMigrations(source),
    nextConfig: readNextConfig(source, getSourceFile, skipped),
    vercelJson: readVercelJson(source, skipped),
    wranglerToml: readWranglerConfig(source, skipped),
    gitignore: readGitignore(source),
    next: {
      routeHandlers: once(() => findRouteHandlers(nextSource)),
      serverActions: once(() => findServerActions(nextSource)),
      middleware: once(() => findMiddleware(nextSource)),
      isClientFile(file) {
        let result = clientFiles.get(file);
        if (result === undefined) {
          result = isClientFile(nextSource, file);
          clientFiles.set(file, result);
        }
        return result;
      },
    },
    config,
    ...(options.tools ? { tools: options.tools } : {}),
    skip(check, reason) {
      skipped.push({ check, reason });
    },
  };
  return { ctx, skipped };
}
