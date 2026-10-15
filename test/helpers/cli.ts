import { fileURLToPath } from 'node:url';
import { execa } from 'execa';

export const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

/** Runs `shipcheck <args>` from source through tsx, from the repo root, without throwing on non-zero exits. */
export function shipcheck(args: string[], env: Record<string, string | undefined> = {}) {
  return execa(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], {
    cwd: REPO_ROOT,
    reject: false,
    env: { NO_COLOR: undefined, FORCE_COLOR: undefined, ...env },
    extendEnv: true,
  });
}
