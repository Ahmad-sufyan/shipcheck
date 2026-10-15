import { describe, expect, it } from 'vitest';
import { input005 as rule } from '../../../src/packs/nextjs-supabase/rules/input-005-command-injection.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/thumbnail/route.ts';
const get = (imports: string, ...body: string[]) =>
  code(imports, 'export async function GET(request: NextRequest) {', "  const image = request.nextUrl.searchParams.get('image') ?? ''", ...body.map((l) => `  ${l}`), '}');

describe('INPUT-005 Command injection', () => {
  it('reports exec with a request-controlled template as critical', async () => {
    const text = get("import { exec } from 'node:child_process'", 'exec(`convert ${image} out.png`, () => {})');
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([expect.objectContaining({ line: 4, severity: 'critical' })]);
  });

  it('reports a promisified exec and non-literal commands that are not tainted as high', async () => {
    const promisified = get("import { exec } from 'child_process'\nimport { promisify } from 'node:util'\nconst run = promisify(exec)", 'await run(`ls ${process.env.DIR}`)');
    const findings = await runRule(rule, { [ROUTE]: promisified });
    expect(findings).toEqual([expect.objectContaining({ line: 6 })]);
    expect(findings[0]?.severity).toBeUndefined();
  });

  it('reports spawn with shell: true and a tainted argument', async () => {
    const text = get("import * as cp from 'node:child_process'", "cp.spawn('convert', [image, 'out.png'], { shell: true })");
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([expect.objectContaining({ line: 4, severity: 'critical' })]);
  });

  it('ignores literal commands and execFile with an argument array', async () => {
    expect(await runRule(rule, { [ROUTE]: get("import { exec, execFile } from 'node:child_process'", "exec('ls -la', () => {})", "execFile('convert', [image, 'out.png'], () => {})") })).toEqual([]);
  });

  it('ignores RegExp.prototype.exec and unrelated exec functions', async () => {
    expect(await runRule(rule, { [ROUTE]: get('', '/^[a-z]+$/.exec(image)', 'db.exec(image)') })).toEqual([]);
  });
});
