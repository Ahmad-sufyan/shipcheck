import { describe, expect, it } from 'vitest';
import { secret004 as rule } from '../../../src/packs/nextjs-supabase/rules/secret-004-hardcoded-secret.js';
import { fakeExec, recorded, toolContext } from '../../helpers/fake-exec.js';
import { FAKE } from '../../helpers/fake-secrets.js';
import { memoryContext } from '../../helpers/memory-context.js';

const STRIPE_FILE = `import Stripe from 'stripe'\n\n// billing\nexport const stripe = new Stripe('${FAKE.stripe}')\n`;
const ENV_LOCAL = `# a\n# b\nA=1\nB=2\n# c\nNEXT_PUBLIC_STRIPE_SECRET_KEY=${FAKE.stripe}\n`;
const files = { 'lib/stripe.ts': STRIPE_FILE, '.env.local': ENV_LOCAL };

async function run(contents: Record<string, string>, gitleaksStdout?: string) {
  const { exec, calls } = fakeExec((command) => (command === 'gitleaks' && gitleaksStdout !== undefined ? { exitCode: 1, stdout: gitleaksStdout } : 'missing'));
  const ctx = memoryContext(contents, {}, { tools: toolContext(exec) });
  const skipped: { check: string; reason: string }[] = [];
  ctx.skip = (check, reason) => skipped.push({ check, reason });
  return { findings: await rule.run(ctx), skipped, calls };
}

describe('SECRET-004 Hardcoded secret', () => {
  it('reports gitleaks findings with the secret masked, leaving env files to the env rules', async () => {
    const { findings, skipped, calls } = await run(files, recorded('gitleaks-dir.json'));
    expect(calls.map((c) => c.args[0])).toEqual(['dir']);
    expect(skipped).toEqual([]);
    expect(findings).toEqual([
      {
        file: 'lib/stripe.ts',
        line: 4,
        column: 35,
        evidence: "export const stripe = new Stripe('sk_t****')",
        explanation: expect.stringContaining('gitleaks rule stripe-access-token'),
        source: 'tool:gitleaks',
      },
    ]);
  });

  it('never shows more than 4 characters of a secret, even from an unredacted report', async () => {
    const { findings } = await run(files, recorded('gitleaks-dir-unredacted.json'));
    expect(findings).toHaveLength(1);
    expect(JSON.stringify(findings)).not.toContain(FAKE.stripe.slice(0, 5));
  });

  it('falls back to built-in patterns when gitleaks is missing, and records the skip', async () => {
    const { findings, skipped } = await run(files);
    expect(findings).toEqual([{ file: 'lib/stripe.ts', line: 4, column: 35, evidence: "export const stripe = new Stripe('sk_t****')", explanation: expect.stringContaining('Stripe'), source: 'static' }]);
    expect(skipped).toEqual([{ check: 'SECRET-004', reason: expect.stringMatching(/gitleaks is not installed.*built-in patterns/) }]);
  });

  it('always adds the Supabase patterns gitleaks does not have', async () => {
    const { findings } = await run({ 'lib/admin.ts': `export const key = "${FAKE.supabaseServiceJwt}"\nexport const k2 = "${FAKE.supabaseSecret}"` }, '[]');
    expect(findings.map((f) => `${f.line} ${f.source} ${f.evidence}`)).toEqual(['1 static export const key = "eyJh****"', '2 static export const k2 = "sb_s****"']);
  });

  it('does not report the same line twice', async () => {
    const report = JSON.stringify([{ RuleID: 'supabase', File: 'lib/admin.ts', StartLine: 1, EndLine: 1, StartColumn: 20, EndColumn: 30 }]);
    const { findings } = await run({ 'lib/admin.ts': `export const key = "${FAKE.supabaseServiceJwt}"` }, report);
    expect(findings).toHaveLength(1);
  });

  it('ignores placeholders, public keys and files outside the scan', async () => {
    const outside = JSON.stringify([{ RuleID: 'x', File: 'node_modules/pkg/index.js', StartLine: 1, EndLine: 1, StartColumn: 1, EndColumn: 5 }]);
    const { findings } = await run(
      {
        'lib/a.ts': "const key = 'sk_test_xxxxxxxxxxxxxxxxxxxx'",
        'lib/b.ts': `const anon = '${FAKE.supabaseAnonJwt}'; const pk = '${FAKE.stripePublishable}'`,
        'package-lock.json': `{"integrity": "${FAKE.stripe}"}`,
      },
      outside,
    );
    expect(findings).toEqual([]);
  });

  it('uses only the built-in patterns when tools are unavailable', async () => {
    const ctx = memoryContext(files);
    expect((await rule.run(ctx)).map((f) => f.file)).toEqual(['lib/stripe.ts']);
  });
});
