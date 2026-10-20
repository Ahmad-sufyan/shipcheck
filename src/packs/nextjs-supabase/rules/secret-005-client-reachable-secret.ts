import { Node } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { findingAt, stringLiteral } from '../analysis/ast-utils.js';
import { clientReachableModules } from '../analysis/import-graph.js';
import { findSecrets, isPlaceholder, maskSpan, SECRET_ENV_NAME } from '../analysis/secret-patterns.js';

const SERVER_ONLY_IMPORT = /^\s*import\s+['"]server-only['"]/m;
const SECRET_ENV = new RegExp(`${SECRET_ENV_NAME.source}|DATABASE_URL|_DSN$`, 'i');
/** How much minified context to keep around a secret found in a bundle. */
const BUNDLE_CONTEXT = 40;

/** Env var name for `process.env.X` or `process.env['X']`. */
function envName(node: Node): string | undefined {
  if (Node.isPropertyAccessExpression(node) && node.getExpression().getText() === 'process.env') return node.getName();
  if (Node.isElementAccessExpression(node) && node.getExpression().getText() === 'process.env') return stringLiteral(node.getArgumentExpression());
  return undefined;
}

/** Secret literals line by line, masked. */
function literalFindings(text: string, file: string, explain: (name: string) => string): RawFinding[] {
  const findings: RawFinding[] = [];
  text.split(/\r?\n/).forEach((line, index) => {
    const secret = findSecrets(line).find((match) => !isPlaceholder(match.value));
    if (!secret) return;
    const from = Math.max(0, secret.index - BUNDLE_CONTEXT);
    const to = Math.min(line.length, secret.index + secret.value.length + BUNDLE_CONTEXT);
    const evidence = maskSpan(line.slice(from, to), secret.index - from, secret.index - from + secret.value.length).trim();
    findings.push({ file, line: index + 1, column: secret.index + 1, evidence, confidence: 'high', explanation: explain(secret.name) });
  });
  return findings;
}

export const secret005: Rule = {
  id: 'SECRET-005',
  title: 'Server secret reachable from client code',
  category: 'secrets',
  severity: 'critical',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    "Follows imports from every 'use client' file (relative and tsconfig-path imports) and reports, in each imported " +
    "module without `import 'server-only'`: secret literals (critical) and reads of non-public secret env vars such as " +
    'STRIPE_SECRET_KEY (medium). Also reports secrets found in .next/static bundles from a local build (critical). The ' +
    "client entry files themselves are left to SECRET-004, AUTHZ-007 and INTEG-004. Limitations: tree shaking is not " +
    'modelled, so an import that the bundler drops is still followed.',
  explanation:
    'Every module a client component imports is bundled for the browser. A secret written in such a module is downloadable ' +
    'by any visitor, and server-only logic that reads secrets ends up in the browser too.',
  fix:
    "Add `import 'server-only'` to modules that use secrets so the build fails when client code imports them, move the " +
    'shared non-secret parts (types, constants) into their own module, and call the secret-using code from a route ' +
    'handler or server action instead.',
  falsePositiveNote: 'Imports that are tree-shaken out of the client bundle are still followed; check the built bundle if unsure.',
  cwe: 'CWE-200',
  references: ['https://nextjs.org/docs/app/getting-started/server-and-client-components#preventing-environment-poisoning'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const [file, chain] of clientReachableModules(ctx)) {
      if (chain.length < 2 || ctx.next.isClientFile(file)) continue;
      const text = ctx.readText(file);
      if (SERVER_ONLY_IMPORT.test(text)) continue;
      const path = chain.join(' → ');
      const literals = literalFindings(text, file, (name) => `A ${name} is written in ${file}, which client code imports (${path}), so it ships in the browser bundle.`);
      findings.push(...literals);
      const reported = new Set(literals.map((f) => f.line));
      ctx.getSourceFile(file).forEachDescendant((node) => {
        const name = envName(node);
        if (!name || name.startsWith('NEXT_PUBLIC_') || !SECRET_ENV.test(name)) return;
        const finding = findingAt(node, {
          severity: 'medium',
          confidence: 'medium',
          explanation:
            `${name} is read in ${file}, which client code imports (${path}). Next.js replaces non-NEXT_PUBLIC_ variables with ` +
            'undefined in browser bundles, so the value does not leak today, but the server logic ships to the browser and ' +
            'renaming the variable to NEXT_PUBLIC_ to "fix" it would publish the secret.',
        });
        if (!reported.has(finding.line!)) findings.push(finding);
        reported.add(finding.line!);
      });
    }
    for (const file of ctx.nextStaticFiles) {
      findings.push(...literalFindings(ctx.readText(file), file, (name) => `A ${name} is in the built browser bundle ${file}; every visitor can download it.`));
    }
    return findings;
  },
};
