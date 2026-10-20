import { Node, SyntaxKind } from 'ts-morph';
import type { RawFinding, Rule, ScanContext } from '../../../types.js';
import { declarationOf, findingAt, relativeFile, sourceFiles, staticText } from '../analysis/ast-utils.js';
import { hasAuthCheck } from '../analysis/auth-check.js';
import { entries, MUTATING_METHODS, type Entry } from '../analysis/entries.js';
import { resolveImport } from '../analysis/import-graph.js';
import { routeRegex } from '../analysis/route-match.js';

const BOT_PROTECTION = /turnstile|cf-turnstile|hcaptcha|h-captcha|recaptcha|grecaptcha|friendlycaptcha|altcha/i;

/** The handler a form submits to: a literal /api path (mutating route) or a server action passed as action={fn}. */
function formTarget(ctx: ScanContext, form: Node, routes: Entry[], actions: Entry[]): Entry | undefined {
  const opening = Node.isJsxElement(form) ? form.getOpeningElement() : form;
  if (!Node.isJsxOpeningElement(opening) && !Node.isJsxSelfClosingElement(opening)) return undefined;
  const attribute = opening.getAttribute('action');
  if (!attribute || !Node.isJsxAttribute(attribute)) return undefined;
  const initializer = attribute.getInitializer();
  const literal = initializer && (Node.isStringLiteral(initializer) ? initializer.getLiteralValue() : Node.isJsxExpression(initializer) ? staticText(initializer.getExpression()) : undefined);
  if (literal?.startsWith('/api/')) {
    const path = literal.split(/[?#]/)[0]!;
    return routes.find((route) => routeRegex(route.routePath!).test(path) && MUTATING_METHODS.has(route.method ?? ''));
  }
  const expression = initializer && Node.isJsxExpression(initializer) ? initializer.getExpression() : undefined;
  if (!expression || !Node.isIdentifier(expression)) return undefined;
  const name = expression.getText();
  for (const declaration of form.getSourceFile().getImportDeclarations()) {
    const specifier = declaration.getNamedImports().find((s) => (s.getAliasNode()?.getText() ?? s.getName()) === name);
    if (!specifier) continue;
    const file = resolveImport(ctx, relativeFile(form), declaration.getModuleSpecifierValue());
    return actions.find((action) => action.file === file && action.name === specifier.getName());
  }
  return declarationOf(expression) ? actions.find((action) => action.file === relativeFile(form) && action.name === name) : undefined;
}

export const rate005: Rule = {
  id: 'RATE-005',
  title: 'Public form without bot protection',
  category: 'rate-limiting',
  severity: 'low',
  confidence: 'medium',
  advisory: true,
  stacks: ['nextjs-app-router'],
  description:
    'Reports <form> elements that submit to a public mutating route handler (a literal /api action) or to a server action ' +
    'without an auth check, when the project contains no Turnstile, hCaptcha or reCAPTCHA at all. Advisory: low-traffic ' +
    'forms may not need it.',
  explanation:
    'Anyone, including bots, can submit this form as often as they like, which invites spam submissions and abuse of ' +
    'whatever the form triggers (emails, database rows).',
  fix: 'Add Cloudflare Turnstile (or hCaptcha / reCAPTCHA) to the form and verify the token server-side with the siteverify API before acting.',
  falsePositiveNote: 'Low-traffic or internal forms may not need bot protection; a rate limiter alone may be enough.',
  cwe: 'CWE-799',
  references: ['https://developers.cloudflare.com/turnstile/get-started/'],
  run(ctx) {
    if (sourceFiles(ctx).some((file) => BOT_PROTECTION.test(ctx.readText(file)))) return [];
    const all = entries(ctx);
    const routes = all.filter((e) => e.kind === 'route' && e.routePath);
    const actions = all.filter((e) => e.kind === 'action');
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => text.includes('<form'))) {
      const sourceFile = ctx.getSourceFile(file);
      const forms = [...sourceFile.getDescendantsOfKind(SyntaxKind.JsxElement), ...sourceFile.getDescendantsOfKind(SyntaxKind.JsxSelfClosingElement)].filter((element) => {
        const tag = Node.isJsxElement(element) ? element.getOpeningElement().getTagNameNode().getText() : element.getTagNameNode().getText();
        return tag === 'form';
      });
      for (const form of forms) {
        const target = formTarget(ctx, form, routes, actions);
        if (target && !hasAuthCheck(target.node, ctx)) findings.push(findingAt(form));
      }
    }
    return findings;
  },
};
