import { Node, SyntaxKind } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeText, findingAt, objectProperty, resolveExpression, sourceFiles, staticText } from '../analysis/ast-utils.js';
import { isHtmlSanitizerCall } from '../analysis/sanitizers.js';

type Verdict = 'safe' | 'unsafe' | 'json';

function classify(value: Node, depth = 0): Verdict {
  const node = unwrapExpression(value);
  if (Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node)) return 'safe';
  if (Node.isTemplateExpression(node) && node.getTemplateSpans().every((span) => classify(span.getExpression(), depth) === 'safe')) return 'safe';
  if (Node.isCallExpression(node)) {
    if (isHtmlSanitizerCall(node)) return 'safe';
    if (calleeText(node) === 'JSON.stringify') return 'json';
    // JSON.stringify(x).replace(/</g, '\\u003c') is the escaping Next.js recommends for JSON-LD.
    if (calleeName(node) === 'replace' && /JSON\.stringify/.test(node.getText()) && /</.test(node.getArguments()[0]?.getText() ?? '')) return 'safe';
  }
  if (Node.isIdentifier(node) && depth < 3) {
    const resolved = resolveExpression(node, 1);
    if (resolved !== node) return classify(resolved, depth + 1);
  }
  return 'unsafe';
}

export const input003: Rule = {
  id: 'INPUT-003',
  title: 'XSS via dangerouslySetInnerHTML',
  category: 'input-validation',
  severity: 'high',
  confidence: 'medium',
  stacks: ['nextjs-app-router'],
  description:
    'Reports dangerouslySetInnerHTML whose __html value is not a string literal and is not wrapped in DOMPurify.sanitize, ' +
    'sanitize-html, xss() or a similar sanitizer (following local variables). JSON.stringify without the `<` escaping that ' +
    'Next.js recommends for JSON-LD is reported with low confidence. Limitations: sanitization done in another module is not ' +
    'recognised, and the rule cannot tell whether the HTML comes from a trusted source.',
  explanation:
    'HTML from a variable is inserted into the page as-is. If any part of it can come from a user, they can run script in ' +
    'other visitors’ browsers and act as them.',
  fix: 'Render text normally ({value}) or sanitize first: `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}`.',
  falsePositiveNote: 'HTML from a trusted CMS or produced by your own build is still reported; sanitizing is cheap insurance.',
  cwe: 'CWE-79',
  references: ['https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html', 'https://nextjs.org/docs/app/guides/json-ld'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => text.includes('dangerouslySetInnerHTML'))) {
      for (const attribute of ctx.getSourceFile(file).getDescendantsOfKind(SyntaxKind.JsxAttribute)) {
        if (attribute.getNameNode().getText() !== 'dangerouslySetInnerHTML') continue;
        const initializer = attribute.getInitializer();
        const expression = initializer && Node.isJsxExpression(initializer) ? initializer.getExpression() : undefined;
        const html = objectProperty(expression, '__html');
        if (!html || staticText(html) !== undefined && !Node.isTemplateExpression(unwrapExpression(html))) continue;
        const verdict = classify(html);
        if (verdict === 'unsafe') findings.push(findingAt(attribute));
        if (verdict === 'json') findings.push(findingAt(attribute, { confidence: 'low' }));
      }
    }
    return findings;
  },
};
