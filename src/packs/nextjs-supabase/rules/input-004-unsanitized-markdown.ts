import { Node, SyntaxKind, type SourceFile } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, findingAt, objectProperty, receiverOf, sourceFiles } from '../analysis/ast-utils.js';
import { insideSanitizer } from '../analysis/sanitizers.js';

/** Local names bound by default or named imports from `module`. */
function importedNames(sourceFile: SourceFile, module: string): Set<string> {
  const names = new Set<string>();
  for (const declaration of sourceFile.getImportDeclarations()) {
    if (declaration.getModuleSpecifierValue() !== module) continue;
    const defaultImport = declaration.getDefaultImport();
    if (defaultImport) names.add(defaultImport.getText());
    for (const named of declaration.getNamedImports()) names.add(named.getAliasNode()?.getText() ?? named.getName());
  }
  return names;
}

function reactMarkdownFindings(sourceFile: SourceFile): RawFinding[] {
  const raw = importedNames(sourceFile, 'rehype-raw');
  if (!raw.size) return [];
  const sanitize = importedNames(sourceFile, 'rehype-sanitize');
  const findings: RawFinding[] = [];
  for (const attribute of sourceFile.getDescendantsOfKind(SyntaxKind.JsxAttribute)) {
    if (attribute.getNameNode().getText() !== 'rehypePlugins') continue;
    const plugins = attribute.getInitializer()?.getText() ?? '';
    const uses = (names: Set<string>) => [...names].some((name) => new RegExp(`\\b${name}\\b`).test(plugins));
    if (uses(raw) && !uses(sanitize)) findings.push(findingAt(attribute.getFirstAncestor((a) => Node.isJsxOpeningElement(a) || Node.isJsxSelfClosingElement(a)) ?? attribute));
  }
  return findings;
}

/** markdown-it instances created with `html: true` whose render output reaches innerHTML/__html unsanitised. */
function markdownItFindings(sourceFile: SourceFile): RawFinding[] {
  const constructors = importedNames(sourceFile, 'markdown-it');
  if (!constructors.size) return [];
  const findings: RawFinding[] = [];
  for (const declaration of sourceFile.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const init = declaration.getInitializer();
    if (!init || !(Node.isNewExpression(init) || Node.isCallExpression(init)) || !constructors.has(init.getExpression().getText())) continue;
    const htmlOption = objectProperty(init.getArguments()[0], 'html');
    if (!htmlOption || htmlOption.getText() !== 'true') continue;
    const instance = declaration.getName();
    const leaks = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression).some((call) => {
      const receiver = receiverOf(call);
      if (calleeName(call) !== 'render' || receiver?.getText() !== instance || insideSanitizer(call)) return false;
      const statement = call.getFirstAncestor((a) => Node.isStatement(a));
      return /innerHTML|__html/.test(statement?.getText() ?? '');
    });
    if (leaks) findings.push(findingAt(htmlOption));
  }
  return findings;
}

export const input004: Rule = {
  id: 'INPUT-004',
  title: 'Unsanitized markdown/HTML rendering',
  category: 'input-validation',
  severity: 'medium',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports react-markdown configured with rehype-raw (which lets raw HTML through) without rehype-sanitize, and markdown-it ' +
    'instances created with html: true whose output is written to innerHTML or __html without a sanitizer. Limitations: ' +
    'plugin lists built in other modules are not followed; marked is not checked.',
  explanation:
    'Markdown that may contain raw HTML is rendered without sanitising, so a user who can write markdown (comments, posts, ' +
    'profiles) can inject script into other visitors’ pages.',
  fix: 'Add rehype-sanitize after rehype-raw (`rehypePlugins={[rehypeRaw, rehypeSanitize]}`), or drop raw HTML support.',
  falsePositiveNote: 'Markdown written only by trusted authors (your own docs) is lower risk; sanitizing still protects against compromised content.',
  cwe: 'CWE-79',
  references: ['https://github.com/rehypejs/rehype-sanitize', 'https://github.com/remarkjs/react-markdown#appendix-a-html-in-markdown'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => text.includes('rehype-raw') || text.includes('markdown-it'))) {
      const sourceFile = ctx.getSourceFile(file);
      findings.push(...reactMarkdownFindings(sourceFile), ...markdownItFindings(sourceFile));
    }
    return findings;
  },
};
