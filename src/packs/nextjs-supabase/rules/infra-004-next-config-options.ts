import { Node, SyntaxKind, type ObjectLiteralExpression } from 'ts-morph';
import { staticPropertyName } from '../../../context/ast.js';
import type { RawFinding, Rule } from '../../../types.js';
import { findingAt, stringLiteral } from '../analysis/ast-utils.js';

/** Only wildcards and dots: matches any host or any single label. */
const ANY_HOST = /^[*.]+$/;

function property(object: ObjectLiteralExpression, name: string): Node | undefined {
  return object.getProperties().find((p) => Node.isPropertyAssignment(p) && staticPropertyName(p.getNameNode()) === name);
}

/** The hostname of a remotePatterns entry: `{ hostname: '...' }` or `new URL('https://host/path')`. */
function patternHostname(element: Node): { node: Node; hostname: string } | undefined {
  if (Node.isObjectLiteralExpression(element)) {
    const assignment = property(element, 'hostname');
    const value = assignment && Node.isPropertyAssignment(assignment) ? stringLiteral(assignment.getInitializer()) : undefined;
    return assignment && value !== undefined ? { node: assignment, hostname: value } : undefined;
  }
  if (Node.isNewExpression(element) && element.getExpression().getText() === 'URL') {
    const url = stringLiteral(element.getArguments()[0]);
    const hostname = url ? /^[a-z][a-z0-9+.-]*:\/\/([^/:?#]+)/i.exec(url)?.[1] : undefined;
    return hostname ? { node: element, hostname } : undefined;
  }
  return undefined;
}

export const infra004: Rule = {
  id: 'INFRA-004',
  title: 'Risky next.config options',
  category: 'infra',
  severity: 'medium',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports, in next.config: images.remotePatterns entries whose hostname is a wildcard ("**" or "*" matches any host; ' +
    '"*.example.com" any subdomain, with low confidence), images.dangerouslyAllowSVG: true without ' +
    'images.contentSecurityPolicy, and experimental.serverActions.allowedOrigins entries that match any origin ("*"). ' +
    'The file is parsed, never executed.',
  explanation:
    'A wildcard remote pattern turns the image optimizer into an open proxy that fetches and caches anything on your bill; ' +
    'SVGs without a CSP can run scripts on your origin; a wildcard allowedOrigins switches off the CSRF origin check for ' +
    'Server Actions.',
  fix:
    'List exact hostnames in images.remotePatterns, set images.contentSecurityPolicy to "default-src \'self\'; script-src ' +
    '\'none\'; sandbox;" (with contentDispositionType "attachment") when SVGs are allowed, and list only your own proxy ' +
    'hosts in serverActions.allowedOrigins.',
  falsePositiveNote: 'A wildcard subdomain of a CDN you control can be acceptable; narrow it if the CDN hosts other customers.',
  cwe: 'CWE-918',
  references: [
    'https://nextjs.org/docs/app/api-reference/components/image#remotepatterns',
    'https://nextjs.org/docs/app/api-reference/components/image#dangerouslyallowsvg',
    'https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions#allowedorigins',
  ],
  run(ctx) {
    if (!ctx.nextConfig) return [];
    const findings: RawFinding[] = [];
    for (const assignment of ctx.getSourceFile(ctx.nextConfig.file).getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
      const name = staticPropertyName(assignment.getNameNode());
      const value = assignment.getInitializer();
      if (!value) continue;
      if (name === 'remotePatterns' && Node.isArrayLiteralExpression(value)) {
        for (const element of value.getElements()) {
          const pattern = patternHostname(element);
          if (!pattern?.hostname.includes('*')) continue;
          const anyHost = ANY_HOST.test(pattern.hostname);
          findings.push(
            findingAt(pattern.node, {
              ...(anyHost ? {} : { confidence: 'low' as const }),
              explanation: anyHost
                ? `remotePatterns hostname "${pattern.hostname}" matches any host, so the image optimizer fetches and serves images from anywhere.`
                : `remotePatterns hostname "${pattern.hostname}" matches every subdomain, including ones other people may control.`,
            }),
          );
        }
      } else if (name === 'dangerouslyAllowSVG' && value.getKind() === SyntaxKind.TrueKeyword) {
        const images = assignment.getParent();
        if (Node.isObjectLiteralExpression(images) && !property(images, 'contentSecurityPolicy')) {
          findings.push(findingAt(assignment, { explanation: 'SVG images are served by the image optimizer without images.contentSecurityPolicy, so a malicious SVG can run scripts on your origin.' }));
        }
      } else if (name === 'allowedOrigins' && Node.isArrayLiteralExpression(value)) {
        for (const element of value.getElements()) {
          const origin = stringLiteral(element);
          if (origin !== undefined && ANY_HOST.test(origin)) {
            findings.push(findingAt(element, { explanation: `serverActions.allowedOrigins entry "${origin}" accepts Server Action requests from any origin, which disables their CSRF protection.` }));
          }
        }
      }
    }
    return findings;
  },
};
