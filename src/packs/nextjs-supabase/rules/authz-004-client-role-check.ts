import { SyntaxKind } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, findingAt, sourceFiles, staticText } from '../analysis/ast-utils.js';
import { isHttpCall } from '../analysis/db-write.js';
import { entries } from '../analysis/entries.js';
import { routeRegex } from '../analysis/route-match.js';

const ROLE_VALUE = /^(?:admin|superadmin|super_admin|owner|staff|moderator)$/i;
const ROLE_SUBJECT = /role|isAdmin|is_admin|admin/i;
const SERVER_ROLE_CHECK = /['"`](?:admin|superadmin|super_admin|owner|staff|moderator)['"`]|\brole\b|\bisAdmin\b|\bis_admin\b|\bpermissions?\b|\bauthorize\s*\(|\bcan\(/i;

export const authz004: Rule = {
  id: 'AUTHZ-004',
  title: 'Role check only on the client',
  category: 'authorization',
  severity: 'medium',
  confidence: 'low',
  stacks: ['nextjs-app-router'],
  description:
    "Reports 'use client' files that compare a role (role === 'admin', isAdmin) and fetch a literal /api path whose route " +
    'handler contains no role condition. Two findings are raised: the client comparison and the route handler. Limitations: ' +
    'role checks enforced only by RLS or in helpers in other modules are not recognised.',
  explanation:
    'The admin-only UI is hidden in the browser, but the API behind it lets any signed-in user call it directly and get the ' +
    'same data or perform the same actions.',
  fix: 'Check the role on the server in the route handler (from the database or app_metadata, never from the request) and return 403 for other users.',
  falsePositiveNote: 'If RLS policies already restrict the data to admins, the server is protected even without a check in the handler.',
  cwe: 'CWE-602',
  references: ['https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/'],
  run(ctx) {
    const findings: RawFinding[] = [];
    const routes = entries(ctx).filter((e) => e.kind === 'route' && e.routePath);
    for (const file of sourceFiles(ctx, (text) => /admin|role/i.test(text))) {
      if (!ctx.next.isClientFile(file)) continue;
      const sourceFile = ctx.getSourceFile(file);
      const comparisons = sourceFile.getDescendantsOfKind(SyntaxKind.BinaryExpression).filter((binary) => {
        if (!/^[!=]==?$/.test(binary.getOperatorToken().getText())) return false;
        const [left, right] = [binary.getLeft(), binary.getRight()];
        const value = staticText(right) ?? staticText(left);
        const subject = staticText(right) !== undefined ? left : right;
        return value !== undefined && ROLE_VALUE.test(value) && ROLE_SUBJECT.test(subject.getText());
      });
      if (!comparisons.length) continue;

      const apiPaths = sourceFile
        .getDescendantsOfKind(SyntaxKind.CallExpression)
        .filter((call) => isHttpCall(call) || calleeName(call) === 'fetch')
        .map((call) => staticText(call.getArguments()[0]))
        .filter((path): path is string => path !== undefined && path.startsWith('/api/'))
        .map((path) => path.split(/[?#]/)[0]!);
      const unprotected = routes.filter(
        (route) => apiPaths.some((path) => routeRegex(route.routePath!).test(path)) && !SERVER_ROLE_CHECK.test(route.node.getText()),
      );
      if (!unprotected.length) continue;

      for (const comparison of comparisons) findings.push(findingAt(comparison));
      for (const route of unprotected) findings.push(findingAt(route.node));
    }
    return findings;
  },
};

