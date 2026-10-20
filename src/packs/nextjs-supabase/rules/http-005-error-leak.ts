import { Node, SyntaxKind, type CatchClause } from 'ts-morph';
import { hasDirective, unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeText, findingAt, sourceFiles } from '../analysis/ast-utils.js';

const RESPONSE_CALL = /^(?:NextResponse|Response)\.json$/;
const RESPONSE_CLASS = /^(?:NextResponse|Response)$/;
const DETAIL = /^(?:message|stack|cause|details)$/;
const EXPECTED_ERROR = /ZodError|ValidationError|instanceof\s+z\.|\.name\s*===\s*['"`]ZodError/;

/** Whether `node` exposes the caught error: err.message/.stack, String(err), JSON.stringify(err), `${err}` or err itself. */
function exposes(node: Node, name: string): boolean {
  const isError = (n: Node) => {
    const inner = unwrapExpression(n);
    return Node.isIdentifier(inner) && inner.getText() === name;
  };
  if (isError(node)) return true;
  return [node, ...node.getDescendants()].some((d) => {
    if (Node.isPropertyAccessExpression(d)) return DETAIL.test(d.getName()) && isError(d.getExpression());
    if (Node.isCallExpression(d)) return /^(?:String|JSON\.stringify)$/.test(calleeText(d)) && d.getArguments().some(isError);
    if (Node.isTemplateSpan(d)) return isError(d.getExpression());
    if (Node.isPropertyAssignment(d)) return d.getInitializer() !== undefined && isError(d.getInitializer()!);
    if (Node.isShorthandPropertyAssignment(d)) return d.getName() === name;
    return false;
  });
}

/** Inside an `if (err instanceof ZodError)`-style branch of the catch block. */
function expectedErrorBranch(node: Node, clause: CatchClause): boolean {
  for (let current = node.getParent(); current && current !== clause; current = current.getParent()) {
    if (Node.isIfStatement(current) && EXPECTED_ERROR.test(current.getExpression().getText())) return true;
  }
  return false;
}

export const http005: Rule = {
  id: 'HTTP-005',
  title: 'Error details leaked to the client',
  category: 'http-config',
  severity: 'medium',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports catch blocks that put the caught error into a response: err.message, err.stack, String(err), ' +
    'JSON.stringify(err), a template with the error, or the error object itself, passed to NextResponse.json, ' +
    'Response.json or new Response, or returned from a server action. Branches that handle ZodError or other validation ' +
    'errors are skipped.',
  explanation:
    'Internal error messages and stack traces reveal table names, query fragments, file paths and library versions, ' +
    'which help attackers map and exploit the system.',
  fix: 'Log the error on the server and return a generic message with a request id, for example `{ error: \'Something went wrong\', requestId }`.',
  falsePositiveNote: 'Errors you create yourself with user-safe messages (known business errors) are fine to return but are still reported.',
  cwe: 'CWE-209',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => text.includes('catch'))) {
      const sourceFile = ctx.getSourceFile(file);
      const serverActions = hasDirective(sourceFile, 'use server');
      for (const clause of sourceFile.getDescendantsOfKind(SyntaxKind.CatchClause)) {
        const name = clause.getVariableDeclaration()?.getName();
        if (!name) continue;
        const block = clause.getBlock();
        const responses: Node[] = [
          ...block.getDescendantsOfKind(SyntaxKind.CallExpression).filter((call) => RESPONSE_CALL.test(calleeText(call))),
          ...block.getDescendantsOfKind(SyntaxKind.NewExpression).filter((expression) => RESPONSE_CLASS.test(expression.getExpression().getText())),
          ...(serverActions ? block.getDescendantsOfKind(SyntaxKind.ReturnStatement).flatMap((r) => r.getExpression() ?? []) : []),
        ];
        for (const response of responses) {
          const payload = Node.isCallExpression(response) || Node.isNewExpression(response) ? (response.getArguments()[0] ?? response) : response;
          if (!exposes(payload, name) || expectedErrorBranch(response, clause)) continue;
          findings.push(findingAt(response.getFirstAncestor((a) => Node.isStatement(a)) ?? response));
        }
      }
    }
    return findings;
  },
};
