import type { CallExpression } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeNameNode, calleeText, calls, findingAt, sourceFiles, type FunctionNode } from '../analysis/ast-utils.js';
import { isFsCall } from '../analysis/db-write.js';
import { entryFunctionOf, isUserInput } from '../analysis/taint.js';

const PATH_BUILDERS = /^(?:path\.)?(?:join|resolve)$/;

/** normalize/resolve + startsWith(base), or basename(), anywhere in the handler. */
function hasPathGuard(fn: FunctionNode | undefined): boolean {
  if (!fn) return false;
  const names = calls(fn).map(calleeName);
  return names.includes('basename') || (names.includes('startsWith') && names.some((n) => n === 'normalize' || n === 'resolve' || n === 'realpath'));
}

function isPathBuilder(call: CallExpression): boolean {
  return PATH_BUILDERS.test(calleeText(call)) && (calleeText(call).startsWith('path.') || ['join', 'resolve'].includes(calleeName(call)));
}

export const input006: Rule = {
  id: 'INPUT-006',
  title: 'Path traversal',
  category: 'input-validation',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports path.join/path.resolve calls with a request-controlled segment, and fs calls whose path is request-controlled, ' +
    'in functions that never resolve the path and check it with startsWith(base) and never use basename(). Limitations: ' +
    'guards in helper functions are not recognised; one finding per line.',
  explanation:
    'A file path is built from request data, so a value such as ../../.env lets the caller read or overwrite files outside ' +
    'the folder you intended.',
  fix:
    'Resolve the final path and verify it stays inside the base directory: `const target = path.resolve(base, name); if ' +
    '(!target.startsWith(base + path.sep)) return 400`, or reduce the input to `path.basename(name)`.',
  falsePositiveNote: 'A path validated by a helper in another file is still reported; the inline check is cheap to add.',
  cwe: 'CWE-22',
  references: ['https://owasp.org/www-community/attacks/Path_Traversal', 'https://nodejs.org/api/path.html#pathresolvepaths'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => /\bfs\b|readFile|writeFile|createReadStream|createWriteStream|path\./.test(text))) {
      const reported = new Set<number>();
      for (const call of calls(ctx.getSourceFile(file))) {
        const builder = isPathBuilder(call);
        if (!builder && !isFsCall(call)) continue;
        const fn = entryFunctionOf(call);
        const args = builder ? call.getArguments() : call.getArguments().slice(0, 1);
        if (!args.some((arg) => isUserInput(arg, fn)) || hasPathGuard(fn)) continue;
        const finding = findingAt(calleeNameNode(call));
        if (!reported.has(finding.line!)) findings.push(finding);
        reported.add(finding.line!);
      }
    }
    return findings;
  },
};
