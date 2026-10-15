import { Node, SyntaxKind, type CallExpression, type SourceFile } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeNameNode, findingAt, objectProperty, sourceFiles, staticText } from '../analysis/ast-utils.js';
import { entryFunctionOf, isUserInput } from '../analysis/taint.js';

const CHILD_PROCESS = new Set(['child_process', 'node:child_process']);
const SHELL_COMMANDS = new Set(['exec', 'execSync']);
const ARGV_COMMANDS = new Set(['spawn', 'spawnSync', 'execFile', 'execFileSync']);

interface Bindings {
  /** Local function name -> child_process export name (exec, spawn, ...), including promisify(exec) aliases. */
  functions: Map<string, string>;
  /** Local names bound to the whole module (`import * as cp`, `require('child_process')`). */
  modules: Set<string>;
}

function childProcessBindings(sourceFile: SourceFile): Bindings {
  const functions = new Map<string, string>();
  const modules = new Set<string>();
  for (const declaration of sourceFile.getImportDeclarations()) {
    if (!CHILD_PROCESS.has(declaration.getModuleSpecifierValue())) continue;
    const namespace = declaration.getNamespaceImport() ?? declaration.getDefaultImport();
    if (namespace) modules.add(namespace.getText());
    for (const named of declaration.getNamedImports()) functions.set(named.getAliasNode()?.getText() ?? named.getName(), named.getName());
  }
  for (const variable of sourceFile.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const init = variable.getInitializer();
    if (!init || !Node.isCallExpression(init)) continue;
    const callee = init.getExpression().getText();
    const [arg] = init.getArguments();
    if (callee === 'require' && CHILD_PROCESS.has(staticText(arg) ?? '')) {
      const name = variable.getNameNode();
      if (Node.isIdentifier(name)) modules.add(name.getText());
      else if (Node.isObjectBindingPattern(name)) for (const element of name.getElements()) functions.set(element.getName(), element.getPropertyNameNode()?.getText() ?? element.getName());
    }
    if ((callee === 'promisify' || callee === 'util.promisify') && arg) {
      const original = functions.get(arg.getText()) ?? (Node.isPropertyAccessExpression(arg) && modules.has(arg.getExpression().getText()) ? arg.getName() : undefined);
      if (original) functions.set(variable.getName(), original);
    }
  }
  return { functions, modules };
}

function childProcessFunction(call: CallExpression, bindings: Bindings): string | undefined {
  const callee = unwrapExpression(call.getExpression());
  if (Node.isIdentifier(callee)) return bindings.functions.get(callee.getText());
  if (Node.isPropertyAccessExpression(callee) && bindings.modules.has(callee.getExpression().getText())) return callee.getName();
  return undefined;
}

function isLiteral(node: Node | undefined): boolean {
  return node === undefined || staticText(node) !== undefined && !Node.isTemplateExpression(unwrapExpression(node));
}

export const input005: Rule = {
  id: 'INPUT-005',
  title: 'Command injection',
  category: 'input-validation',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports child_process exec/execSync (including promisified aliases) called with a non-literal command, and ' +
    'spawn/execFile with shell: true and non-literal arguments. Commands that include request data are critical; other ' +
    'dynamic commands are high. Constant commands and execFile/spawn with an argument array and no shell are not reported.',
  explanation:
    'A shell command is assembled at runtime. If any part of it comes from a request, an attacker can append their own ' +
    'commands and run them on your server.',
  fix:
    "Use execFile or spawn with an argument array and no shell (`execFile('convert', [input, output])`), and validate inputs " +
    'against an allowlist.',
  falsePositiveNote: 'Dynamic commands built only from trusted configuration are reported as high; review and switch to execFile.',
  cwe: 'CWE-78',
  references: ['https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback', 'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => text.includes('child_process'))) {
      const sourceFile = ctx.getSourceFile(file);
      const bindings = childProcessBindings(sourceFile);
      for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        const fnName = childProcessFunction(call, bindings);
        if (!fnName) continue;
        const args = call.getArguments();
        let dynamic: Node[] = [];
        if (SHELL_COMMANDS.has(fnName)) {
          if (!isLiteral(args[0])) dynamic = [args[0]!];
        } else if (ARGV_COMMANDS.has(fnName)) {
          const options = args.find((arg) => objectProperty(arg, 'shell') !== undefined);
          if (options && objectProperty(options, 'shell')?.getText() !== 'false') dynamic = args.filter((arg) => arg !== options && !isLiteral(arg));
        }
        if (!dynamic.length) continue;
        const fn = entryFunctionOf(call);
        const tainted = dynamic.some((arg) => isUserInput(arg, fn));
        findings.push(findingAt(calleeNameNode(call), tainted ? { severity: 'critical' } : {}));
      }
    }
    return findings;
  },
};
