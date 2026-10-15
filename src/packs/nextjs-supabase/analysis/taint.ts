import { Node, SyntaxKind } from 'ts-morph';
import { hasDirective } from '../../../context/ast.js';
import { routePathFromFile } from '../../../stacks/nextjs/routes.js';
import {
  calleeName,
  calleeText,
  declarationOf,
  isExportedStatement,
  isFunctionNode,
  outermostFunction,
  receiverOf,
  relativeFile,
  topLevelStatement,
  type FunctionNode,
} from './ast-utils.js';

/** How many identifier-to-declaration steps the analysis follows before giving up. */
export const MAX_HOPS = 3;

export type EntryKind = 'route' | 'action';

const BODY_READERS = new Set(['json', 'formData', 'text']);
const REQUEST_NAME = /^(?:req|request)$/i;
const SOURCE_CONTAINERS = new Set(['searchParams', 'headers', 'cookies']);
/** Methods whose result still carries the receiver's data. */
const PROPAGATING_METHODS = new Set([
  'get',
  'getAll',
  'entries',
  'values',
  'keys',
  'trim',
  'trimStart',
  'trimEnd',
  'toLowerCase',
  'toUpperCase',
  'toLocaleLowerCase',
  'toLocaleUpperCase',
  'slice',
  'substring',
  'substr',
  'split',
  'replace',
  'replaceAll',
  'concat',
  'join',
  'toString',
  'normalize',
  'at',
  'padStart',
  'padEnd',
]);
/** Global functions that pass their (first) argument's data through. */
const PROPAGATING_FUNCTIONS = new Set(['String', 'decodeURIComponent', 'decodeURI', 'structuredClone', 'JSON.parse', 'Object.entries', 'Object.keys', 'Object.values', 'Object.fromEntries']);
const PROPAGATING_CONSTRUCTORS = new Set(['URL', 'URLSearchParams', 'String']);

export interface TaintOptions {
  /** Treat values checked with a regex .test() as validated (default true). */
  regexSanitizes?: boolean;
}

interface State {
  regexSanitizes: boolean;
  fn: FunctionNode | undefined;
  kind: EntryKind | undefined;
  hops: number;
  seen: ReadonlySet<Node>;
}

/** Whether `fn` is a route handler or a server action, whose inputs are attacker-controlled. */
export function entryKind(fn: FunctionNode | undefined): EntryKind | undefined {
  if (!fn) return undefined;
  const body = fn.getBody();
  if (body && Node.isBlock(body) && hasDirective(body, 'use server')) return 'action';
  if (outermostFunction(fn) !== fn) return undefined;
  const exported = isExportedStatement(topLevelStatement(fn));
  if (!exported) return undefined;
  if (hasDirective(fn.getSourceFile(), 'use server')) return 'action';
  if (routePathFromFile(relativeFile(fn)) !== null) return 'route';
  return undefined;
}

/**
 * Whether `node` evaluates to attacker-controlled data inside `fn`: request bodies, query strings,
 * route params, headers, cookies and server action arguments, followed through assignments,
 * destructuring, property and element access, templates, concatenation and await (max 3 hops).
 * Calls to anything but a few pass-through built-ins end the trail, so schema.parse() output,
 * safeParse().data and other helper results count as sanitized.
 */
export function isUserInput(node: Node, fn: FunctionNode | undefined, options: TaintOptions = {}): boolean {
  return tainted(node, { fn, kind: entryKind(fn), hops: 0, seen: new Set(), regexSanitizes: options.regexSanitizes ?? true });
}

function unwrap(input: Node): Node {
  let node = input;
  for (;;) {
    if (
      Node.isParenthesizedExpression(node) ||
      Node.isAsExpression(node) ||
      Node.isSatisfiesExpression(node) ||
      Node.isTypeAssertion(node) ||
      Node.isNonNullExpression(node) ||
      Node.isAwaitExpression(node)
    ) {
      node = node.getExpression();
    } else {
      return node;
    }
  }
}

function tainted(input: Node, s: State): boolean {
  const node = unwrap(input);
  if (Node.isCallExpression(node)) return isSourceCall(node, s) || callPropagates(node, s);
  if (Node.isIdentifier(node)) return identifierTainted(node, s);
  if (Node.isPropertyAccessExpression(node) || Node.isElementAccessExpression(node)) return tainted(node.getExpression(), s);
  if (Node.isTemplateExpression(node)) return node.getTemplateSpans().some((span) => tainted(span.getExpression(), s));
  if (Node.isBinaryExpression(node)) {
    const operator = node.getOperatorToken().getKind();
    if (operator === SyntaxKind.EqualsToken) return tainted(node.getRight(), s);
    if (
      operator === SyntaxKind.PlusToken ||
      operator === SyntaxKind.QuestionQuestionToken ||
      operator === SyntaxKind.BarBarToken ||
      operator === SyntaxKind.AmpersandAmpersandToken
    ) {
      return tainted(node.getLeft(), s) || tainted(node.getRight(), s);
    }
    return false;
  }
  if (Node.isConditionalExpression(node)) return tainted(node.getWhenTrue(), s) || tainted(node.getWhenFalse(), s);
  if (Node.isObjectLiteralExpression(node)) {
    return node.getProperties().some((property) => {
      if (Node.isSpreadAssignment(property)) return tainted(property.getExpression(), s);
      if (Node.isPropertyAssignment(property)) {
        const initializer = property.getInitializer();
        return initializer ? tainted(initializer, s) : false;
      }
      if (Node.isShorthandPropertyAssignment(property)) return tainted(property.getNameNode(), s);
      return false;
    });
  }
  if (Node.isArrayLiteralExpression(node)) return node.getElements().some((element) => tainted(element, s));
  if (Node.isSpreadElement(node)) return tainted(node.getExpression(), s);
  if (Node.isNewExpression(node)) {
    const first = node.getArguments()[0];
    return PROPAGATING_CONSTRUCTORS.has(node.getExpression().getText()) && first !== undefined && tainted(first, s);
  }
  return false;
}

/** request.json()/formData()/text(), searchParams/headers/cookies .get(). */
function isSourceCall(call: Node, s: State): boolean {
  if (!Node.isCallExpression(call)) return false;
  const name = calleeName(call);
  const receiver = receiverOf(call);
  if (!receiver) return false;

  if (BODY_READERS.has(name)) {
    const target = unwrap(receiver);
    if (!Node.isIdentifier(target)) return false;
    if (REQUEST_NAME.test(target.getText())) return true;
    const declaration = declarationOf(target);
    return s.kind === 'route' && declaration !== undefined && parameterIndex(declaration, s.fn) === 0;
  }

  if (name === 'get' || name === 'getAll') {
    const target = unwrap(receiver);
    if (Node.isPropertyAccessExpression(target) && SOURCE_CONTAINERS.has(target.getName())) return true;
    if (Node.isIdentifier(target) && target.getText() === 'searchParams') return true;
    const resolved = resolveLocal(target, s);
    if (resolved && Node.isCallExpression(resolved)) {
      const callee = unwrap(resolved.getExpression());
      if (Node.isIdentifier(callee) && (callee.getText() === 'headers' || callee.getText() === 'cookies')) return true;
    }
    if (resolved && Node.isPropertyAccessExpression(resolved) && SOURCE_CONTAINERS.has(resolved.getName())) return true;
  }
  return false;
}

/** Follows an identifier to its local initializer (unwrapped), without counting as a taint hop. */
function resolveLocal(node: Node, s: State): Node | undefined {
  let current = unwrap(node);
  for (let i = 0; i < MAX_HOPS && Node.isIdentifier(current); i++) {
    const declaration = declarationOf(current);
    if (!declaration || !Node.isVariableDeclaration(declaration) || !within(declaration, s.fn)) return undefined;
    const initializer = declaration.getInitializer();
    if (!initializer) return undefined;
    current = unwrap(initializer);
  }
  return current;
}

function callPropagates(call: Node, s: State): boolean {
  if (!Node.isCallExpression(call)) return false;
  const args = call.getArguments();
  const text = calleeText(call);
  if (PROPAGATING_FUNCTIONS.has(text)) return args[0] !== undefined && tainted(args[0], s);
  if (text === 'Object.assign') return args.some((arg) => tainted(arg, s));
  const receiver = receiverOf(call);
  return receiver !== undefined && PROPAGATING_METHODS.has(calleeName(call)) && tainted(receiver, s);
}

function within(node: Node, fn: FunctionNode | undefined): boolean {
  return fn !== undefined && (node === fn || node.getAncestors().includes(fn));
}

/** Index of the parameter (of `fn`) that declares `declaration`, or -1. */
function parameterIndex(declaration: Node, fn: FunctionNode | undefined): number {
  if (!fn) return -1;
  const parameter = Node.isParameterDeclaration(declaration) ? declaration : declaration.getFirstAncestor((a) => Node.isParameterDeclaration(a));
  if (!parameter || parameter.getParent() !== fn) return -1;
  return fn.getParameters().indexOf(parameter);
}

/** In-place regex validation (`if (!RE.test(name)) return`) counts as sanitizing `name`. */
function regexTested(name: string, fn: FunctionNode): boolean {
  return fn.getDescendantsOfKind(SyntaxKind.CallExpression).some((call) => {
    const first = call.getArguments()[0];
    return calleeName(call) === 'test' && first !== undefined && Node.isIdentifier(unwrap(first)) && unwrap(first).getText() === name;
  });
}

function identifierTainted(identifier: Node, s: State): boolean {
  if (!Node.isIdentifier(identifier) || !s.fn) return false;
  const declaration = declarationOf(identifier);
  if (!declaration || s.seen.has(declaration) || !within(declaration, s.fn)) return false;
  if (s.regexSanitizes && regexTested(identifier.getText(), s.fn)) return false;

  const index = parameterIndex(declaration, s.fn);
  if (index !== -1) return s.kind === 'action' || (s.kind === 'route' && index === 1);
  if (Node.isParameterDeclaration(declaration) || declaration.getFirstAncestor((a) => Node.isParameterDeclaration(a))) return false;

  if (s.hops >= MAX_HOPS) return false;
  const next: State = { ...s, hops: s.hops + 1, seen: new Set([...s.seen, declaration]) };

  const variable = Node.isVariableDeclaration(declaration) ? declaration : declaration.getFirstAncestor((a) => Node.isVariableDeclaration(a));
  if (!variable || !Node.isVariableDeclaration(variable)) return false;
  const initializer = variable.getInitializer();
  if (initializer && tainted(initializer, next)) return true;

  // let x = ...; x = <tainted>
  if (variable === declaration) {
    const name = identifier.getText();
    return s.fn.getDescendantsOfKind(SyntaxKind.BinaryExpression).some((assignment) => {
      if (assignment.getOperatorToken().getKind() !== SyntaxKind.EqualsToken) return false;
      const left = assignment.getLeft();
      return Node.isIdentifier(left) && left.getText() === name && declarationOf(left) === declaration && tainted(assignment.getRight(), next);
    });
  }
  return false;
}

/** The function a taint question should be asked against: the handler or action that encloses `node`. */
export function entryFunctionOf(node: Node): FunctionNode | undefined {
  for (let current: Node | undefined = node; current; current = current.getParent()) {
    if (isFunctionNode(current) && entryKind(current)) return current;
  }
  return outermostFunction(node);
}
