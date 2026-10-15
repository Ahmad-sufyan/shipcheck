import { Node } from 'ts-morph';
import { calleeName, calleeText } from './ast-utils.js';

const HTML_SANITIZER_NAME = /^(?:sanitize|sanitizeHtml|sanitizeHTML|purify|escapeHtml|escapeHTML|escape|xss|filterXSS)$/;

/** DOMPurify.sanitize, sanitize-html, xss(), escape helpers. */
export function isHtmlSanitizerCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  return HTML_SANITIZER_NAME.test(calleeName(node)) || /(?:^|\.)(?:DOMPurify|purify)\.sanitize$/i.test(calleeText(node));
}

/** Whether `node` sits inside the arguments of a sanitizer call (within its statement). */
export function insideSanitizer(node: Node): boolean {
  for (let current = node.getParent(); current && !Node.isStatement(current); current = current.getParent()) {
    if (isHtmlSanitizerCall(current)) return true;
  }
  return false;
}

const SCHEMA_METHODS = new Set(['parse', 'safeParse', 'parseAsync', 'safeParseAsync', 'validate', 'validateSync', 'assert', 'is']);
const NOT_SCHEMAS = /^(?:JSON|Date|Number|URL|path|querystring|qs|url|Math|BigInt|Object|Array|Reflect|assert)$/;

/** zod/valibot/yup/arktype-style validation calls; JSON.parse and friends do not count. */
export function isSchemaValidationCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  const name = calleeName(node);
  if (!SCHEMA_METHODS.has(name)) return false;
  const text = calleeText(node);
  const receiver = text.slice(0, Math.max(0, text.length - name.length - 1));
  return !NOT_SCHEMAS.test(receiver);
}
