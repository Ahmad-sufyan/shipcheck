import { Node, SyntaxKind, type SourceFile } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeText, findingAt, importBindings, importedCallName, isTestPath, resolveExpression, sourceFiles, stringLiteral } from '../analysis/ast-utils.js';

const SECRET_ENV = /^(?:JWT_SECRET|AUTH_SECRET|NEXTAUTH_SECRET|SESSION_SECRET|SUPABASE_JWT_SECRET|[A-Z0-9_]*_JWT_SECRET)$/;
const COMMON_WORDS = /^(?:secret|secret123|changeme|change-me|password|passw0rd|test|testing|dev|development|example|default|jwtsecret|jwt-secret|mysecret|my-secret|your-secret|supersecret|super-secret|keyboard cat|123456|admin)$/i;
const EXAMPLE_ENV = /\.(?:example|sample|template|dist)$/i;
const MIN_LENGTH = 32;

/** String literals a key expression can evaluate to: a literal, a `?? 'fallback'`/`|| 'fallback'`, or TextEncoder().encode('...'). */
function literalSources(input: Node, depth = 0): Node[] {
  const node = unwrapExpression(input);
  if (stringLiteral(node) !== undefined) return [node];
  if (depth > 3) return [];
  if (Node.isIdentifier(node)) {
    const resolved = resolveExpression(node, 1);
    return resolved === node ? [] : literalSources(resolved, depth + 1);
  }
  if (Node.isBinaryExpression(node) && ['??', '||'].includes(node.getOperatorToken().getText())) return literalSources(node.getRight(), depth + 1);
  if (Node.isCallExpression(node) && /(?:^|\.)encode$/.test(calleeText(node)) && /TextEncoder/.test(node.getExpression().getText())) {
    const [arg] = node.getArguments();
    return arg ? literalSources(arg, depth + 1) : [];
  }
  if (Node.isCallExpression(node) && (calleeText(node) === 'Buffer.from' || calleeText(node) === 'createSecretKey')) {
    const [arg] = node.getArguments();
    return arg ? literalSources(arg, depth + 1) : [];
  }
  return [];
}

/** Key arguments of jsonwebtoken sign/verify and jose sign/jwtVerify/compactVerify calls. */
function keyArguments(sourceFile: SourceFile): Node[] {
  const jwt = importBindings(sourceFile, ['jsonwebtoken']);
  const jose = importBindings(sourceFile, ['jose']);
  const keys: Node[] = [];
  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const args = call.getArguments();
    const jwtFn = importedCallName(call, jwt);
    if ((jwtFn === 'sign' || jwtFn === 'verify') && args[1]) keys.push(args[1]);
    const joseFn = importedCallName(call, jose);
    if ((joseFn === 'jwtVerify' || joseFn === 'compactVerify' || joseFn === 'jwtDecrypt') && args[1]) keys.push(args[1]);
    const callee = call.getExpression();
    if (Node.isPropertyAccessExpression(callee) && callee.getName() === 'sign' && /new\s+SignJWT\b/.test(callee.getExpression().getText()) && args[0]) keys.push(args[0]);
  }
  return keys;
}

export const auth006: Rule = {
  id: 'AUTH-006',
  title: 'Weak JWT secret',
  category: 'secrets',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports string literals used as the key for jsonwebtoken sign/verify or jose SignJWT/jwtVerify, including literals ' +
    "behind a local constant, a `process.env.X ?? 'fallback'`, or TextEncoder().encode('...'), reported once at the " +
    'literal. Also reports JWT_SECRET, AUTH_SECRET, NEXTAUTH_SECRET and similar variables in .env files that are shorter ' +
    'than 32 characters or a common word. Test directories and example env files are skipped.',
  explanation:
    'Tokens are signed with a secret that is in your source code or easy to guess, so anyone who knows or guesses it can ' +
    'mint valid tokens for any user.',
  fix: 'Generate at least 32 random bytes (`openssl rand -base64 32`), store them in an environment variable, and fail at startup when it is missing instead of falling back to a literal.',
  falsePositiveNote: 'Secrets used only by tests outside test directories are still reported.',
  cwe: 'CWE-798',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#weak-token-secret'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => text.includes('jsonwebtoken') || text.includes('jose'))) {
      const seen = new Set<Node>();
      for (const key of keyArguments(ctx.getSourceFile(file))) {
        for (const literal of literalSources(key)) {
          if (seen.has(literal)) continue;
          seen.add(literal);
          findings.push(findingAt(literal));
        }
      }
    }
    for (const env of ctx.envFiles) {
      if (EXAMPLE_ENV.test(env.file) || isTestPath(env.file)) continue;
      for (const entry of env.entries) {
        if (!SECRET_ENV.test(entry.key) || !entry.value) continue;
        if (entry.value.length < MIN_LENGTH || COMMON_WORDS.test(entry.value)) {
          findings.push({ file: env.file, line: entry.line, evidence: `${entry.key}=<${entry.value.length} chars>` });
        }
      }
    }
    return findings;
  },
};
