import { Node } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeNameNode, calls, findingAt, sourceFiles, stringLiteral } from '../analysis/ast-utils.js';

const FAST_HASHES = new Set(['md5', 'sha1', 'sha256', 'sha512']);
const PASSWORD_NAME = /pass(?:word)?|pwd/i;

export const auth001: Rule = {
  id: 'AUTH-001',
  title: 'Weak password hashing',
  category: 'authentication',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    "Reports createHash('md5' | 'sha1' | 'sha256' | 'sha512') whose .update() input mentions a password-like name " +
    '(password, pass, pwd). These hashes are fast, so leaked hashes can be brute-forced at billions of guesses per second. ' +
    'Limitations: only node:crypto createHash chains are inspected; weak bcrypt cost factors are not checked.',
  explanation:
    'Passwords are stored with a fast general-purpose hash. If your database leaks, most of these passwords can be cracked ' +
    'quickly, and users who reuse passwords are exposed elsewhere too.',
  fix: 'Use Supabase Auth, or a password hashing function: argon2id, scrypt, or bcrypt with a cost factor of at least 12.',
  falsePositiveNote: 'A checksum over a password-named variable that is not a stored credential (rare) is still reported.',
  cwe: 'CWE-916',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => text.includes('createHash'))) {
      for (const call of calls(ctx.getSourceFile(file))) {
        if (calleeName(call) !== 'createHash' || !FAST_HASHES.has((stringLiteral(call.getArguments()[0]) ?? '').toLowerCase())) continue;
        const access = call.getParent();
        const update = access?.getParent();
        if (!access || !Node.isPropertyAccessExpression(access) || access.getName() !== 'update' || !update || !Node.isCallExpression(update)) continue;
        const input = update.getArguments()[0]?.getText() ?? '';
        if (PASSWORD_NAME.test(input)) findings.push(findingAt(calleeNameNode(call)));
      }
    }
    return findings;
  },
};
