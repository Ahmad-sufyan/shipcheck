import type { Rule } from '../../../types.js';
import { entries } from '../analysis/entries.js';
import { isLogoutEntry, isResetEntry, loginSignals } from '../analysis/flows.js';

/** An audit helper call or a write to an audit/auth-events table. */
const AUDIT_WRITE = /audit|auth_events|security_events|login_events|activity_log|recordEvent|logEvent\s*\(/i;

export const data004: Rule = {
  id: 'DATA-004',
  title: 'No audit logging for authentication events',
  category: 'data-protection',
  severity: 'info',
  confidence: 'medium',
  advisory: true,
  stacks: ['nextjs-app-router'],
  description:
    'Project-level check: when the app has its own login, logout or password reset handlers and none of them records an ' +
    'audit event (an audit helper, or a write to an audit/auth_events/security_events table), reports once. Advisory: ' +
    'Supabase Auth keeps its own auth logs for flows it handles.',
  explanation:
    'Sign-ins, sign-outs and password resets leave no trace in your own data, so you cannot investigate a compromised ' +
    'account or notice credential-stuffing attempts.',
  fix: 'Write an append-only audit record (user id, action, IP, time) for logins, failed logins, logouts and password resets.',
  falsePositiveNote: 'Supabase Auth audit logs cover flows handled entirely by Supabase; custom handlers are not covered.',
  cwe: 'CWE-778',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#which-events-to-log', 'https://supabase.com/docs/guides/auth/audit-logs'],
  run(ctx) {
    const authEntries = entries(ctx).filter((entry) => loginSignals(entry).login || isLogoutEntry(entry) || isResetEntry(entry));
    if (!authEntries.length || authEntries.some((entry) => AUDIT_WRITE.test(entry.node.getText()))) return [];
    return [{ evidence: 'No audit record is written by the login, logout or password reset handlers' }];
  },
};
