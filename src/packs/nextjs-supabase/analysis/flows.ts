import { calleeName, calleeText, calls } from './ast-utils.js';
import type { Entry } from './entries.js';

const LOGIN_PATH = /(?:^|\/)(?:login|log-in|signin|sign-in)(?:\/|$)/i;
const PASSWORD_CHECK = /(?:^|\.)(?:compare|compareSync|verify)$/;
const RESET_PATH = /reset|forgot|recover/i;
const RESET_TEXT = /password[_-]?resets?|reset[_-]?password|forgot[_-]?password/i;
const LOGOUT_PATH = /(?:^|\/)(?:logout|log-out|signout|sign-out)(?:\/|$)/i;
const LOGOUT_NAME = /^(?:logout|logOut|signOut|signout|sign_out|log_out)$/;

export interface LoginSignals {
  /** The entry is a login handler. */
  login: boolean;
  /** It signs in only through Supabase Auth (signInWithPassword) and verifies no password itself. */
  supabaseOnly: boolean;
}

/** Login handlers: POST-ish routes under /login or /signin, or code that verifies a password. */
export function loginSignals(entry: Entry): LoginSignals {
  const found = calls(entry.node).map((call) => ({ name: calleeName(call), text: calleeText(call) }));
  const supabaseSignIn = found.some((c) => c.name === 'signInWithPassword');
  const verifiesPassword = found.some(
    (c) => (/bcrypt|argon|scrypt/i.test(c.text) && PASSWORD_CHECK.test(c.text)) || /^(?:verifyPassword|comparePassword|checkPassword)$/.test(c.name),
  );
  const loginPath = entry.kind === 'route' && entry.method !== 'GET' && LOGIN_PATH.test(entry.routePath ?? '');
  return { login: loginPath || supabaseSignIn || verifiesPassword, supabaseOnly: supabaseSignIn && !verifiesPassword };
}

/** Password reset handlers: reset/forgot/recover paths or names, or code that mentions password resets. */
export function isResetEntry(entry: Entry): boolean {
  return (entry.kind === 'route' && RESET_PATH.test(entry.routePath ?? '')) || RESET_PATH.test(entry.name) || RESET_TEXT.test(entry.node.getText());
}

export function isLogoutEntry(entry: Entry): boolean {
  return (entry.kind === 'route' && LOGOUT_PATH.test(entry.routePath ?? '')) || (entry.kind === 'action' && LOGOUT_NAME.test(entry.name));
}
