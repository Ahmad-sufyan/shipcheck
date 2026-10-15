import type { RulePack } from '../../types.js';
import { auth001 } from './rules/auth-001-weak-password-hash.js';
import { auth002 } from './rules/auth-002-login-rate-limit.js';
import { auth003 } from './rules/auth-003-login-enumeration.js';
import { auth004 } from './rules/auth-004-insecure-cookie.js';
import { auth005 } from './rules/auth-005-jwt-not-pinned.js';
import { auth006 } from './rules/auth-006-weak-jwt-secret.js';
import { auth007 } from './rules/auth-007-token-in-storage.js';
import { auth008 } from './rules/auth-008-oauth-without-state.js';
import { auth009 } from './rules/auth-009-oauth-redirect.js';
import { auth010 } from './rules/auth-010-weak-reset-token.js';
import { auth011 } from './rules/auth-011-reset-enumeration.js';
import { auth012 } from './rules/auth-012-no-mfa.js';
import { auth013 } from './rules/auth-013-logout-session.js';
import { authz001 } from './rules/authz-001-handler-without-auth.js';
import { authz002 } from './rules/authz-002-matcher-gap.js';
import { authz003 } from './rules/authz-003-idor.js';
import { authz004 } from './rules/authz-004-client-role-check.js';
import { authz005 } from './rules/authz-005-rls-disabled.js';
import { authz006 } from './rules/authz-006-permissive-policy.js';
import { authz007 } from './rules/authz-007-service-role-client.js';
import { authz008 } from './rules/authz-008-mass-assignment.js';
import { http001 } from './rules/http-001-csp.js';
import { http002 } from './rules/http-002-security-headers.js';
import { http006PoweredBy } from './rules/http-006-powered-by.js';
import { input001 } from './rules/input-001-sql-injection.js';
import { input002 } from './rules/input-002-nosql-injection.js';
import { input003 } from './rules/input-003-dangerous-html.js';
import { input004 } from './rules/input-004-unsanitized-markdown.js';
import { input005 } from './rules/input-005-command-injection.js';
import { input006 } from './rules/input-006-path-traversal.js';
import { input007 } from './rules/input-007-ssrf.js';
import { input008 } from './rules/input-008-open-redirect.js';
import { input009 } from './rules/input-009-unvalidated-upload.js';
import { input010 } from './rules/input-010-no-schema-validation.js';
import { input011 } from './rules/input-011-redos.js';
import { input012 } from './rules/input-012-prototype-pollution.js';
import { integ001 } from './rules/integ-001-webhook-signature.js';
import { integ002 } from './rules/integ-002-cron-secret.js';
import { integ003 } from './rules/integ-003-client-price.js';
import { integ004 } from './rules/integ-004-llm-key-client.js';
import { integ005 } from './rules/integ-005-system-prompt-input.js';
import { rate001 } from './rules/rate-001-sensitive-endpoint.js';
import { rate002 } from './rules/rate-002-ai-endpoint.js';
import { rate003 } from './rules/rate-003-memory-limiter.js';
import { rate004 } from './rules/rate-004-spoofable-key.js';
import { rate005 } from './rules/rate-005-form-bot-protection.js';
import { secret006SourceMaps } from './rules/secret-006-source-maps.js';

export const nextjsSupabasePack: RulePack = {
  id: 'nextjs-supabase',
  title: 'Next.js App Router + Supabase',
  rules: [auth001, auth002, auth003, auth004, auth005, auth006, auth007, auth008, auth009, auth010, auth011, auth012, auth013, authz001, authz002, authz003, authz004, authz005, authz006, authz007, authz008, http001, http002, http006PoweredBy, input001, input002, input003, input004, input005, input006, input007, input008, input009, input010, input011, input012, integ001, integ002, integ003, integ004, integ005, rate001, rate002, rate003, rate004, rate005, secret006SourceMaps],
};
