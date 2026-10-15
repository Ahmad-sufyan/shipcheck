import type { RulePack } from '../../types.js';
import { authz001 } from './rules/authz-001-handler-without-auth.js';
import { authz002 } from './rules/authz-002-matcher-gap.js';
import { authz003 } from './rules/authz-003-idor.js';
import { authz005 } from './rules/authz-005-rls-disabled.js';
import { authz006 } from './rules/authz-006-permissive-policy.js';
import { authz007 } from './rules/authz-007-service-role-client.js';
import { authz008 } from './rules/authz-008-mass-assignment.js';
import { http006PoweredBy } from './rules/http-006-powered-by.js';
import { input001 } from './rules/input-001-sql-injection.js';
import { input003 } from './rules/input-003-dangerous-html.js';
import { input004 } from './rules/input-004-unsanitized-markdown.js';
import { input005 } from './rules/input-005-command-injection.js';
import { input006 } from './rules/input-006-path-traversal.js';
import { secret006SourceMaps } from './rules/secret-006-source-maps.js';

export const nextjsSupabasePack: RulePack = {
  id: 'nextjs-supabase',
  title: 'Next.js App Router + Supabase',
  rules: [authz001, authz002, authz003, authz005, authz006, authz007, authz008, http006PoweredBy, input001, input003, input004, input005, input006, secret006SourceMaps],
};
