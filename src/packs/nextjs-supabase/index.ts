import type { RulePack } from '../../types.js';
import { authz001 } from './rules/authz-001-handler-without-auth.js';
import { authz002 } from './rules/authz-002-matcher-gap.js';
import { http006PoweredBy } from './rules/http-006-powered-by.js';
import { secret006SourceMaps } from './rules/secret-006-source-maps.js';

export const nextjsSupabasePack: RulePack = {
  id: 'nextjs-supabase',
  title: 'Next.js App Router + Supabase',
  rules: [authz001, authz002, http006PoweredBy, secret006SourceMaps],
};
