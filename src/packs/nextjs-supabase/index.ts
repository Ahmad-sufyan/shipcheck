import type { RulePack } from '../../types.js';
import { http006PoweredBy } from './rules/http-006-powered-by.js';
import { secret006SourceMaps } from './rules/secret-006-source-maps.js';

export const nextjsSupabasePack: RulePack = {
  id: 'nextjs-supabase',
  title: 'Next.js App Router + Supabase',
  rules: [http006PoweredBy, secret006SourceMaps],
};
