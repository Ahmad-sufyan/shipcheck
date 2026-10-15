import { createRegistry, type RuleRegistry } from '../core/registry.js';
import type { Rule, RulePack } from '../types.js';
import { nextjsSupabasePack } from './nextjs-supabase/index.js';

export const packs: readonly RulePack[] = [nextjsSupabasePack];

export function allRules(): Rule[] {
  return packs.flatMap((pack) => pack.rules);
}

/** A fresh registry holding every rule from every pack (validated on registration). */
export function defaultRegistry(): RuleRegistry {
  return createRegistry(allRules());
}
