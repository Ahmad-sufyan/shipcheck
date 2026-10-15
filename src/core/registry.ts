import { RuleMetaSchema } from '../schema.js';
import type { Rule } from '../types.js';
import { compareStrings } from '../context/files.js';

export class RuleRegistry {
  readonly #rules = new Map<string, Rule>();

  /** Validates the rule's metadata and adds it. Throws on invalid metadata or a duplicate id. */
  register(rule: Rule): this {
    const parsed = RuleMetaSchema.safeParse(rule);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((issue) => `${issue.path.map(String).join('.')}: ${issue.message}`).join('; ');
      throw new Error(`Invalid rule ${String(rule.id)}: ${issues}`);
    }
    if (this.#rules.has(rule.id)) throw new Error(`Duplicate rule id ${rule.id}`);
    this.#rules.set(rule.id, rule);
    return this;
  }

  get(id: string): Rule | undefined {
    return this.#rules.get(id);
  }

  has(id: string): boolean {
    return this.#rules.has(id);
  }

  /** All rules, sorted by id. */
  all(): Rule[] {
    return [...this.#rules.values()].sort((a, b) => compareStrings(a.id, b.id));
  }

  get size(): number {
    return this.#rules.size;
  }
}

export function createRegistry(rules: readonly Rule[]): RuleRegistry {
  const registry = new RuleRegistry();
  for (const rule of rules) registry.register(rule);
  return registry;
}
