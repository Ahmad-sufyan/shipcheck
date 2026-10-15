import type { Rule } from '../../src/types.js';

/** A minimal valid rule for engine tests; override any field. */
export function testRule(overrides: Partial<Rule> = {}): Rule {
  return {
    id: 'TEST-001',
    title: 'Test rule',
    category: 'http-config',
    severity: 'medium',
    confidence: 'high',
    stacks: [],
    description: 'A rule used by tests.',
    explanation: 'Default explanation.',
    fix: 'Default fix.',
    falsePositiveNote: 'None.',
    run: () => [],
    ...overrides,
  };
}
