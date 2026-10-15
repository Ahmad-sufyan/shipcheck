import { describe, expect, it } from 'vitest';
import { createRegistry, RuleRegistry } from '../../../src/core/registry.js';
import { testRule } from '../../helpers/rules.js';

describe('RuleRegistry', () => {
  it('returns registered rules sorted by id', () => {
    const registry = createRegistry([testRule({ id: 'B-002' }), testRule({ id: 'A-001' }), testRule({ id: 'B-001' })]);
    expect(registry.all().map((r) => r.id)).toEqual(['A-001', 'B-001', 'B-002']);
    expect(registry.size).toBe(3);
    expect(registry.has('A-001')).toBe(true);
    expect(registry.get('B-002')?.id).toBe('B-002');
    expect(registry.get('Z-999')).toBeUndefined();
  });

  it('rejects duplicate ids', () => {
    const registry = new RuleRegistry().register(testRule());
    expect(() => registry.register(testRule())).toThrow(/Duplicate rule id TEST-001/);
  });

  it('rejects rules with invalid metadata, naming the rule and field', () => {
    expect(() => createRegistry([testRule({ id: 'lowercase-1' })])).toThrow(/lowercase-1.*id/s);
    expect(() => createRegistry([testRule({ fix: '' })])).toThrow(/TEST-001.*fix/s);
    expect(() => createRegistry([testRule({ cwe: '200' })])).toThrow(/TEST-001.*cwe/s);
    expect(() => createRegistry([testRule({ stacks: ['django' as never] })])).toThrow(/TEST-001.*stacks/s);
  });
});
