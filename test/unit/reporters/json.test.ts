import { describe, expect, it } from 'vitest';
import { renderJson } from '../../../src/reporters/json.js';
import { ScanResultSchema } from '../../../src/schema.js';
import { makeFinding, makeResult } from '../../helpers/results.js';

describe('renderJson', () => {
  it('pretty-prints the full scan result with a trailing newline', () => {
    const result = makeResult([makeFinding()]);
    const out = renderJson(result);
    expect(out.endsWith('}\n')).toBe(true);
    expect(out).toContain('\n  "schemaVersion": "1.0",\n');
    expect(ScanResultSchema.parse(JSON.parse(out))).toEqual(result);
  });
});
