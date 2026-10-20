import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import type { ErrorObject } from 'ajv';

// Both packages are CommonJS with a default export; require() sidesteps NodeNext default-import interop.
const require = createRequire(import.meta.url);
const Ajv = require('ajv-draft-04') as typeof import('ajv-draft-04').default;
const addFormats = require('ajv-formats') as typeof import('ajv-formats').default;

/**
 * The official OASIS SARIF 2.1.0 schema (errata01, JSON Schema draft-04), vendored unchanged from
 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
 * (Copyright OASIS Open 2023), sha256 c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e.
 */
const schema = JSON.parse(readFileSync(new URL('../schemas/sarif-schema-2.1.0.json', import.meta.url), 'utf8')) as object;

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validate = ajv.compile(schema);

/** Schema errors as readable strings; empty when the document is valid SARIF 2.1.0. */
export function sarifErrors(document: unknown): string[] {
  if (validate(document)) return [];
  return (validate.errors ?? []).map((e: ErrorObject) => `${e.instancePath || '(root)'} ${e.message ?? ''}`);
}
