import type { CallExpression } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeText, calls, findingAt } from '../analysis/ast-utils.js';
import { isFsCall } from '../analysis/db-write.js';
import { entries } from '../analysis/entries.js';

const FS_WRITES = new Set(['writeFile', 'writeFileSync', 'createWriteStream', 'appendFile', 'copyFile', 'rename']);

function isFileSink(call: CallExpression): boolean {
  return (isFsCall(call) && FS_WRITES.has(calleeName(call))) || (calleeName(call) === 'upload' && /storage/.test(calleeText(call)));
}

export const input009: Rule = {
  id: 'INPUT-009',
  title: 'Unvalidated file upload',
  category: 'input-validation',
  severity: 'high',
  confidence: 'medium',
  stacks: ['nextjs-app-router'],
  description:
    'In route handlers and server actions that read form data, reports file writes (fs writeFile/createWriteStream) and ' +
    'storage uploads when the function never checks both the file .size and .type, and any write whose destination ' +
    'mentions public/, which Next.js serves directly. Limitations: checks in helpers and bucket-level limits are not seen.',
  explanation:
    'Any file the caller sends is stored, so an attacker can upload huge files to exhaust storage, or HTML/SVG files that ' +
    'run script when opened from your domain.',
  fix: 'Check file.size against a limit and the type (ideally by magic bytes) against an allowlist, generate the file name yourself, and store uploads outside public/ (for example a private Supabase Storage bucket).',
  falsePositiveNote: 'Storage bucket policies that enforce size and MIME limits are not visible to this rule.',
  cwe: 'CWE-434',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html', 'https://supabase.com/docs/guides/storage/buckets/fundamentals'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const entry of entries(ctx)) {
      const text = entry.node.getText();
      const readsForm = /\.formData\(\)/.test(text) || (entry.kind === 'action' && /\bFormData\b|\.get\(/.test(text));
      if (!readsForm) continue;
      const checked = /\.size\b/.test(text) && /\.type\b/.test(text);
      for (const sink of calls(entry.node).filter(isFileSink)) {
        const publicPath = /['"`/]public['"`/]/.test(sink.getText());
        if (!checked || publicPath) findings.push(findingAt(sink));
      }
    }
    return findings;
  },
};
