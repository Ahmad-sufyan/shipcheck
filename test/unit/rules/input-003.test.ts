import { describe, expect, it } from 'vitest';
import { input003 as rule } from '../../../src/packs/nextjs-supabase/rules/input-003-dangerous-html.js';
import { code, runRule } from '../../helpers/memory-context.js';

const FILE = 'components/comment.tsx';
const component = (...lines: string[]) => code('export function Comment({ comment }: { comment: { body: string } }) {', ...lines, '}');

describe('INPUT-003 XSS via dangerouslySetInnerHTML', () => {
  it('reports unsanitised HTML', async () => {
    const text = component('  return (', '    <div dangerouslySetInnerHTML={{ __html: comment.body }} />', '  )');
    expect(await runRule(rule, { [FILE]: text })).toEqual([{ file: FILE, line: 3, evidence: '<div dangerouslySetInnerHTML={{ __html: comment.body }} />' }]);
  });

  it('follows identifiers to unsanitised values', async () => {
    const text = component('  const html = `<p>${comment.body}</p>`', '  return <div dangerouslySetInnerHTML={{ __html: html }} />');
    expect(await runRule(rule, { [FILE]: text })).toHaveLength(1);
  });

  it('reports JSON.stringify without escaping with low confidence', async () => {
    const text = component('  return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(comment) }} />');
    expect(await runRule(rule, { [FILE]: text })).toEqual([expect.objectContaining({ confidence: 'low' })]);
  });

  it('ignores sanitised HTML, directly or through a variable', async () => {
    expect(await runRule(rule, { [FILE]: component('  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.body) }} />') })).toEqual([]);
    expect(await runRule(rule, { [FILE]: component('  const safe = sanitizeHtml(comment.body)', '  return <div dangerouslySetInnerHTML={{ __html: safe }} />') })).toEqual([]);
  });

  it('ignores string literals and escaped JSON-LD', async () => {
    expect(await runRule(rule, { [FILE]: component("  return <div dangerouslySetInnerHTML={{ __html: '<br/>' }} />") })).toEqual([]);
    const jsonLd = component("  return <script dangerouslySetInnerHTML={{ __html: JSON.stringify(comment).replace(/</g, '\\\\u003c') }} />");
    expect(await runRule(rule, { [FILE]: jsonLd })).toEqual([]);
  });
});
