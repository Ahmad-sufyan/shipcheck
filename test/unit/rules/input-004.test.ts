import { describe, expect, it } from 'vitest';
import { input004 as rule } from '../../../src/packs/nextjs-supabase/rules/input-004-unsanitized-markdown.js';
import { code, runRule } from '../../helpers/memory-context.js';

const FILE = 'components/markdown-view.tsx';
const imports = code("import ReactMarkdown from 'react-markdown'", "import rehypeRaw from 'rehype-raw'", "import rehypeSanitize from 'rehype-sanitize'");

describe('INPUT-004 Unsanitized markdown/HTML', () => {
  it('reports ReactMarkdown with rehype-raw and no rehype-sanitize', async () => {
    const text = code(imports, 'export function View({ source }: { source: string }) {', '  return <ReactMarkdown rehypePlugins={[rehypeRaw]}>{source}</ReactMarkdown>', '}');
    expect(await runRule(rule, { [FILE]: text })).toEqual([{ file: FILE, line: 5, evidence: 'return <ReactMarkdown rehypePlugins={[rehypeRaw]}>{source}</ReactMarkdown>' }]);
  });

  it('reports markdown-it with html: true rendered into innerHTML without sanitising', async () => {
    const text = code("import MarkdownIt from 'markdown-it'", 'const md = new MarkdownIt({ html: true })', 'export function render(el: HTMLElement, src: string) {', '  el.innerHTML = md.render(src)', '}');
    expect(await runRule(rule, { 'lib/render.ts': text })).toEqual([expect.objectContaining({ line: 2 })]);
  });

  it('ignores rehype-raw followed by rehype-sanitize', async () => {
    const text = code(imports, 'export function View({ source }: { source: string }) {', '  return <ReactMarkdown rehypePlugins={[rehypeRaw, [rehypeSanitize, schema]]}>{source}</ReactMarkdown>', '}');
    expect(await runRule(rule, { [FILE]: text })).toEqual([]);
  });

  it('ignores ReactMarkdown without raw HTML support', async () => {
    const text = code("import ReactMarkdown from 'react-markdown'", 'export const View = ({ source }: { source: string }) => <ReactMarkdown>{source}</ReactMarkdown>');
    expect(await runRule(rule, { [FILE]: text })).toEqual([]);
  });

  it('ignores markdown-it output that is sanitised', async () => {
    const text = code("import MarkdownIt from 'markdown-it'", 'const md = new MarkdownIt({ html: true })', 'export function render(el: HTMLElement, src: string) {', '  el.innerHTML = DOMPurify.sanitize(md.render(src))', '}');
    expect(await runRule(rule, { 'lib/render.ts': text })).toEqual([]);
  });
});
