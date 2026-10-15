import { describe, expect, it } from 'vitest';
import { createMemorySource } from '../../../src/context/files.js';
import { detectStacks } from '../../../src/stacks/detect.js';

function detect(files: Record<string, string>): string[] {
  const source = createMemorySource(files);
  const raw = files['package.json'];
  const pkg = raw ? { file: 'package.json', data: JSON.parse(raw) as Record<string, unknown> } : null;
  return [...detectStacks(source, pkg)];
}

const next = JSON.stringify({ dependencies: { next: '16.4.1' } });

describe('detectStacks', () => {
  it('detects the App Router when next is a dependency and app/ or src/app/ exists', () => {
    expect(detect({ 'package.json': next, 'app/page.tsx': '' })).toEqual(['nextjs-app-router']);
    expect(detect({ 'package.json': next, 'src/app/page.tsx': '' })).toEqual(['nextjs-app-router']);
    expect(detect({ 'package.json': next, 'pages/index.tsx': '' })).toEqual([]);
    expect(detect({ 'package.json': '{}', 'app/page.tsx': '' })).toEqual([]);
    expect(detect({ 'package.json': JSON.stringify({ devDependencies: { next: '16' } }), 'app/page.tsx': '' })).toEqual(['nextjs-app-router']);
  });

  it('detects Supabase from dependencies or a supabase/ directory', () => {
    expect(detect({ 'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2' } }) })).toEqual(['supabase']);
    expect(detect({ 'package.json': JSON.stringify({ dependencies: { '@supabase/ssr': '1' } }) })).toEqual(['supabase']);
    expect(detect({ 'supabase/config.toml': '' })).toEqual(['supabase']);
  });

  it('detects Vercel and Cloudflare from their config files', () => {
    expect(detect({ 'vercel.json': '{}' })).toEqual(['vercel']);
    expect(detect({ '.vercel/project.json': '{}' })).toEqual(['vercel']);
    expect(detect({ 'wrangler.toml': '' })).toEqual(['cloudflare']);
    expect(detect({ 'wrangler.json': '{}' })).toEqual(['cloudflare']);
    expect(detect({ 'wrangler.jsonc': '{}' })).toEqual(['cloudflare']);
  });

  it('returns stacks in a fixed order', () => {
    expect(
      detect({
        'package.json': JSON.stringify({ dependencies: { next: '16', '@supabase/ssr': '1' } }),
        'app/page.tsx': '',
        'wrangler.toml': '',
        'vercel.json': '{}',
      }),
    ).toEqual(['nextjs-app-router', 'supabase', 'vercel', 'cloudflare']);
  });
});
