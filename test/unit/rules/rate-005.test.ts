import { describe, expect, it } from 'vitest';
import { rate005 as rule } from '../../../src/packs/nextjs-supabase/rules/rate-005-form-bot-protection.js';
import { code, runRule } from '../../helpers/memory-context.js';

const page = code('export default function ContactPage() {', '  return (', '    <form action="/api/contact" method="post">', '      <input name="email" />', '    </form>', '  )', '}');
const route = code('export async function POST(request: Request) {', "  await resend.emails.send({ from: 'a', to: 'b', subject: 'c', text: 'd' })", '}');

describe('RATE-005 Public form without bot protection', () => {
  it('reports a form posting to a public mutation endpoint', async () => {
    expect(await runRule(rule, { 'app/contact/page.tsx': page, 'app/api/contact/route.ts': route })).toEqual([
      { file: 'app/contact/page.tsx', line: 3, evidence: '<form action="/api/contact" method="post">' },
    ]);
  });

  it('reports forms bound to server actions without auth', async () => {
    const actions = code("'use server'", 'export async function subscribe(formData: FormData) {', "  await db.query('insert into subs values ($1)', [formData.get('email')])", '}');
    const form = code("import { subscribe } from './actions'", 'export default function P() {', '  return <form action={subscribe}><input name="email" /></form>', '}');
    expect(await runRule(rule, { 'app/actions.ts': actions, 'app/page.tsx': form })).toEqual([expect.objectContaining({ file: 'app/page.tsx', line: 3 })]);
  });

  it('ignores projects that use Turnstile, hCaptcha or reCAPTCHA', async () => {
    expect(await runRule(rule, { 'app/contact/page.tsx': page, 'app/api/contact/route.ts': route, 'components/captcha.tsx': "import { Turnstile } from '@marsidev/react-turnstile'" })).toEqual([]);
  });

  it('ignores forms posting to authenticated endpoints', async () => {
    const authed = route.replace('{\n', '{\n  const { data } = await supabase.auth.getUser()\n');
    expect(await runRule(rule, { 'app/contact/page.tsx': page, 'app/api/contact/route.ts': authed })).toEqual([]);
  });
});
