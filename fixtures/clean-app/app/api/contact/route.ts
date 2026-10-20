import { NextResponse } from 'next/server'
import { ipAddress } from '@vercel/functions'
import { Resend } from 'resend'
import { z } from 'zod'
import { rateLimit } from '@/lib/rate-limit'

const resend = new Resend(process.env.RESEND_API_KEY)
const ContactSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.email(),
  message: z.string().min(1).max(5000),
  'cf-turnstile-response': z.string().min(1),
})

async function verifyTurnstile(token: string, ip: string): Promise<boolean> {
  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: new URLSearchParams({ secret: process.env.TURNSTILE_SECRET_KEY!, response: token, remoteip: ip }),
  })
  const result = (await response.json()) as { success: boolean }
  return result.success
}

export async function POST(request: Request) {
  const ip = ipAddress(request) ?? 'unknown'
  if (!(await rateLimit(`contact:${ip}`))) {
    return NextResponse.json({ error: 'Too many requests' }, { status: 429 })
  }
  const parsed = ContactSchema.safeParse(Object.fromEntries(await request.formData()))
  if (!parsed.success || !(await verifyTurnstile(parsed.data['cf-turnstile-response'], ip))) {
    return NextResponse.json({ error: 'Invalid submission' }, { status: 400 })
  }
  await resend.emails.send({
    from: 'Acme <hello@acme.example>',
    to: 'support@acme.example',
    replyTo: parsed.data.email,
    subject: 'New contact form message',
    text: parsed.data.message,
  })
  return NextResponse.redirect(new URL('/contact?sent=1', request.url), 303)
}
