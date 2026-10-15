import { NextResponse } from 'next/server'
import { Resend } from 'resend'
import { z } from 'zod'

const resend = new Resend(process.env.RESEND_API_KEY)
const ContactSchema = z.object({ name: z.string().min(1).max(100), email: z.email(), message: z.string().min(1).max(5000) })

// shipcheck-expect: RATE-001
export async function POST(request: Request) {
  const input = ContactSchema.parse(Object.fromEntries(await request.formData()))
  await resend.emails.send({
    from: 'Acme <hello@acme.example>',
    to: 'support@acme.example',
    replyTo: input.email,
    subject: `Contact form: ${input.name}`,
    text: input.message,
  })
  return NextResponse.redirect(new URL('/contact?sent=1', request.url), 303)
}
