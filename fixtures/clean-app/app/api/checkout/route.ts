import { NextResponse } from 'next/server'
import { z } from 'zod'
import { stripe } from '@/lib/stripe'
import { createClient } from '@/lib/supabase/server'

/** Prices live on the server; the client only names a plan. */
const PRICE_IDS = { starter: 'price_starter_monthly', pro: 'price_pro_monthly' } as const
const CheckoutSchema = z.object({ plan: z.enum(['starter', 'pro']), seats: z.number().int().min(1).max(50) })

export async function POST(request: Request) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const parsed = CheckoutSchema.safeParse(await request.json())
  if (!parsed.success) {
    return NextResponse.json({ error: 'Invalid checkout request' }, { status: 400 })
  }
  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    customer_email: user.email,
    line_items: [{ price: PRICE_IDS[parsed.data.plan], quantity: parsed.data.seats }],
    success_url: `${process.env.NEXT_PUBLIC_SITE_URL}/checkout/success`,
    cancel_url: `${process.env.NEXT_PUBLIC_SITE_URL}/pricing`,
  })

  return NextResponse.json({ url: session.url })
}
