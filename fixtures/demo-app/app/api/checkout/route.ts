import { NextResponse } from 'next/server'
import { stripe } from '@/lib/stripe'
import { createClient } from '@/lib/supabase/server'

export async function POST(request: Request) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // shipcheck-expect: INPUT-010
  const body = await request.json()
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    customer_email: user.email,
    line_items: [
      {
        price_data: {
          currency: 'usd',
          product_data: { name: 'Acme Pro' },
          // shipcheck-expect: INTEG-003
          unit_amount: body.amount,
        },
        quantity: body.quantity,
      },
    ],
    success_url: `${process.env.NEXT_PUBLIC_SITE_URL}/checkout/success`,
    cancel_url: `${process.env.NEXT_PUBLIC_SITE_URL}/pricing`,
  })

  return NextResponse.json({ url: session.url })
}
