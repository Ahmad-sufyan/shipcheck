import type Stripe from 'stripe'
import { NextResponse } from 'next/server'
import { pool } from '@/lib/db'
import { stripe } from '@/lib/stripe'

export async function POST(request: Request) {
  const payload = await request.text()
  const signature = request.headers.get('stripe-signature') ?? ''

  let event: Stripe.Event
  try {
    event = stripe.webhooks.constructEvent(payload, signature, process.env.STRIPE_WEBHOOK_SECRET!)
  } catch {
    return NextResponse.json({ error: 'Invalid signature' }, { status: 400 })
  }

  if (event.type === 'checkout.session.completed') {
    await pool.query("update orders set status = 'paid' where stripe_session_id = $1", [event.data.object.id])
  }
  return NextResponse.json({ received: true })
}
