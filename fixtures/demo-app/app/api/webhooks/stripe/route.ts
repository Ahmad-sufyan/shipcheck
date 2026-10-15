import { NextResponse } from 'next/server'
import { pool } from '@/lib/db'

// shipcheck-expect: INTEG-001
export async function POST(request: Request) {
  const event = await request.json()

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object
      await pool.query("update orders set status = 'paid' where stripe_session_id = $1", [session.id])
      break
    }
    case 'customer.subscription.deleted':
      await pool.query('delete from subscriptions where stripe_subscription_id = $1', [event.data.object.id])
      break
  }

  return NextResponse.json({ received: true })
}
