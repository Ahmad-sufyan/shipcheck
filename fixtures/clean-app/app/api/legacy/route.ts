import { NextResponse } from 'next/server'
import { z } from 'zod'
import { getCollection } from '@/lib/mongo'
import { createClient } from '@/lib/supabase/server'

const OrderFilterSchema = z.object({
  status: z.enum(['pending', 'paid', 'refunded']).optional(),
})

export async function POST(request: Request) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const parsed = OrderFilterSchema.safeParse(await request.json())
  if (!parsed.success) {
    return NextResponse.json({ error: 'Invalid filter' }, { status: 400 })
  }
  const filter = parsed.data.status ? { userId: user.id, status: parsed.data.status } : { userId: user.id }
  const orders = await getCollection('orders')
  const results = await orders.find(filter).limit(50).toArray()
  return NextResponse.json(results)
}
