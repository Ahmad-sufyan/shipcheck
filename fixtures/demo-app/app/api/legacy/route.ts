import { NextResponse } from 'next/server'
import { getCollection } from '@/lib/mongo'
import { createClient } from '@/lib/supabase/server'

export async function POST(request: Request) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const body = await request.json()
  const orders = await getCollection('orders')
  // shipcheck-expect: INPUT-002
  const results = await orders.find(body).limit(50).toArray()
  return NextResponse.json(results)
}
