import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'

export async function GET() {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const { data: caller } = await supabase.from('profiles').select('role').eq('id', user.id).single()
  if (caller?.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  const { count: users } = await supabase.from('profiles').select('*', { count: 'exact', head: true })
  const { data: invoices } = await supabase.from('invoices').select('amount_cents')
  const revenueCents = (invoices ?? []).reduce((sum, invoice) => sum + invoice.amount_cents, 0)

  return NextResponse.json({ users: users ?? 0, revenueCents })
}
