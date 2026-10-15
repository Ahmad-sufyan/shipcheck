import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // shipcheck-expect: AUTHZ-003
  const { data: invoice } = await supabase.from('invoices').select('*').eq('id', id).single()
  if (!invoice) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }
  // shipcheck-expect: DATA-002
  return NextResponse.json(invoice)
}
