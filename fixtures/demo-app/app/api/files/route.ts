import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse, type NextRequest } from 'next/server'
import { createClient } from '@/lib/supabase/server'

const base = path.join(process.cwd(), 'storage', 'exports')

export async function GET(request: NextRequest) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const name = request.nextUrl.searchParams.get('name') ?? ''
  // shipcheck-expect: INPUT-006
  const file = await readFile(path.join(base, name))
  return new NextResponse(file, { headers: { 'content-type': 'application/octet-stream' } })
}
