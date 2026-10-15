import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse, type NextRequest } from 'next/server'
import { createClient } from '@/lib/supabase/server'

const base = path.resolve(process.cwd(), 'storage', 'exports')

export async function GET(request: NextRequest) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const name = request.nextUrl.searchParams.get('name') ?? ''
  const target = path.resolve(base, user.id, path.normalize(name))
  if (!target.startsWith(base + path.sep)) {
    return NextResponse.json({ error: 'Invalid file name' }, { status: 400 })
  }
  const file = await readFile(target)
  return new NextResponse(file, { headers: { 'content-type': 'application/octet-stream' } })
}
