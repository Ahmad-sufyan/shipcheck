import { randomUUID } from 'node:crypto'
import { writeFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'

export async function POST(request: Request) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const form = await request.formData()
  const file = form.get('file') as File
  const filename = `${randomUUID()}${path.extname(file.name)}`
  const bytes = Buffer.from(await file.arrayBuffer())
  // shipcheck-expect: INPUT-009
  await writeFile(path.join(process.cwd(), 'public', 'uploads', filename), bytes)

  return NextResponse.json({ url: `/uploads/${filename}` }, { status: 201 })
}
