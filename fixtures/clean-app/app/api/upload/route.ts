import { randomUUID } from 'node:crypto'
import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'

const MAX_BYTES = 5 * 1024 * 1024
const EXTENSIONS: Record<string, string> = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp' }

export async function POST(request: Request) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const form = await request.formData()
  const file = form.get('file')
  if (!(file instanceof File)) {
    return NextResponse.json({ error: 'No file' }, { status: 400 })
  }
  const extension = EXTENSIONS[file.type]
  if (!extension) {
    return NextResponse.json({ error: 'Only PNG, JPEG and WebP images are allowed' }, { status: 415 })
  }
  if (file.size > MAX_BYTES) {
    return NextResponse.json({ error: 'File too large' }, { status: 413 })
  }

  const objectPath = `${user.id}/${randomUUID()}.${extension}`
  const { error } = await supabase.storage.from('uploads').upload(objectPath, file, { contentType: file.type, upsert: false })
  if (error) {
    return NextResponse.json({ error: 'Upload failed' }, { status: 500 })
  }
  return NextResponse.json({ path: objectPath }, { status: 201 })
}
