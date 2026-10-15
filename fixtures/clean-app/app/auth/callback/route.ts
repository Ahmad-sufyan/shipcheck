import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'

/** Only same-origin relative paths are allowed as post-login destinations. */
function safeNextPath(value: string | null): string {
  if (!value || !value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return '/dashboard'
  return value
}

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url)
  const code = searchParams.get('code')

  if (code) {
    const supabase = await createClient()
    await supabase.auth.exchangeCodeForSession(code)
  }

  const destination = new URL(safeNextPath(searchParams.get('redirectTo')), origin)
  if (destination.origin !== origin) {
    return NextResponse.redirect(new URL('/dashboard', origin))
  }
  return NextResponse.redirect(destination)
}
