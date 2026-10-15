import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'

export async function POST() {
  const cookieStore = await cookies()
  // shipcheck-expect: AUTH-013
  cookieStore.delete('session')
  return NextResponse.json({ ok: true })
}
