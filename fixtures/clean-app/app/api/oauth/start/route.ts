import { createHash, randomBytes } from 'node:crypto'
import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'

export async function GET() {
  const state = randomBytes(32).toString('base64url')
  const codeVerifier = randomBytes(32).toString('base64url')
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

  const cookieStore = await cookies()
  const cookieOptions = { httpOnly: true, secure: true, sameSite: 'lax' as const, path: '/api/oauth', maxAge: 600 }
  cookieStore.set('oauth_state', state, cookieOptions)
  cookieStore.set('oauth_verifier', codeVerifier, cookieOptions)

  const authorizeUrl = new URL('https://github.com/login/oauth/authorize')
  authorizeUrl.searchParams.set('client_id', process.env.GITHUB_CLIENT_ID!)
  authorizeUrl.searchParams.set('redirect_uri', `${process.env.NEXT_PUBLIC_SITE_URL}/api/oauth/callback`)
  authorizeUrl.searchParams.set('scope', 'read:user')
  authorizeUrl.searchParams.set('state', state)
  authorizeUrl.searchParams.set('code_challenge', codeChallenge)
  authorizeUrl.searchParams.set('code_challenge_method', 'S256')
  return NextResponse.redirect(authorizeUrl)
}
