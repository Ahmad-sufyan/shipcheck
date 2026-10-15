import { NextResponse } from 'next/server'

export async function GET() {
  const clientId = process.env.GITHUB_CLIENT_ID!
  const redirectUri = `${process.env.NEXT_PUBLIC_SITE_URL}/api/oauth/callback`
  // shipcheck-expect: AUTH-008
  const authorizeUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=read:user`
  return NextResponse.redirect(authorizeUrl)
}
