import { exec } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { NextResponse, type NextRequest } from 'next/server'

export async function GET(request: NextRequest) {
  const image = request.nextUrl.searchParams.get('image') ?? ''

  await new Promise<void>((resolve, reject) => {
    // shipcheck-expect: INPUT-005
    exec(`convert public/images/${image} -thumbnail 200x200 /tmp/thumbnail.png`, (error) => (error ? reject(error) : resolve()))
  })

  const thumbnail = await readFile('/tmp/thumbnail.png')
  return new NextResponse(thumbnail, { headers: { 'content-type': 'image/png' } })
}
