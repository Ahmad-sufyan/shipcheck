import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse, type NextRequest } from 'next/server'

const IMAGE_NAME = /^[a-z0-9-]{1,64}\.(?:png|jpg|jpeg|webp)$/

export async function GET(request: NextRequest) {
  const image = request.nextUrl.searchParams.get('image') ?? ''
  if (!IMAGE_NAME.test(image)) {
    return NextResponse.json({ error: 'Invalid image name' }, { status: 400 })
  }

  const source = path.join(process.cwd(), 'public', 'images', image)
  await new Promise<void>((resolve, reject) => {
    execFile('convert', [source, '-thumbnail', '200x200', '/tmp/thumbnail.png'], (error) => (error ? reject(error) : resolve()))
  })

  const thumbnail = await readFile('/tmp/thumbnail.png')
  return new NextResponse(thumbnail, { headers: { 'content-type': 'image/png' } })
}
