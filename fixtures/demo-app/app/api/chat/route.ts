import OpenAI from 'openai'
import { NextResponse } from 'next/server'
import { z } from 'zod'
import { createClient } from '@/lib/supabase/server'

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
const ChatSchema = z.object({ message: z.string().min(1).max(4000), persona: z.string().max(200) })

// shipcheck-expect: RATE-002
export async function POST(request: Request) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const { message, persona } = ChatSchema.parse(await request.json())
  const completion = await openai.chat.completions.create({
    model: 'gpt-4.1-mini',
    messages: [
      // shipcheck-expect: INTEG-005
      { role: 'system', content: `You are the Acme billing assistant. Answer in the voice of ${persona}.` },
      { role: 'user', content: message },
    ],
  })

  return NextResponse.json({ reply: completion.choices[0]?.message.content ?? '' })
}
