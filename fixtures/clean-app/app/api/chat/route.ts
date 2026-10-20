import OpenAI from 'openai'
import { NextResponse } from 'next/server'
import { z } from 'zod'
import { pool } from '@/lib/db'
import { rateLimit } from '@/lib/rate-limit'
import { createClient } from '@/lib/supabase/server'

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
const ChatSchema = z.object({ message: z.string().min(1).max(4000), tone: z.enum(['friendly', 'formal']) })
const SYSTEM_PROMPTS = {
  friendly: 'You are the Acme billing assistant. Answer warmly and briefly.',
  formal: 'You are the Acme billing assistant. Answer formally and briefly.',
} as const
const DAILY_TOKEN_QUOTA = 50_000

export async function POST(request: Request) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  if (!(await rateLimit(`chat:${user.id}`))) {
    return NextResponse.json({ error: 'Too many requests' }, { status: 429 })
  }
  const { rows } = await pool.query('select coalesce(sum(tokens), 0) as used from ai_usage where user_id = $1 and created_at > now() - interval \'1 day\'', [user.id])
  if (Number(rows[0]?.used ?? 0) >= DAILY_TOKEN_QUOTA) {
    return NextResponse.json({ error: 'Daily quota reached' }, { status: 429 })
  }

  const parsed = ChatSchema.safeParse(await request.json())
  if (!parsed.success) {
    return NextResponse.json({ error: 'Invalid message' }, { status: 400 })
  }
  const completion = await openai.chat.completions.create({
    model: 'gpt-4.1-mini',
    max_tokens: 800,
    messages: [
      { role: 'system', content: SYSTEM_PROMPTS[parsed.data.tone] },
      { role: 'user', content: parsed.data.message },
    ],
  })
  await pool.query('insert into ai_usage (user_id, tokens) values ($1, $2)', [user.id, completion.usage?.total_tokens ?? 0])

  return NextResponse.json({ reply: completion.choices[0]?.message.content ?? '' })
}
