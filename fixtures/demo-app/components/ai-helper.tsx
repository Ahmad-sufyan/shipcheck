'use client'

import { useState } from 'react'
import OpenAI from 'openai'

// shipcheck-expect: INTEG-004
const openai = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true })

export function AiHelper() {
  const [answer, setAnswer] = useState('')

  async function ask(question: string) {
    const completion = await openai.chat.completions.create({ model: 'gpt-4.1-mini', messages: [{ role: 'user', content: question }] })
    setAnswer(completion.choices[0]?.message.content ?? '')
  }

  return (
    <div>
      <button onClick={() => ask('Summarise my invoices')}>Ask</button>
      <p>{answer}</p>
    </div>
  )
}
