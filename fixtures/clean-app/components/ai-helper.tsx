'use client'

import { useState } from 'react'

/** Talks to /api/chat; the model and its API key stay on the server. */
export function AiHelper() {
  const [answer, setAnswer] = useState('')

  async function ask(message: string) {
    const response = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message, tone: 'friendly' }),
    })
    const data = (await response.json()) as { reply?: string }
    setAnswer(data.reply ?? '')
  }

  return (
    <div>
      <button onClick={() => ask('Summarise my invoices')}>Ask</button>
      <p>{answer}</p>
    </div>
  )
}
