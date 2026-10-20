'use client'

import { useState } from 'react'
import { PLANS } from '@/lib/plans'

export function PricingClient() {
  const [selected, setSelected] = useState<string>(PLANS[0].id)
  return (
    <ul>
      {PLANS.map((plan) => (
        <li key={plan.id}>
          <button type="button" aria-pressed={selected === plan.id} onClick={() => setSelected(plan.id)}>
            {plan.name}: ${(plan.priceCents / 100).toFixed(2)} per month
          </button>
        </li>
      ))}
    </ul>
  )
}
