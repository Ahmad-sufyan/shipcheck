import { z } from 'zod'

export const Greeting = z.object({ name: z.string().min(1) })
