import 'server-only'
import { z } from 'zod'

const EnvSchema = z.object({
  NEXT_PUBLIC_SUPABASE_URL: z.url(),
  NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string().min(1),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),
  STRIPE_SECRET_KEY: z.string().startsWith('sk_'),
  DATABASE_URL: z.url(),
})

/** Fails the server start with a clear message when a variable is missing or malformed. */
export const env = EnvSchema.parse(process.env)
