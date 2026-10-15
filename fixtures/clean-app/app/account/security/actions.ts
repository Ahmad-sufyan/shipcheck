'use server'

import { z } from 'zod'
import { createClient } from '@/lib/supabase/server'

const VerifySchema = z.object({ factorId: z.string().min(1), code: z.string().regex(/^\d{6}$/) })

/** Starts TOTP enrollment for the signed-in user and returns the QR code to scan. */
export async function enrollTotp() {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) throw new Error('Unauthorized')

  const { data, error } = await supabase.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'Authenticator app' })
  if (error) throw new Error('Could not start MFA enrollment')
  return { factorId: data.id, qrCode: data.totp.qr_code }
}

/** Verifies the first TOTP code to finish enrollment. */
export async function verifyTotp(input: { factorId: string; code: string }) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) throw new Error('Unauthorized')
  const parsed = VerifySchema.safeParse(input)
  if (!parsed.success) throw new Error('Invalid code')

  const { error } = await supabase.auth.mfa.challengeAndVerify(parsed.data)
  if (error) throw new Error('Invalid code')
  return { ok: true }
}
