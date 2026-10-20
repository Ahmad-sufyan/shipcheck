import 'server-only'
import { stripe } from '@/lib/stripe'

export { PLANS } from '@/lib/plans'

export async function listInvoices(customerId: string) {
  return stripe.invoices.list({ customer: customerId, limit: 10 })
}
