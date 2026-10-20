import Stripe from 'stripe'

// shipcheck-expect: SECRET-004
export const stripe = new Stripe('sk_test_FAKEFAKEFAKEFAKEFAKEFAKE00')
