import PaymentRecharge from "../payment/recharge";

/**
 * /account/recharge — standalone recharge page (R4 / account-center).
 *
 * Reuses the full recharge form + payment flow from /payment/recharge so the
 * two routes never drift. The shared page already guards on auth (redirects
 * unauthenticated users to /login) and links back to /dashboard?tab=account.
 */
export default PaymentRecharge;