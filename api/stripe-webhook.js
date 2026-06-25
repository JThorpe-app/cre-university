// =========================================================
// STRIPE WEBHOOK — grants/revokes entitlements in Supabase
// Runs on Vercel as a serverless function (server-side only).
//
// Flow:
//   checkout.session.completed   -> grant entitlement by customer email
//   customer.subscription.deleted-> revoke the monthly entitlement
//   charge.refunded              -> revoke the purchased entitlement
//
// Secrets come from Vercel env vars (never the browser):
//   STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
// =========================================================

import Stripe from "stripe";
import { createClient } from "@supabase/supabase-js";

// Stripe needs the RAW request body to verify the signature, so we must
// turn OFF Vercel's automatic JSON body parsing for this route.
export const config = { api: { bodyParser: false } };

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Service-role client bypasses RLS — required to write entitlements that
// regular users are not allowed to insert. Never expose this key client-side.
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false, autoRefreshToken: false } },
);

// Amount (in cents) -> product_code fallback, used only when the Stripe Price
// has no `product_code` metadata. Covers the two CRE University prices.
const AMOUNT_TO_PRODUCT = {
  39900: "cre_u_lifetime", // $399 one-time
  4900: "cre_u_monthly", //  $49 / month
};

// Read the raw body as a Buffer so the Stripe signature check sees exact bytes.
async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks);
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const sig = req.headers["stripe-signature"];
  const rawBody = await readRawBody(req);

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      rawBody,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET,
    );
  } catch (err) {
    // Signature mismatch = either the wrong webhook secret (test vs live!)
    // or the raw body was altered. Return 400 so Stripe retries.
    console.error("Webhook signature verification failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case "checkout.session.completed":
        await handleCheckoutCompleted(event.data.object);
        break;
      case "customer.subscription.deleted":
        await handleSubscriptionDeleted(event.data.object);
        break;
      case "charge.refunded":
        await handleRefund(event.data.object);
        break;
      default:
        // Ignore everything else.
        break;
    }
    return res.json({ received: true });
  } catch (err) {
    // Return 500 so Stripe retries delivery (the handlers are idempotent).
    console.error("Webhook handler error:", err);
    return res.status(500).json({ error: err.message });
  }
}

// ---------------------------------------------------------
// checkout.session.completed -> grant entitlement
// ---------------------------------------------------------
async function handleCheckoutCompleted(session) {
  const email = session.customer_details?.email || session.customer_email;
  if (!email) {
    console.error("No email on checkout session", session.id);
    return;
  }

  const productCode = await resolveProductCode(session);
  if (!productCode) {
    console.error(
      "Could not resolve product_code for session",
      session.id,
      "amount_total:",
      session.amount_total,
    );
    return;
  }

  // Find (or create) the Supabase user for this email.
  let user = await findUserByEmail(email);
  if (!user) {
    // Bought before signing up — create a confirmed account with no password.
    // They'll set one via the "forgot password" flow on first visit.
    const { data: created, error: createErr } =
      await supabase.auth.admin.createUser({ email, email_confirm: true });
    if (createErr) {
      // Race: a parallel signup may have created them. Re-fetch before giving up.
      user = await findUserByEmail(email);
      if (!user) {
        console.error("Failed to create user", email, createErr);
        return;
      }
    } else {
      user = created.user;
    }
  }

  const isSubscription = session.mode === "subscription";

  // Idempotent on (user_id, product_code, stripe_session_id) — Stripe may
  // deliver the same event more than once.
  const { error } = await supabase.from("entitlements").upsert(
    {
      user_id: user.id,
      product_code: productCode,
      source: "stripe",
      stripe_session_id: session.id,
      stripe_subscription_id: session.subscription || null,
      status: "active",
      // One-time = no expiry. Subscriptions also stay null here; access is
      // revoked when Stripe sends customer.subscription.deleted at period end.
      expires_at: null,
      metadata: {
        email,
        amount_total: session.amount_total,
        mode: session.mode,
      },
    },
    { onConflict: "user_id,product_code,stripe_session_id" },
  );

  if (error) {
    console.error("Failed to insert entitlement", error);
    throw error; // bubble up so Stripe retries
  }
  console.log(
    `Granted ${productCode} to ${email}${isSubscription ? " (subscription)" : ""}`,
  );
}

// ---------------------------------------------------------
// customer.subscription.deleted -> revoke monthly entitlement
// ---------------------------------------------------------
async function handleSubscriptionDeleted(sub) {
  const { error } = await supabase
    .from("entitlements")
    .update({ status: "revoked" })
    .eq("stripe_subscription_id", sub.id);
  if (error) {
    console.error("Failed to revoke subscription entitlement", sub.id, error);
    throw error;
  }
  console.log(`Revoked entitlement for subscription ${sub.id}`);
}

// ---------------------------------------------------------
// charge.refunded -> revoke the entitlement for that purchase
// ---------------------------------------------------------
async function handleRefund(charge) {
  // Map the charge back to its checkout session via the payment_intent.
  const sessions = await stripe.checkout.sessions.list({
    payment_intent: charge.payment_intent,
    limit: 1,
  });
  const session = sessions.data[0];
  if (!session) {
    console.error("No checkout session for refunded charge", charge.id);
    return;
  }
  const { error } = await supabase
    .from("entitlements")
    .update({ status: "revoked" })
    .eq("stripe_session_id", session.id);
  if (error) {
    console.error("Failed to revoke refunded entitlement", session.id, error);
    throw error;
  }
  console.log(`Revoked entitlement for refunded session ${session.id}`);
}

// ---------------------------------------------------------
// Helpers
// ---------------------------------------------------------

// Resolve product_code: prefer Price/Product metadata (the canonical method),
// then fall back to the purchase amount for the two CRE University prices.
async function resolveProductCode(session) {
  const lineItems = await stripe.checkout.sessions.listLineItems(session.id, {
    expand: ["data.price.product"],
  });
  const price = lineItems.data[0]?.price;
  const fromMeta =
    price?.metadata?.product_code ||
    price?.product?.metadata?.product_code ||
    session.metadata?.product_code;
  if (fromMeta) return fromMeta;

  return AMOUNT_TO_PRODUCT[session.amount_total] || null;
}

// Look up a user by email. supabase.auth.admin.listUsers() is PAGINATED —
// the naive one-call .find() silently misses anyone past the first page, so
// we walk pages until we find them (bounded to avoid an infinite loop).
async function findUserByEmail(email) {
  const target = email.toLowerCase();
  const perPage = 200;
  for (let page = 1; page <= 50; page++) {
    const { data, error } = await supabase.auth.admin.listUsers({
      page,
      perPage,
    });
    if (error) throw error;
    const match = data.users.find((u) => (u.email || "").toLowerCase() === target);
    if (match) return match;
    if (data.users.length < perPage) break; // reached the last page
  }
  return null;
}
