# CRE University + Deal Analyzer — Auth & Payment Implementation Spec

**For execution by Claude Code in the user's local environment.**

## Context

User (Jimmy / JThorpe) has 4 existing HTML/React single-file products deployed via Vercel:

1. **CRE University** — `cre-university.vercel.app` — gamified CRE investing education
2. **Deal Analyzer A** — Quick screening calculator (currently free, will require email signup)
3. **Deal Analyzer B** — Multi-year underwriter ($79 one-time)
4. **Deal Analyzer C** — Pro suite with GP/LP, capex, tax, sensitivity ($299 one-time)

**Current state:** All products are client-side only. No auth. localStorage for persistence. No way to enforce paywall — anyone with the URL can use anything.

**Goal:** Lock everything behind real auth (email + password) with server-validated entitlements. Stripe handles payment. Supabase stores users, entitlements, and progress data.

**Constraints:**
- User is non-technical — explain every step
- User deploys via GitHub → Vercel
- User has Supabase account and Stripe account set up
- Stripe products + prices already exist in user's Stripe dashboard (user will provide product IDs)

---

## Architecture overview

```
┌─────────────────────────────────────────────────────────┐
│  Browser (one of the 4 HTML files)                       │
│  - Loads Supabase JS client                              │
│  - Checks session on load                                │
│  - Shows login modal if no session                       │
│  - Checks entitlement for this product_code              │
│  - Shows "buy this" CTA if no entitlement                │
└────────────────┬────────────────────────────────────────┘
                 │
                 │ HTTPS
                 ▼
┌─────────────────────────────────────────────────────────┐
│  Supabase                                                │
│  - auth.users (managed)                                  │
│  - public.entitlements                                   │
│  - public.progress (jsonb per product per user)          │
│  - RLS policies: users only access their own rows        │
└─────────────────────────────────────────────────────────┘
                 ▲
                 │ Service role key (server-side only)
                 │
┌─────────────────────────────────────────────────────────┐
│  Vercel Serverless: /api/stripe-webhook                  │
│  - Receives Stripe checkout.session.completed            │
│  - Validates signature                                   │
│  - Looks up user by customer email                       │
│  - Inserts row in entitlements table                     │
│  - Handles refunds (revokes entitlement)                 │
└────────────────▲────────────────────────────────────────┘
                 │
                 │ Stripe webhook
                 │
┌─────────────────────────────────────────────────────────┐
│  Stripe (existing — user already has products set up)    │
│  - Checkout sessions for each product                    │
│  - Customer portal for subscription management           │
└─────────────────────────────────────────────────────────┘
```

---

## Product codes (use exactly these strings)

These are the canonical identifiers used in Supabase, in the HTML files, and in Stripe webhook metadata.

| Product | `product_code` | Type |
|---|---|---|
| CRE University Lifetime | `cre_u_lifetime` | one-time |
| CRE University Monthly | `cre_u_monthly` | subscription |
| Deal Analyzer A (free w/ email) | `da_a` | free (granted at signup) |
| Deal Analyzer B | `da_b` | one-time |
| Deal Analyzer C | `da_c` | one-time |

**Important:** When the user adds Stripe products to the webhook config, each Stripe `price_id` must map to one of these `product_code` values. User must provide that mapping.

---

# STEP 0 — Information Jimmy needs to provide

Before any code runs, Jimmy needs to gather:

## From Supabase
1. **Supabase project URL** (looks like `https://xxxxx.supabase.co`)
2. **Supabase anon/public key** (`eyJ...` — safe to put in browser)
3. **Supabase service role key** (`eyJ...` — SECRET, used by webhook only)

Where to find: Supabase dashboard → Project Settings → API

## From Stripe
4. **Stripe publishable key** (`pk_live_...` or `pk_test_...`)
5. **Stripe secret key** (`sk_live_...` or `sk_test_...` — SECRET, used by webhook only)
6. **Stripe webhook signing secret** (`whsec_...` — generated AFTER we deploy the webhook URL in Step 5)
7. **The 4 Stripe price IDs** (look like `price_1A2b3C4d5E6f...`) and which one maps to which `product_code` from the table above

Where to find: Stripe dashboard → Developers → API keys, and Products page for price IDs

## From Vercel
8. Confirm which Vercel project each product is deployed to (all 4 in one project? Or separate projects?)

> **IMPORTANT — DO NOT PROCEED past Step 0 without these.** If Jimmy doesn't have them yet, walk him through getting each one before touching code.

---

# STEP 1 — Supabase database schema

Open the Supabase SQL Editor and run the following migration. Explain to Jimmy what each table does.

```sql
-- =================================================================
-- 1. ENTITLEMENTS TABLE
-- Tracks which products each user has access to.
-- =================================================================
create table if not exists public.entitlements (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade not null,
  product_code text not null,
  granted_at timestamptz default now() not null,
  expires_at timestamptz, -- null = lifetime, set for monthly subs
  source text not null check (source in ('stripe', 'manual', 'free_signup')),
  stripe_session_id text, -- for audit / refund handling
  stripe_subscription_id text, -- for subs only
  status text not null default 'active' check (status in ('active', 'revoked', 'expired')),
  metadata jsonb default '{}'::jsonb,
  unique(user_id, product_code, stripe_session_id)
);

create index if not exists entitlements_user_product_idx 
  on public.entitlements(user_id, product_code) 
  where status = 'active';

create index if not exists entitlements_stripe_session_idx 
  on public.entitlements(stripe_session_id);

-- =================================================================
-- 2. PROGRESS TABLE
-- Per-user, per-product state. Replaces localStorage in CRE U.
-- One row per (user, product). data is a jsonb blob.
-- =================================================================
create table if not exists public.progress (
  user_id uuid references auth.users(id) on delete cascade not null,
  product_code text not null,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz default now() not null,
  primary key (user_id, product_code)
);

-- =================================================================
-- 3. ROW LEVEL SECURITY
-- Critical: without these, users could read everyone's data.
-- =================================================================
alter table public.entitlements enable row level security;
alter table public.progress enable row level security;

-- Users can read their own entitlements
create policy "Users read own entitlements"
  on public.entitlements for select
  using (auth.uid() = user_id);

-- Users CANNOT insert/update entitlements directly (only webhook can, via service role)
-- (No insert/update/delete policy for regular users — service role bypasses RLS)

-- Users can read/write their own progress
create policy "Users read own progress"
  on public.progress for select
  using (auth.uid() = user_id);

create policy "Users insert own progress"
  on public.progress for insert
  with check (auth.uid() = user_id);

create policy "Users update own progress"
  on public.progress for update
  using (auth.uid() = user_id);

-- =================================================================
-- 4. AUTO-GRANT FREE TIER ON SIGNUP
-- When a user signs up, they automatically get da_a entitlement.
-- =================================================================
create or replace function public.handle_new_user()
returns trigger 
language plpgsql 
security definer 
set search_path = public
as $$
begin
  insert into public.entitlements (user_id, product_code, source, status)
  values (new.id, 'da_a', 'free_signup', 'active')
  on conflict do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- =================================================================
-- 5. HELPER VIEW FOR CHECKING ENTITLEMENT
-- =================================================================
create or replace view public.my_active_entitlements as
select product_code, granted_at, expires_at, source
from public.entitlements
where user_id = auth.uid()
  and status = 'active'
  and (expires_at is null or expires_at > now());
```

After running, verify in Supabase Table Editor that both tables exist and RLS is enabled.

---

# STEP 2 — Supabase Auth configuration

In Supabase dashboard:

1. Go to **Authentication → Providers**
2. Make sure **Email** provider is enabled
3. Toggle ON: "Enable email confirmations" (so spam signups don't pollute the DB)
4. Go to **Authentication → URL Configuration**
5. Add to "Site URL": Jimmy's main domain (e.g., `https://cre-university.vercel.app`)
6. Add to "Redirect URLs":
   - `https://cre-university.vercel.app/**`
   - And the URLs for each Deal Analyzer if hosted separately
7. Go to **Authentication → Email Templates**
8. Customize the "Confirm signup" email — change branding to CRE University

---

# STEP 3 — Shared auth library (`auth.js`)

Create a single shared JS file all four HTML products will load via CDN-style include. Host it in the same Vercel project (or a separate `/public/` folder if using monorepo).

**File: `auth.js`** (place in same directory as the HTML files)

```javascript
// Shared auth + entitlement library for all CRE U / Deal Analyzer products
// Loads Supabase, manages session, exposes window.CREAuth API

(function() {
  // SUPABASE_URL and SUPABASE_ANON_KEY are public — safe to expose
  // Jimmy: replace these with your actual values
  const SUPABASE_URL = "https://YOUR_PROJECT.supabase.co";
  const SUPABASE_ANON_KEY = "YOUR_ANON_KEY";

  // Load Supabase JS client from CDN
  const supabaseScript = document.createElement("script");
  supabaseScript.src = "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2";
  document.head.appendChild(supabaseScript);

  supabaseScript.onload = () => {
    const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
    
    window.CREAuth = {
      supabase,

      async getSession() {
        const { data } = await supabase.auth.getSession();
        return data.session;
      },

      async getUser() {
        const { data } = await supabase.auth.getUser();
        return data.user;
      },

      async signUp(email, password) {
        const { data, error } = await supabase.auth.signUp({ email, password });
        return { data, error };
      },

      async signIn(email, password) {
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        return { data, error };
      },

      async signOut() {
        await supabase.auth.signOut();
        window.location.reload();
      },

      async resetPassword(email) {
        const { data, error } = await supabase.auth.resetPasswordForEmail(email, {
          redirectTo: window.location.origin + "/reset-password.html"
        });
        return { data, error };
      },

      async hasEntitlement(productCode) {
        const session = await this.getSession();
        if (!session) return false;
        const { data, error } = await supabase
          .from("my_active_entitlements")
          .select("product_code")
          .eq("product_code", productCode)
          .maybeSingle();
        return !error && !!data;
      },

      async loadProgress(productCode) {
        const session = await this.getSession();
        if (!session) return null;
        const { data } = await supabase
          .from("progress")
          .select("data")
          .eq("product_code", productCode)
          .maybeSingle();
        return data ? data.data : null;
      },

      async saveProgress(productCode, progressData) {
        const session = await this.getSession();
        if (!session) return false;
        const { error } = await supabase
          .from("progress")
          .upsert({
            user_id: session.user.id,
            product_code: productCode,
            data: progressData,
            updated_at: new Date().toISOString()
          });
        return !error;
      },

      onAuthStateChange(callback) {
        return supabase.auth.onAuthStateChange(callback);
      }
    };

    // Fire ready event
    document.dispatchEvent(new Event("creauth:ready"));
  };
})();
```

---

# STEP 4 — Auth gate modal (HTML/CSS/JS to inject into each product)

Each of the 4 HTML files needs the same gate UI bolted on. We'll add it as a React component that wraps the existing app.

**Conceptual flow:**

```
On app load:
  1. Show loading state while CREAuth initializes
  2. Check session
     - No session → show LOGIN/SIGNUP screen
     - Has session → check entitlement for THIS product
       - Has entitlement → show app
       - No entitlement → show BUY screen with CTA to Stripe Checkout
```

**Each HTML file needs:**
- A `<script src="./auth.js"></script>` tag added in the `<head>`
- A `PRODUCT_CODE` constant declared near the top of the React code:
  - `cre-university` HTML: depends on which tier the user has → check for `cre_u_lifetime` OR `cre_u_monthly`
  - `deal-analyzer.html` (A): check for `da_a`
  - `deal-analyzer-b.html`: check for `da_b`
  - `deal-analyzer-c.html`: check for `da_c`

**Stripe checkout links** (Jimmy provides these from his Stripe dashboard — they are Payment Links, the simplest path):

```javascript
const STRIPE_LINKS = {
  cre_u_lifetime: "https://buy.stripe.com/XXX_lifetime_link",
  cre_u_monthly:  "https://buy.stripe.com/XXX_monthly_link",
  da_b:           "https://buy.stripe.com/XXX_da_b_link",
  da_c:           "https://buy.stripe.com/XXX_da_c_link",
};
```

**CRITICAL:** When Jimmy creates the Stripe Payment Links, he MUST enable "Collect customer email" AND add the `product_code` as metadata on the Price (in the Stripe dashboard, edit the Price → add metadata key `product_code` with value matching the table in this spec). The webhook uses this metadata to know what to grant.

**React wrapper component (add to each HTML file just inside the App component):**

```jsx
function AuthGate({ productCode, stripeLink, productName, children }) {
  const [status, setStatus] = React.useState("loading"); // loading | locked | nosub | ready
  const [user, setUser] = React.useState(null);
  const [mode, setMode] = React.useState("signin"); // signin | signup | forgot
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState("");
  const [info, setInfo] = React.useState("");

  React.useEffect(() => {
    const init = async () => {
      // Wait for CREAuth to be ready
      if (!window.CREAuth) {
        await new Promise(r => document.addEventListener("creauth:ready", r, { once: true }));
      }
      
      const session = await window.CREAuth.getSession();
      if (!session) { setStatus("locked"); return; }
      
      setUser(session.user);
      
      // Special case for CRE U: check either lifetime OR monthly
      if (productCode === "cre_u_any") {
        const hasLife = await window.CREAuth.hasEntitlement("cre_u_lifetime");
        const hasMo = await window.CREAuth.hasEntitlement("cre_u_monthly");
        setStatus(hasLife || hasMo ? "ready" : "nosub");
        return;
      }
      
      const hasEnt = await window.CREAuth.hasEntitlement(productCode);
      setStatus(hasEnt ? "ready" : "nosub");
    };
    
    init();
    
    // Listen for auth state changes
    if (window.CREAuth) {
      const { data: { subscription } } = window.CREAuth.onAuthStateChange(() => init());
      return () => subscription.unsubscribe();
    }
  }, [productCode]);

  const handleSubmit = async (e) => {
    e?.preventDefault();
    setError("");
    setInfo("");
    
    if (mode === "signin") {
      const { error } = await window.CREAuth.signIn(email, password);
      if (error) setError(error.message);
    } else if (mode === "signup") {
      const { error } = await window.CREAuth.signUp(email, password);
      if (error) setError(error.message);
      else setInfo("Check your email to confirm your account.");
    } else if (mode === "forgot") {
      const { error } = await window.CREAuth.resetPassword(email);
      if (error) setError(error.message);
      else setInfo("Password reset link sent. Check your email.");
    }
  };

  if (status === "loading") {
    return <div className="min-h-screen flex items-center justify-center text-[14px]" style={{color: "var(--muted)"}}>Loading...</div>;
  }

  if (status === "locked") {
    return (
      <div className="min-h-screen flex items-center justify-center p-4" style={{background: "#E6DFD1"}}>
        <div className="w-full max-w-[420px] card-hi p-6">
          <div className="font-display text-[28px] mb-2" style={{fontWeight: 700}}>
            {mode === "signin" ? "Sign in" : mode === "signup" ? "Create account" : "Reset password"}
          </div>
          <p className="text-[13px] mb-5" style={{color: "var(--muted)"}}>
            {mode === "signin" ? "Welcome back." : mode === "signup" ? "Get started — Deal Analyzer A is included free with signup." : "Enter your email and we'll send a reset link."}
          </p>
          
          <form onSubmit={handleSubmit}>
            <input type="email" placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} required
              className="w-full px-3 py-2.5 mb-3 text-[14px] rounded-lg"
              style={{background: "var(--bg-card)", border: "1px solid var(--border)", color: "var(--text)"}}/>
            {mode !== "forgot" && (
              <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} required minLength={6}
                className="w-full px-3 py-2.5 mb-3 text-[14px] rounded-lg"
                style={{background: "var(--bg-card)", border: "1px solid var(--border)", color: "var(--text)"}}/>
            )}
            {error && <div className="text-[12.5px] mb-3 p-2.5 rounded-lg" style={{background: "rgba(220,38,38,0.08)", color: "var(--danger)"}}>{error}</div>}
            {info && <div className="text-[12.5px] mb-3 p-2.5 rounded-lg" style={{background: "rgba(0,169,104,0.08)", color: "var(--accent)"}}>{info}</div>}
            
            <button type="submit" className="w-full py-3 text-[13.5px] uppercase tracking-wider font-bold rounded-xl"
              style={{background: "var(--accent)", color: "#FFF"}}>
              {mode === "signin" ? "Sign in" : mode === "signup" ? "Create account" : "Send reset link"}
            </button>
          </form>
          
          <div className="mt-4 text-[12px] text-center" style={{color: "var(--muted)"}}>
            {mode === "signin" && (
              <>
                <button onClick={() => { setMode("signup"); setError(""); setInfo(""); }} className="underline">Create account</button>
                {" · "}
                <button onClick={() => { setMode("forgot"); setError(""); setInfo(""); }} className="underline">Forgot password</button>
              </>
            )}
            {mode === "signup" && (
              <button onClick={() => { setMode("signin"); setError(""); setInfo(""); }} className="underline">Have an account? Sign in</button>
            )}
            {mode === "forgot" && (
              <button onClick={() => { setMode("signin"); setError(""); setInfo(""); }} className="underline">Back to sign in</button>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (status === "nosub") {
    return (
      <div className="min-h-screen flex items-center justify-center p-4" style={{background: "#E6DFD1"}}>
        <div className="w-full max-w-[460px] card-hi p-6 text-center">
          <div className="font-display text-[28px] mb-2" style={{fontWeight: 700}}>
            Unlock {productName}
          </div>
          <p className="text-[13.5px] mb-5" style={{color: "var(--muted)", lineHeight: 1.55}}>
            You're signed in as <b>{user?.email}</b> but don't have access to this product yet. Complete checkout below and you'll be back in seconds.
          </p>
          
          <a href={stripeLink + "?prefilled_email=" + encodeURIComponent(user?.email || "")}
             className="block w-full py-3.5 text-[13.5px] uppercase tracking-wider font-bold rounded-xl mb-3"
             style={{background: "linear-gradient(135deg, var(--gold), var(--gold-2))", color: "#3A2700", boxShadow: "0 4px 0 #A77517"}}>
            Buy now
          </a>
          
          <button onClick={() => window.CREAuth.signOut()} className="text-[12px] underline" style={{color: "var(--muted)"}}>
            Sign out
          </button>
        </div>
      </div>
    );
  }

  return children;
}
```

**Then wrap the existing top-level App component:**

```jsx
// At top of script:
const PRODUCT_CODE = "da_b"; // or "da_c", or "da_a", or "cre_u_any"
const PRODUCT_NAME = "Deal Analyzer · Underwriter";
const STRIPE_LINK = "https://buy.stripe.com/XXX"; // from Jimmy's Stripe dashboard

// Wrap the existing App:
function GatedApp() {
  return (
    <AuthGate productCode={PRODUCT_CODE} stripeLink={STRIPE_LINK} productName={PRODUCT_NAME}>
      <App />
    </AuthGate>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<GatedApp />);
```

---

# STEP 5 — Stripe webhook (Vercel serverless function)

Create file: `api/stripe-webhook.js` in the Vercel project root.

```javascript
// Stripe webhook handler
// Receives checkout.session.completed and grants entitlements in Supabase

import Stripe from "stripe";
import { createClient } from "@supabase/supabase-js";

// Disable Vercel's default body parsing — we need raw body for Stripe signature
export const config = { api: { bodyParser: false } };

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

// Helper to read raw body
async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
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
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error("Webhook signature verification failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        await handleCheckoutCompleted(session);
        break;
      }
      case "customer.subscription.deleted": {
        const sub = event.data.object;
        await handleSubscriptionDeleted(sub);
        break;
      }
      case "charge.refunded": {
        const charge = event.data.object;
        await handleRefund(charge);
        break;
      }
      default:
        // Ignore other events
        break;
    }
    return res.json({ received: true });
  } catch (err) {
    console.error("Webhook handler error:", err);
    return res.status(500).json({ error: err.message });
  }
}

async function handleCheckoutCompleted(session) {
  const email = session.customer_details?.email || session.customer_email;
  if (!email) {
    console.error("No email in checkout session", session.id);
    return;
  }

  // Get product_code from line items metadata
  const lineItems = await stripe.checkout.sessions.listLineItems(session.id, { expand: ["data.price.product"] });
  const productCode = lineItems.data[0]?.price?.metadata?.product_code 
                   || lineItems.data[0]?.price?.product?.metadata?.product_code;

  if (!productCode) {
    console.error("No product_code metadata on price/product for session", session.id);
    return;
  }

  // Find user by email
  const { data: userList } = await supabase.auth.admin.listUsers();
  let user = userList.users.find(u => u.email === email);

  // If user doesn't exist, create them — bought before signing up
  if (!user) {
    const { data: newUser, error: createErr } = await supabase.auth.admin.createUser({
      email,
      email_confirm: true,
      // No password — they'll have to reset it
    });
    if (createErr) { console.error("Failed to create user", createErr); return; }
    user = newUser.user;
    // TODO: Send them a welcome email with password reset link
  }

  // Determine if this is a sub
  const isSubscription = session.mode === "subscription";
  
  // Insert entitlement
  const { error } = await supabase.from("entitlements").upsert({
    user_id: user.id,
    product_code: productCode,
    source: "stripe",
    stripe_session_id: session.id,
    stripe_subscription_id: session.subscription || null,
    status: "active",
    expires_at: isSubscription ? null : null, // subs renew themselves; one-time = no expiry
    metadata: { email, amount_total: session.amount_total }
  }, { onConflict: "user_id,product_code,stripe_session_id" });

  if (error) console.error("Failed to insert entitlement", error);
  else console.log(`Granted ${productCode} to ${email}`);
}

async function handleSubscriptionDeleted(sub) {
  // When subscription cancels, revoke entitlement
  const { error } = await supabase
    .from("entitlements")
    .update({ status: "revoked" })
    .eq("stripe_subscription_id", sub.id);
  if (error) console.error("Failed to revoke sub entitlement", error);
}

async function handleRefund(charge) {
  // On refund, find the session and revoke
  const session = await stripe.checkout.sessions.list({ payment_intent: charge.payment_intent, limit: 1 });
  if (session.data[0]) {
    await supabase
      .from("entitlements")
      .update({ status: "revoked" })
      .eq("stripe_session_id", session.data[0].id);
  }
}
```

---

# STEP 6 — Vercel environment variables

In Vercel dashboard → Project → Settings → Environment Variables, add:

| Key | Value | Scope |
|---|---|---|
| `SUPABASE_URL` | `https://xxxxx.supabase.co` | All |
| `SUPABASE_SERVICE_ROLE_KEY` | The service role key (SECRET) | All |
| `STRIPE_SECRET_KEY` | `sk_live_...` | All |
| `STRIPE_WEBHOOK_SECRET` | `whsec_...` (from Step 7) | All |

Make sure "Sensitive" is toggled ON for the two secret ones.

Also add to `package.json` (or create one if not present):

```json
{
  "dependencies": {
    "stripe": "^17.0.0",
    "@supabase/supabase-js": "^2.45.0"
  }
}
```

---

# STEP 7 — Stripe webhook setup

1. Deploy the project to Vercel so `/api/stripe-webhook` exists
2. Go to Stripe Dashboard → Developers → Webhooks → Add endpoint
3. URL: `https://YOUR-DOMAIN.vercel.app/api/stripe-webhook`
4. Events to send (check these):
   - `checkout.session.completed`
   - `customer.subscription.deleted`
   - `charge.refunded`
5. Copy the "Signing secret" (starts with `whsec_`)
6. Add it as `STRIPE_WEBHOOK_SECRET` env var in Vercel
7. Re-deploy Vercel project (or trigger redeploy so env var is picked up)

---

# STEP 8 — Stripe product metadata

For each of the 4 paid Stripe products in Jimmy's dashboard, edit the **Price** (not just the product) and add metadata:

| Stripe Product | Metadata key | Metadata value |
|---|---|---|
| CRE University Lifetime | `product_code` | `cre_u_lifetime` |
| CRE University Monthly | `product_code` | `cre_u_monthly` |
| Deal Analyzer B | `product_code` | `da_b` |
| Deal Analyzer C | `product_code` | `da_c` |

This is how the webhook knows which entitlement to grant.

---

# STEP 9 — Update each HTML file

For each of the 4 product HTML files, make these changes:

### Common changes (all 4 files)

1. Add `<script src="/auth.js"></script>` in `<head>` (or wherever the file is hosted)
2. Inside the `<script type="text/babel">` block, at the top, add:
   ```javascript
   const PRODUCT_CODE = "..."; // see table below
   const PRODUCT_NAME = "...";
   const STRIPE_LINK = "..."; // Stripe Payment Link URL
   ```
3. Paste the `AuthGate` component (from Step 4)
4. Replace the existing `ReactDOM.createRoot(...).render(<App />);` with the `GatedApp` wrapper version

### Per-file specifics

**`index.html` (CRE University):**
```javascript
const PRODUCT_CODE = "cre_u_any";
const PRODUCT_NAME = "CRE University";
const STRIPE_LINK = ""; // Use a landing-page approach: show both lifetime + monthly buttons in the gate
```
For CRE U, modify the `nosub` branch of `AuthGate` to show TWO buy buttons (one for lifetime $399, one for monthly $49).

**`deal-analyzer.html` (Tier A):**
```javascript
const PRODUCT_CODE = "da_a";
const PRODUCT_NAME = "Deal Analyzer · Quick Screen";
const STRIPE_LINK = ""; // No Stripe needed — da_a is granted free on signup
```
For Tier A, the gate only enforces login — every signed-in user gets `da_a` automatically via the database trigger. The `nosub` state should never actually trigger for `da_a`.

**`deal-analyzer-b.html`:**
```javascript
const PRODUCT_CODE = "da_b";
const PRODUCT_NAME = "Deal Analyzer · Underwriter";
const STRIPE_LINK = "https://buy.stripe.com/XXX_da_b";
```

**`deal-analyzer-c.html`:**
```javascript
const PRODUCT_CODE = "da_c";
const PRODUCT_NAME = "Deal Analyzer · Pro";
const STRIPE_LINK = "https://buy.stripe.com/XXX_da_c";
```

### Migrate CRE U progress from localStorage to Supabase

In `index.html` (CRE U), find the `usePersistedState` hook and replace it with a Supabase-backed version:

```javascript
function usePersistedState(key, initial) {
  const [value, setValue] = React.useState(initial);
  const [loaded, setLoaded] = React.useState(false);

  React.useEffect(() => {
    let mounted = true;
    const load = async () => {
      const data = await window.CREAuth.loadProgress("cre_u_any");
      if (mounted && data && data[key] !== undefined) setValue(data[key]);
      if (mounted) setLoaded(true);
    };
    load();
    return () => { mounted = false; };
  }, [key]);

  React.useEffect(() => {
    if (!loaded) return;
    // Debounce saves
    const t = setTimeout(async () => {
      const existing = (await window.CREAuth.loadProgress("cre_u_any")) || {};
      existing[key] = value;
      await window.CREAuth.saveProgress("cre_u_any", existing);
    }, 600);
    return () => clearTimeout(t);
  }, [value, loaded, key]);

  return [value, setValue];
}
```

**Important:** This changes the behavior — state is now async-loaded. The app should NOT render until `loaded === true` for critical pieces. Add a global "loading progress" state if needed.

---

# STEP 10 — Test plan

In this order:

1. **Schema:** Run the SQL migration. Verify tables exist.
2. **Auth:** Build a minimal test page that calls `CREAuth.signUp`. Confirm a user is created in Supabase auth.
3. **Trigger:** After signup, check `entitlements` table — should have row with `product_code='da_a'`, `source='free_signup'`.
4. **Login gate:** Open `deal-analyzer.html` (Tier A) without signing in. Should see login screen. Sign in. Should see app.
5. **Paywall:** Open `deal-analyzer-b.html` signed in as a user without `da_b`. Should see "buy now" screen.
6. **Webhook (test mode first):**
   - Switch to Stripe TEST mode
   - Use Stripe CLI to forward events to local: `stripe listen --forward-to localhost:3000/api/stripe-webhook`
   - OR: deploy to a preview Vercel URL, set the webhook in Stripe TEST mode pointing there
   - Make a test purchase with card `4242 4242 4242 4242`
   - Confirm webhook fires
   - Confirm entitlement is created in Supabase
   - Confirm user can now access the gated product
7. **Refund test:** Refund the test charge. Confirm entitlement gets `status='revoked'`.
8. **Cross-device test:** Sign in on phone. Sign in on laptop. Both should work.
9. **Switch to LIVE mode:** Update webhook URL, env vars, and Stripe Payment Link URLs to production.

---

# STEP 11 — Cutover plan

**Existing users (12 testers):** Their progress is in their browser localStorage. When you cut over to auth, they will be locked out. Options:

- **Easiest:** Email them, explain there's now a login, have them sign up. They'll lose their streaks but it's only 12 people.
- **Better:** Add a one-time "Import my old progress" button that reads from localStorage and writes to Supabase on first login. ~30 min extra build.

**Existing URLs (cre-university.vercel.app):** No change — same URL, just now has a login screen on load.

**Deal Analyzer URLs:** If they're on the same Vercel project as CRE U, just upload the updated HTML files. If on separate projects, deploy to each.

---

# STEP 12 — Post-launch

Set up monitoring:

1. **Stripe → Webhooks → recent deliveries.** Watch for failures.
2. **Supabase → Logs.** Watch for RLS violations or query errors.
3. **Vercel → Functions logs.** Watch for webhook errors.

Add to your todo list:
- Implement Stripe Customer Portal link in CRE U sub view (so monthly subs can self-cancel)
- "Import old progress" tool for existing testers
- Welcome email after signup with what to do next

---

# Common gotchas to warn Jimmy about

1. **Stripe webhook in TEST vs LIVE mode** — they have different signing secrets. Easy to get confused. Use test mode for ALL initial testing.
2. **Email confirmation required** — users won't be able to sign in until they click the email confirmation link. If Jimmy disables this, spam signups will pollute the DB.
3. **Service role key is SECRET** — never put it in browser JS. Only in Vercel env vars used by the webhook.
4. **Anon key IS safe in browser** — RLS policies protect the data.
5. **Stripe Payment Links MUST collect email** — check the box when creating them.
6. **Metadata is on the Price, not the Product** — common mistake.
7. **Free signups still need email confirmation** — even Deal Analyzer A users have to click the link in their email.

---

# Done state

When all 12 steps are complete:

- ✅ Anyone visiting any of the 4 product URLs hits a login wall
- ✅ Signup is free and grants Deal Analyzer A automatically
- ✅ B and C require paid purchase via Stripe → webhook → entitlement → access
- ✅ CRE U requires either lifetime or monthly entitlement
- ✅ Sharing URLs does nothing — recipient needs an account with the right entitlement
- ✅ Refunds automatically revoke access
- ✅ Subs cancel automatically revoke at period end (`customer.subscription.deleted`)
- ✅ Progress in CRE U syncs across devices for the same user

# End of spec
