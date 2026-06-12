-- =================================================================
-- CRE University — Auth & Entitlements foundation
-- Run this in: Supabase Dashboard → SQL Editor → New query → Run
-- Safe to re-run (uses "if not exists" / "or replace" throughout).
-- =================================================================

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
drop policy if exists "Users read own entitlements" on public.entitlements;
create policy "Users read own entitlements"
  on public.entitlements for select
  using (auth.uid() = user_id);

-- Users CANNOT insert/update entitlements directly (only webhook can, via service role)
-- (No insert/update/delete policy for regular users — service role bypasses RLS)

-- Users can read/write their own progress
drop policy if exists "Users read own progress" on public.progress;
create policy "Users read own progress"
  on public.progress for select
  using (auth.uid() = user_id);

drop policy if exists "Users insert own progress" on public.progress;
create policy "Users insert own progress"
  on public.progress for insert
  with check (auth.uid() = user_id);

drop policy if exists "Users update own progress" on public.progress;
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
-- security_invoker = on so the view runs as the *querying* user and
-- respects the entitlements RLS policy below — not as the postgres
-- owner (a definer view would silently bypass the caller's RLS).
-- =================================================================
create or replace view public.my_active_entitlements
  with (security_invoker = on) as
select product_code, granted_at, expires_at, source
from public.entitlements
where user_id = auth.uid()
  and status = 'active'
  and (expires_at is null or expires_at > now());

-- =================================================================
-- 6. GRANTS
-- PostgREST runs queries as the `authenticated` (or `anon`) role. RLS
-- decides which ROWS are visible, but the role still needs table/view
-- level SELECT privilege or PostgREST returns HTTP 403 before RLS is
-- ever evaluated. Missing these grants is what caused the 403 on
-- my_active_entitlements. RLS keeps each user scoped to their own rows.
-- =================================================================
grant select on public.entitlements to authenticated;
grant select on public.my_active_entitlements to authenticated;

