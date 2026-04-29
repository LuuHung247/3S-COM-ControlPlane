-- ThreatCrush Waitlist Table
-- Run this migration against your Supabase project

create table if not exists public.waitlist (
  id uuid default gen_random_uuid() primary key,
  email text not null unique,
  paid boolean default false,
  payment_method text check (payment_method in ('stripe', 'crypto')),
  stripe_session_id text,
  coinpay_invoice_id text,
  paid_at timestamptz,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- Index for quick lookups
create index if not exists idx_waitlist_email on public.waitlist (email);
create index if not exists idx_waitlist_paid on public.waitlist (paid);

-- RLS policies
alter table public.waitlist enable row level security;

-- Allow inserts from anon (for the signup form)
create policy "Allow anonymous inserts" on public.waitlist
  for insert
  with check (true);

-- Only authenticated/service role can read
create policy "Service role can read" on public.waitlist
  for select
  using (auth.role() = 'service_role');

-- Updated at trigger
create or replace function public.handle_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create trigger on_waitlist_updated
  before update on public.waitlist
  for each row
  execute function public.handle_updated_at();
