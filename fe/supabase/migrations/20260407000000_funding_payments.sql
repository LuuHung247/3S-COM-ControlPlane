-- threatcrush funding payments (CoinPay-routed credit card + crypto)
-- Anonymous: no auth coupling. Optional contributor name/email.

create extension if not exists "pgcrypto";

create table if not exists public.funding_payments (
  id uuid primary key default gen_random_uuid(),
  coinpay_payment_id text unique not null,
  amount_usd numeric(12,2) not null,
  amount_crypto numeric(36,18),
  currency text not null,
  status text not null default 'pending'
    check (status in ('pending','confirmed','forwarded','expired','failed')),
  contributor_name text,
  contributor_email text,
  tx_hash text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  paid_at timestamptz
);

create index if not exists idx_funding_payments_status on public.funding_payments(status);
create index if not exists idx_funding_payments_paid_at on public.funding_payments(paid_at desc);
create index if not exists idx_funding_payments_status_paid_at
  on public.funding_payments(status, paid_at desc);

alter table public.funding_payments enable row level security;
-- No anon policies on purpose: only the service-role server reads/writes.
