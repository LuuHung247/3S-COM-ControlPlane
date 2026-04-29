-- Referral program: refer a friend, both get lifetime for $249 instead of $499

-- Add referral fields to waitlist
ALTER TABLE public.waitlist ADD COLUMN IF NOT EXISTS referral_code TEXT UNIQUE;
ALTER TABLE public.waitlist ADD COLUMN IF NOT EXISTS referred_by TEXT REFERENCES public.waitlist(referral_code);
ALTER TABLE public.waitlist ADD COLUMN IF NOT EXISTS amount_usd NUMERIC DEFAULT 499;
ALTER TABLE public.waitlist ADD COLUMN IF NOT EXISTS payment_id TEXT;
ALTER TABLE public.waitlist ADD COLUMN IF NOT EXISTS payment_status TEXT;

-- Generate referral codes for existing entries
UPDATE public.waitlist SET referral_code = substr(md5(random()::text), 1, 8) WHERE referral_code IS NULL;

-- Index for referral lookups
CREATE INDEX IF NOT EXISTS idx_waitlist_referral_code ON public.waitlist(referral_code);
CREATE INDEX IF NOT EXISTS idx_waitlist_referred_by ON public.waitlist(referred_by);
