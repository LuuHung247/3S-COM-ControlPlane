CREATE TABLE IF NOT EXISTS user_profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT UNIQUE NOT NULL,
  phone TEXT,
  display_name TEXT,
  avatar_url TEXT,
  email_verified BOOLEAN DEFAULT false,
  phone_verified BOOLEAN DEFAULT false,
  license_key TEXT,
  license_status TEXT DEFAULT 'none' CHECK (license_status IN ('none', 'active', 'expired')),
  referral_code TEXT UNIQUE,
  referred_by TEXT,
  wallet_address TEXT,
  payout_crypto TEXT DEFAULT 'USDT',
  total_referral_earnings_usd NUMERIC(10,2) DEFAULT 0,
  notification_email BOOLEAN DEFAULT true,
  notification_sms BOOLEAN DEFAULT true,
  notification_webhook_url TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_profiles_email ON user_profiles(email);
CREATE INDEX IF NOT EXISTS idx_user_profiles_referral ON user_profiles(referral_code);

-- RLS policies
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own profile"
  ON user_profiles FOR SELECT
  USING (auth.uid() = id);

CREATE POLICY "Users can update own profile"
  ON user_profiles FOR UPDATE
  USING (auth.uid() = id);

CREATE POLICY "Service role can insert profiles"
  ON user_profiles FOR INSERT
  WITH CHECK (true);
