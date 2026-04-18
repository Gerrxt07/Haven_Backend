-- Migration: Replace password_hash with SRP salt and verifier
-- This enables Secure Remote Password (SRP-6a) authentication

-- Add new SRP columns
ALTER TABLE users ADD COLUMN IF NOT EXISTS srp_salt TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS srp_verifier TEXT;

-- Migrate existing data: set SRP columns to NULL for now
-- Existing users will need to reset their passwords to use SRP

-- Drop the old password_hash column
-- Note: Only do this after all existing users have migrated
-- For now, we keep it nullable for backward compatibility during transition
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- Add comment for documentation
COMMENT ON COLUMN users.srp_salt IS 'SRP-6a salt (base64 encoded) for secure remote password authentication';
COMMENT ON COLUMN users.srp_verifier IS 'SRP-6a verifier (base64 encoded) for secure remote password authentication';
