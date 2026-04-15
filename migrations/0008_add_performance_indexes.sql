-- Message pagination hot path with soft-delete filter.
CREATE INDEX IF NOT EXISTS idx_messages_channel_active_id_desc
    ON messages(channel_id, id DESC)
    WHERE deleted_at IS NULL;

-- Keep auth-session lookups and token-version checks fast for active sessions.
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_token_active_expires
    ON auth_sessions(user_id, token_version, expires_at DESC)
    WHERE revoked_at IS NULL;

-- Email verification checks only care about active codes.
CREATE INDEX IF NOT EXISTS idx_email_verification_codes_user_active_created
    ON email_verification_codes(user_id, created_at DESC)
    WHERE consumed_at IS NULL;
