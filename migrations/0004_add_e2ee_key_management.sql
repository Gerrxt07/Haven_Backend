ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS is_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS ciphertext TEXT,
    ADD COLUMN IF NOT EXISTS nonce TEXT,
    ADD COLUMN IF NOT EXISTS aad TEXT,
    ADD COLUMN IF NOT EXISTS algorithm TEXT,
    ADD COLUMN IF NOT EXISTS sender_key_id BIGINT;

CREATE TABLE IF NOT EXISTS user_key_bundles (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    identity_key TEXT NOT NULL,
    signed_prekey_id BIGINT NOT NULL,
    signed_prekey TEXT NOT NULL,
    signed_prekey_signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    prekey TEXT NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT one_time_prekeys_user_id_id_unique UNIQUE (user_id, id)
);

CREATE TABLE IF NOT EXISTS message_recipient_keys (
    id BIGINT PRIMARY KEY,
    message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    recipient_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_message_key TEXT NOT NULL,
    one_time_prekey_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT message_recipient_keys_msg_recipient_unique UNIQUE (message_id, recipient_user_id)
);

CREATE INDEX IF NOT EXISTS idx_one_time_prekeys_user_unconsumed
    ON one_time_prekeys(user_id, consumed_at, id DESC);

CREATE INDEX IF NOT EXISTS idx_messages_channel_encrypted_cursor
    ON messages(channel_id, is_encrypted, id DESC);

CREATE INDEX IF NOT EXISTS idx_message_recipient_keys_recipient_message
    ON message_recipient_keys(recipient_user_id, message_id DESC);

DROP TRIGGER IF EXISTS user_key_bundles_set_updated_at ON user_key_bundles;
CREATE TRIGGER user_key_bundles_set_updated_at
BEFORE UPDATE ON user_key_bundles
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
