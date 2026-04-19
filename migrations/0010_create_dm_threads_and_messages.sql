CREATE TABLE IF NOT EXISTS dm_threads (
    id BIGINT PRIMARY KEY,
    user_a_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_b_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_by_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT dm_threads_not_self CHECK (user_a_id <> user_b_id),
    CONSTRAINT dm_threads_ordered_pair CHECK (user_a_id < user_b_id),
    CONSTRAINT dm_threads_user_pair_unique UNIQUE (user_a_id, user_b_id)
);

CREATE INDEX IF NOT EXISTS idx_dm_threads_user_a_updated
    ON dm_threads(user_a_id, updated_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_dm_threads_user_b_updated
    ON dm_threads(user_b_id, updated_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS dm_messages (
    id BIGINT PRIMARY KEY,
    thread_id BIGINT NOT NULL REFERENCES dm_threads(id) ON DELETE CASCADE,
    author_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    content TEXT NOT NULL,
    is_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    ciphertext TEXT,
    nonce TEXT,
    aad TEXT,
    algorithm TEXT,
    edited_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dm_messages_thread_active_id_desc
    ON dm_messages(thread_id, id DESC)
    WHERE deleted_at IS NULL;

DROP TRIGGER IF EXISTS dm_threads_set_updated_at ON dm_threads;
CREATE TRIGGER dm_threads_set_updated_at
BEFORE UPDATE ON dm_threads
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS dm_messages_set_updated_at ON dm_messages;
CREATE TRIGGER dm_messages_set_updated_at
BEFORE UPDATE ON dm_messages
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
