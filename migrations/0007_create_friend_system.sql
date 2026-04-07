CREATE TABLE IF NOT EXISTS friend_requests (
    id BIGINT PRIMARY KEY,
    from_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'declined')),
    responded_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT friend_requests_not_self CHECK (from_user_id <> to_user_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_friend_requests_pending_pair
    ON friend_requests (LEAST(from_user_id, to_user_id), GREATEST(from_user_id, to_user_id))
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_friend_requests_to_user_pending
    ON friend_requests (to_user_id, created_at DESC)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_friend_requests_from_user_pending
    ON friend_requests (from_user_id, created_at DESC)
    WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS friends (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    friend_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT friends_not_self CHECK (user_id <> friend_user_id),
    CONSTRAINT friends_user_friend_unique UNIQUE (user_id, friend_user_id)
);

CREATE INDEX IF NOT EXISTS idx_friends_user_id_created_at
    ON friends (user_id, created_at DESC);

DROP TRIGGER IF EXISTS friend_requests_set_updated_at ON friend_requests;
CREATE TRIGGER friend_requests_set_updated_at
BEFORE UPDATE ON friend_requests
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
