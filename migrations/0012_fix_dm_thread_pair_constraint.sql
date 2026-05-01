ALTER TABLE dm_threads
    ADD COLUMN IF NOT EXISTS created_by_user_id BIGINT;

UPDATE dm_threads
SET created_by_user_id = user_a_id
WHERE created_by_user_id IS NULL;

ALTER TABLE dm_threads
    ALTER COLUMN created_by_user_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'dm_threads_created_by_user_id_fkey'
          AND conrelid = 'dm_threads'::regclass
    ) THEN
        ALTER TABLE dm_threads
            ADD CONSTRAINT dm_threads_created_by_user_id_fkey
            FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'dm_threads_not_self'
          AND conrelid = 'dm_threads'::regclass
    ) THEN
        ALTER TABLE dm_threads
            ADD CONSTRAINT dm_threads_not_self CHECK (user_a_id <> user_b_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'dm_threads_ordered_pair'
          AND conrelid = 'dm_threads'::regclass
    ) THEN
        ALTER TABLE dm_threads
            ADD CONSTRAINT dm_threads_ordered_pair CHECK (user_a_id < user_b_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'dm_threads_user_pair_unique'
          AND conrelid = 'dm_threads'::regclass
    ) THEN
        WITH ranked_threads AS (
            SELECT
                id,
                MIN(id) OVER (PARTITION BY user_a_id, user_b_id) AS keep_id,
                ROW_NUMBER() OVER (PARTITION BY user_a_id, user_b_id ORDER BY id) AS row_number
            FROM dm_threads
        )
        UPDATE dm_messages
        SET thread_id = ranked_threads.keep_id
        FROM ranked_threads
        WHERE dm_messages.thread_id = ranked_threads.id
          AND ranked_threads.row_number > 1;

        WITH ranked_threads AS (
            SELECT
                id,
                ROW_NUMBER() OVER (PARTITION BY user_a_id, user_b_id ORDER BY id) AS row_number
            FROM dm_threads
        )
        DELETE FROM dm_threads
        USING ranked_threads
        WHERE dm_threads.id = ranked_threads.id
          AND ranked_threads.row_number > 1;

        ALTER TABLE dm_threads
            ADD CONSTRAINT dm_threads_user_pair_unique UNIQUE (user_a_id, user_b_id);
    END IF;
END $$;
