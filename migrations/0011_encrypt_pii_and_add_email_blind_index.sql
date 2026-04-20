ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_email_key;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_blind_index TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS users_email_blind_index_key
    ON users (email_blind_index)
    WHERE email_blind_index IS NOT NULL;

ALTER TABLE users
    ALTER COLUMN date_of_birth TYPE TEXT
    USING date_of_birth::text;
