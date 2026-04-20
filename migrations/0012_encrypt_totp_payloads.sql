ALTER TABLE users
    ALTER COLUMN totp_backup_codes TYPE TEXT
    USING CASE
        WHEN totp_backup_codes IS NULL THEN NULL
        ELSE to_json(totp_backup_codes)::text
    END;

ALTER TABLE totp_setups
    ALTER COLUMN backup_codes TYPE TEXT
    USING to_json(backup_codes)::text;
