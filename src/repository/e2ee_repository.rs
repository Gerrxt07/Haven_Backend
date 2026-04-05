use crate::{
    domain::e2ee::{
        KeyBundleWithPrekey, NewMessageRecipientKey, PublicKeyBundle, UploadKeyBundleRequest,
    },
    error::AppError,
};
use sqlx::PgPool;

pub async fn user_exists(pool: &PgPool, user_id: i64) -> Result<bool, AppError> {
    let exists = sqlx::query_scalar::<_, i64>("SELECT 1 FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?
        .is_some();
    Ok(exists)
}

pub async fn upsert_key_bundle(
    pool: &PgPool,
    user_id: i64,
    req: &UploadKeyBundleRequest,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        r#"
        INSERT INTO user_key_bundles (
            user_id, identity_key, signed_prekey_id, signed_prekey, signed_prekey_signature
        ) VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (user_id)
        DO UPDATE SET
            identity_key = EXCLUDED.identity_key,
            signed_prekey_id = EXCLUDED.signed_prekey_id,
            signed_prekey = EXCLUDED.signed_prekey,
            signed_prekey_signature = EXCLUDED.signed_prekey_signature,
            updated_at = NOW()
        "#,
    )
    .bind(user_id)
    .bind(&req.identity_key)
    .bind(req.signed_prekey_id)
    .bind(&req.signed_prekey)
    .bind(&req.signed_prekey_signature)
    .execute(&mut *tx)
    .await?;

    for prekey in &req.one_time_prekeys {
        sqlx::query(
            r#"
            INSERT INTO one_time_prekeys (id, user_id, prekey)
            VALUES ($1, $2, $3)
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(prekey.id)
        .bind(user_id)
        .bind(&prekey.prekey)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

pub async fn get_public_bundle(
    pool: &PgPool,
    user_id: i64,
) -> Result<Option<PublicKeyBundle>, AppError> {
    let bundle = sqlx::query_as::<_, PublicKeyBundle>(
        r#"
        SELECT user_id, identity_key, signed_prekey_id, signed_prekey, signed_prekey_signature, created_at, updated_at
        FROM user_key_bundles
        WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(bundle)
}

pub async fn claim_prekey_bundle(
    pool: &PgPool,
    target_user_id: i64,
) -> Result<Option<KeyBundleWithPrekey>, AppError> {
    let mut tx = pool.begin().await?;

    let bundle = sqlx::query_as::<_, PublicKeyBundle>(
        r#"
        SELECT user_id, identity_key, signed_prekey_id, signed_prekey, signed_prekey_signature, created_at, updated_at
        FROM user_key_bundles
        WHERE user_id = $1
        "#,
    )
    .bind(target_user_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(bundle) = bundle else {
        tx.commit().await?;
        return Ok(None);
    };

    let prekey_row = sqlx::query_as::<_, (i64, String)>(
        r#"
        SELECT id, prekey
        FROM one_time_prekeys
        WHERE user_id = $1 AND consumed_at IS NULL
        ORDER BY id DESC
        LIMIT 1
        FOR UPDATE SKIP LOCKED
        "#,
    )
    .bind(target_user_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((prekey_id, prekey)) = prekey_row else {
        tx.commit().await?;
        return Ok(None);
    };

    sqlx::query("UPDATE one_time_prekeys SET consumed_at = NOW() WHERE id = $1")
        .bind(prekey_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(Some(KeyBundleWithPrekey {
        user_id: bundle.user_id,
        identity_key: bundle.identity_key,
        signed_prekey_id: bundle.signed_prekey_id,
        signed_prekey: bundle.signed_prekey,
        signed_prekey_signature: bundle.signed_prekey_signature,
        one_time_prekey_id: prekey_id,
        one_time_prekey: prekey,
    }))
}

pub async fn insert_message_recipient_keys(
    pool: &PgPool,
    rows: Vec<NewMessageRecipientKey>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;

    for row in rows {
        sqlx::query(
            r#"
            INSERT INTO message_recipient_keys (
                id, message_id, recipient_user_id, encrypted_message_key, one_time_prekey_id
            ) VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (message_id, recipient_user_id) DO UPDATE
            SET encrypted_message_key = EXCLUDED.encrypted_message_key,
                one_time_prekey_id = EXCLUDED.one_time_prekey_id
            "#,
        )
        .bind(crate::auth::generate_id())
        .bind(row.message_id)
        .bind(row.recipient_user_id)
        .bind(row.encrypted_message_key)
        .bind(row.one_time_prekey_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}
