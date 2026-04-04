# Haven Backend (Base)

Initial Rust backend foundation for Haven.

## Stack

- Axum (HTTP API)
- PostgreSQL (persistent relational data)
- DragonflyDB via Redis protocol (cache/state)
- SQLx (database access + migrations)

## Quick start

1. Ensure Postgres and Dragonfly are running from your existing Docker setup.
2. Copy env template:

```bash
cp .env.example .env
```

3. Run backend:

```bash
cargo run
```

Server starts on `0.0.0.0:8086` by default.

## Endpoints

- `GET /api/v1/health`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `GET /api/v1/auth/me` (Bearer access token)
- `POST /api/v1/users/me/avatar` (Bearer access token, multipart `file` JPG/PNG <= 5MB, optimized to WebP)
- `GET /api/v1/media/avatars/:user_id/avatar.webp`
- `POST /api/v1/users`
- `GET /api/v1/users/:id`
- `GET /api/v1/ws` (WebSocket gateway: presence + new message events)
- `GET /api/v1/realtime/ws` (WebSocket Event-Bus)
- `POST /api/v1/servers`
- `POST /api/v1/channels`
- `POST /api/v1/messages`
- `POST /api/v1/servers/:server_id/channels`
- `GET /api/v1/servers/:server_id/channels?before=<id>&limit=<n>`
- `POST /api/v1/channels/:channel_id/messages`
- `GET /api/v1/channels/:channel_id/messages?before=<id>&limit=<n>`
- `POST /api/v1/e2ee/keys/bundle` (upload identity key + signed prekey + one-time prekeys)
- `GET /api/v1/e2ee/keys/bundle/:user_id` (fetch public key bundle)
- `POST /api/v1/e2ee/keys/claim` (claim target one-time prekey bundle for X3DH bootstrap)

## Notes

- Migration creates a `users` table based on `db.txt`.
- `id` is `BIGINT` and expected to be a Snowflake-compatible value generated upstream.
- The backend uses a dedicated Postgres DB (`POSTGRES_DB`, default: `haven_backend`) and creates it automatically if missing.
- The checked-in env template is aligned to your current Postgres docker credentials (`admin` / `phantom_db`) and creates `haven_backend` as a separate application DB.
- Auth foundation uses `Argon2id` password hashing and `PASETO v4 local` tokens (access + refresh).
- Extended crypto foundation includes `XChaCha20-Poly1305` via `CryptoManager` for authenticated encryption of sensitive payloads.
- Security hardening includes: request body limits, route-level rate limiting, stricter CORS config, input validation, and account-status checks on protected route access.
- Chat hardening: strict cursor pagination params (`before`, `limit`) for message history, ID/content validation, slug allowlist (`[a-z0-9-]`), and membership checks for channel message creation.
- Realtime uses Dragonfly as presence/session cache (`presence:user:*`, `session:ws:*`) and Redis Pub/Sub fan-out (`haven:events`).
- E2EE foundation: server stores encrypted message envelopes (`ciphertext`, `nonce`, `aad`, `algorithm`) and per-recipient wrapped message keys (`message_recipient_keys`).
