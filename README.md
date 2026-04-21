<div align="center">
  <h1>Haven Backend</h1>
  <p><b>A hardened Rust backend for authentication, realtime messaging, friendship flows, and E2EE support.</b></p>

  <p>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-000000?logo=rust&style=flat-square" alt="Rust"></a>
    <a href="https://github.com/tokio-rs/axum"><img src="https://img.shields.io/badge/Axum-5E4AE3?style=flat-square" alt="Axum"></a>
    <a href="https://www.postgresql.org/"><img src="https://img.shields.io/badge/PostgreSQL-336791?logo=postgresql&logoColor=white&style=flat-square" alt="PostgreSQL"></a>
    <a href="https://www.dragonflydb.io/"><img src="https://img.shields.io/badge/DragonflyDB-ff6b35?style=flat-square" alt="DragonflyDB"></a>
    <a href="./docs/openapi.yaml"><img src="https://img.shields.io/badge/OpenAPI-available-green?style=flat-square" alt="OpenAPI"></a>
  </p>
</div>

---

## Overview

**Haven Backend** is the server-side core for the Haven platform. It provides:

- authentication and session handling
- server, channel, direct-message, and friend workflows
- websocket-based realtime delivery
- E2EE key-bundle and encrypted-envelope support
- privacy and operational hardening for a production-facing chat backend

The codebase is written in Rust with Axum, SQLx, PostgreSQL, and DragonflyDB/Redis.

## Security Architecture

The backend is built around strict validation, authenticated transport state, and encrypted handling of sensitive data.

### Authentication and account protection

- **SRP login flow:** Primary password login uses a challenge-response SRP handshake instead of sending raw passwords.
- **Legacy login compatibility:** A legacy password route still exists for compatibility during migration.
- **PASETO tokens:** Access and refresh sessions are issued with `PASETO v4 local`.
- **Refresh-session tracking:** Refresh tokens are stored as hashes in persistent auth sessions.
- **TOTP 2FA and backup codes:** Optional two-factor flows include setup, confirmation, disable, and backup code consumption.
- **Per-account login throttling:** Login and login challenge endpoints are rate-limited by identity, not only by IP.
- **Account status enforcement:** Disabled or deleted accounts cannot continue normal authenticated flows.

### Data protection

- **Authenticated encryption:** Sensitive server-side values use `XChaCha20-Poly1305`.
- **Encrypted PII fields:** Email, date of birth, TOTP secrets, and backup-code material are encrypted at rest.
- **Blind indexes:** Email lookups use blind indexes so exact values do not need to be queried directly.
- **Avatar processing controls:** Avatar uploads are type-checked, size-limited, resized, and stored as optimized WebP output.

### API and transport hardening

- **Request body limits:** Global request body size limits are enforced at the HTTP layer.
- **Validation-first handlers:** Payloads, cursors, IDs, base64 blobs, and field lengths are validated before deeper processing.
- **CORS controls:** Allowed origins are configurable rather than fully implicit.
- **Per-route rate limiting:** Route middleware throttles abusive request rates.
- **Strict websocket authentication:** WebSocket connections are authenticated through the first message, not query-string bearer tokens.
- **Server-side websocket identity:** Client websocket commands no longer provide `user_id`; identity is derived from the verified token.
- **Per-connection websocket throttling:** Realtime sockets are rate-limited at message level.
- **E2EE payload caps:** Oversized ciphertext, nonce, and AAD payloads are rejected before storage or fanout.

### Realtime and privacy operations

- **Redis/Dragonfly Pub/Sub fanout:** Realtime events are distributed through Redis Pub/Sub for multi-node delivery.
- **Presence and websocket session cache:** Presence and websocket session state are cached in Dragonfly.
- **Deleted-account cleanup:** Soft-deleted accounts are periodically anonymized after the retention window.
- **Avatar cleanup task:** Orphaned avatar files are cleaned automatically in the background.

## Core Features

- User registration and profile retrieval
- SRP login challenge and verification
- Refresh-token rotation and auth-session persistence
- Email verification
- Optional two-factor authentication
- Avatar upload and retrieval
- Friends and friend-request workflows
- Server, channel, and direct-message flows
- Realtime websocket presence and event delivery
- Public E2EE bundle publishing and prekey claiming

## Technology Stack

- **Language:** Rust
- **HTTP and websocket framework:** Axum
- **Async runtime:** Tokio
- **Database:** PostgreSQL
- **Cache and fanout:** DragonflyDB over the Redis protocol
- **Database access:** SQLx migrations and queries
- **Auth and crypto:** SRP, PASETO, XChaCha20-Poly1305, Argon2id
- **Observability:** tracing, tracing-subscriber, tracing-appender

## Getting Started

### Prerequisites

- Rust toolchain
- PostgreSQL
- DragonflyDB or a Redis-compatible instance
- SMTP credentials for email verification flows

### Environment

Copy and fill the template:

```bash
cp .env.example .env
```

Important variables include:

- `POSTGRES_ADMIN_URL`
- `POSTGRES_DB`
- `POSTGRES_URL`
- `DRAGONFLY_URL`
- `PASETO_LOCAL_KEY`
- `XCHACHA20_KEY`
- `MASTER_ENCRYPTION_KEY`
- `BLIND_INDEX_KEY`
- `CORS_ALLOWED_ORIGINS`

### Run locally

```bash
cargo run
```

Default bind address is `0.0.0.0:8086`.

### Verification

```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## API Surface

### Auth

- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/login/challenge`
- `POST /api/v1/auth/login/verify`
- `POST /api/v1/auth/refresh`
- `GET /api/v1/auth/me`
- `POST /api/v1/auth/email/verification/request`
- `POST /api/v1/auth/email/verification/confirm`
- `POST /api/v1/auth/2fa/setup`
- `POST /api/v1/auth/2fa/confirm`
- `POST /api/v1/auth/2fa/disable`

### Users and media

- `POST /api/v1/users`
- `GET /api/v1/users/{id}`
- `POST /api/v1/users/me/avatar`
- `GET /api/v1/media/avatars/{user_id}/avatar.webp`

### Chat and direct messages

- `POST /api/v1/servers`
- `POST /api/v1/channels`
- `POST /api/v1/messages`
- `POST /api/v1/servers/{server_id}/channels`
- `GET /api/v1/servers/{server_id}/channels`
- `POST /api/v1/channels/{channel_id}/messages`
- `GET /api/v1/channels/{channel_id}/messages`
- `POST /api/v1/dm/threads`
- `GET /api/v1/dm/threads`
- `POST /api/v1/dm/threads/{thread_id}/messages`
- `GET /api/v1/dm/threads/{thread_id}/messages`

### Friends

- `GET /api/v1/friends`
- `POST /api/v1/friends/request`
- `GET /api/v1/friends/requests/incoming`
- `GET /api/v1/friends/requests/outgoing`
- `POST /api/v1/friends/requests/{request_id}/accept`
- `POST /api/v1/friends/requests/{request_id}/decline`

### E2EE

- `POST /api/v1/e2ee/keys/bundle`
- `GET /api/v1/e2ee/keys/bundle/{user_id}`
- `POST /api/v1/e2ee/keys/claim`

### Realtime

- `GET /api/v1/ws`
- `GET /api/v1/realtime/ws`

## OpenAPI

- Spec file: [docs/openapi.yaml](./docs/openapi.yaml)

Example with Scalar:

```bash
docker run --rm -p 8080:8080 \
  -e SPEC_URL=/spec/openapi.yaml \
  -v "$(pwd)/docs:/spec" scalarapi/scalar:latest
```

## Development Notes

- The backend creates and migrates its application database automatically on startup.
- `DragonflyDB` is used both as cache/state storage and as the realtime fanout bus.
- WebSocket clients must authenticate after connect with an explicit `authenticate` message.
- The `x-srp-challenge-id` header is required for SRP login verification.

## Project Structure

```text
Haven_Backend/
|-- migrations/            SQL schema and migration files
|-- src/
|   |-- transport/         HTTP and websocket route wiring
|   |-- service/           Business logic
|   |-- repository/        Data-access layer
|   |-- domain/            Request, response, and model types
|   |-- maintenance.rs     Background cleanup tasks
|   |-- security.rs        Rate limiting and request safeguards
|   `-- main.rs            App bootstrap, config, middleware, tracing
|-- docs/                  OpenAPI and supporting documentation
|-- .env.example           Environment template
`-- Cargo.toml             Rust package manifest
```

## Related Repositories

- Backend: this repository
- Client: [Haven](../Haven)

## License

Use and distribution depend on the Haven project licensing and repository policy. Check the parent project and repository metadata before redistribution.
