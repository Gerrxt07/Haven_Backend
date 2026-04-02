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
- `POST /api/v1/users`
- `GET /api/v1/users/:id`

## Notes

- Migration creates a `users` table based on `db.txt`.
- `id` is `BIGINT` and expected to be a Snowflake-compatible value generated upstream.
- The backend uses a dedicated Postgres DB (`POSTGRES_DB`, default: `haven_backend`) and creates it automatically if missing.
- The checked-in env template is aligned to your current Postgres docker credentials (`admin` / `phantom_db`) and creates `haven_backend` as a separate application DB.
- Auth foundation uses `Argon2id` password hashing and `PASETO v4 local` tokens (access + refresh).
- Security hardening includes: request body limits, route-level rate limiting, stricter CORS config, input validation, and account-status checks on protected route access.
