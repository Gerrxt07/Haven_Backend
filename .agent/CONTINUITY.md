# CONTINUITY

2026-04-20T10:45:00+02:00 [TOOL] `UNCONFIRMED` missing file at `.agent/CONTINUITY.md`; created baseline memory file for repo continuity.
2026-04-20T10:45:00+02:00 [USER] Create OpenAPI document for Haven backend for tools like Scalar.
2026-04-20T10:45:00+02:00 [CODE] Added `docs/openapi.yaml` for current HTTP API under `/api/v1`; excludes WebSocket upgrade routes.
2026-04-21T10:21:55+02:00 [USER] Implement open feature issues one-by-one, add tests when needed, do not run server locally, and open one PR after `cargo test` and `cargo clippy` pass.
2026-04-21T10:21:55+02:00 [CODE] Implemented issue set #10-#14 in code: centralized auth 2FA checks, added identity-based login limiting, moved WS auth to first-message token auth with per-connection throttling and server-side identity enforcement, enforced E2EE payload size caps, switched realtime publish path to Redis Pub/Sub only, and added deleted-account anonymization sweep.
2026-04-21T10:21:55+02:00 [TOOL] Verified green with `cargo test` and `cargo clippy --all-targets --all-features -- -D warnings`.
