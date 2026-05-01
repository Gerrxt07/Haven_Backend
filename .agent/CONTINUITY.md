# CONTINUITY

2026-04-20T10:45:00+02:00 [TOOL] `UNCONFIRMED` missing file at `.agent/CONTINUITY.md`; created baseline memory file for repo continuity.
2026-04-20T10:45:00+02:00 [USER] Create OpenAPI document for Haven backend for tools like Scalar.
2026-04-20T10:45:00+02:00 [CODE] Added `docs/openapi.yaml` for current HTTP API under `/api/v1`; excludes WebSocket upgrade routes.
2026-04-21T10:21:55+02:00 [USER] Implement open feature issues one-by-one, add tests when needed, do not run server locally, and open one PR after `cargo test` and `cargo clippy` pass.
2026-04-21T10:21:55+02:00 [CODE] Implemented issue set #10-#14 in code: centralized auth 2FA checks, added identity-based login limiting, moved WS auth to first-message token auth with per-connection throttling and server-side identity enforcement, enforced E2EE payload size caps, switched realtime publish path to Redis Pub/Sub only, and added deleted-account anonymization sweep.
2026-04-21T10:21:55+02:00 [TOOL] Verified green with `cargo test` and `cargo clippy --all-targets --all-features -- -D warnings`.
2026-04-21T10:38:34+02:00 [USER] Redesign, write, and format the backend README in the same modern style as the client README.
2026-04-21T10:38:34+02:00 [CODE] Replaced the backend README with a modern overview covering security architecture, feature set, stack, API surface, OpenAPI usage, and project structure.
2026-04-21T10:38:34+02:00 [ASSUMPTION] Backend README update is documentation-only; no Rust code paths changed.
2026-04-21T11:05:00+02:00 [USER] Push the backend docs OpenAPI files directly to master.
2026-04-21T11:05:00+02:00 [CODE] Staged the untracked `docs/openapi.yaml` file for a direct master commit.
2026-04-21T11:11:53+02:00 [USER] Patch and push OpenAPI docs after latest backend auth and message handling changes.
2026-04-21T11:11:53+02:00 [CODE] Updated `docs/openapi.yaml` to document WebSocket first-message auth notes, shared `403 Forbidden` responses, and `413 Payload Too Large` on message creation routes.
2026-04-21T12:08:18+02:00 [USER] Implement backend issues #16-#19.
2026-04-21T12:08:18+02:00 [CODE] Switched ID generation to Sonyflake with a configurable machine-id source, removed legacy password auth and the `/auth/login` route, added login IP rate limiting for SRP challenge/verify, dropped `password_hash` from writes plus added migration `0011_drop_password_hash_from_users.sql`, and invalidated `cache:auth:status:{user_id}` during deleted-account anonymization.
2026-04-28T20:15:35+02:00 [USER] Requested fixing client HCVE-2026-0001 through HCVE-2026-0004, with backend pushed if changed.
2026-04-28T20:15:35+02:00 [CODE] Backend direct-message creation now rejects plaintext payloads and stores only ciphertext, nonce, AAD, and E2EE algorithm for DMs.
2026-04-28T20:15:35+02:00 [TOOL] Verified backend change with `cargo fmt --check`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.
2026-05-01T10:32:01+0200 [USER] Reported clicking a contact to write now returns `database error`; backend log showed `POST /api/v1/dm/threads` returned `500`.
2026-05-01T10:32:01+0200 [ASSUMPTION] Likely production schema drift from `0010_create_dm_threads_and_messages.sql`, where an existing `dm_threads` table lacked constraints/columns later required by `create_or_get_dm_thread`.
2026-05-01T10:32:01+0200 [CODE] Added migration `0012_fix_dm_thread_pair_constraint.sql` to repair `created_by_user_id`, add missing DM thread constraints, merge duplicate pair rows, and add the `(user_a_id, user_b_id)` unique constraint required by `ON CONFLICT`.
2026-05-01T10:32:01+0200 [TOOL] Verified backend with `cargo fmt --check`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.
2026-05-01T10:38:53+0200 [USER] Reported same client database error after rebuild; backend logs still showed `POST /api/v1/dm/threads` returning `500`.
2026-05-01T10:38:53+0200 [CODE] Hardened DM thread creation to select an existing pair before insert and removed runtime dependency on `ON CONFLICT (user_a_id, user_b_id)`, with duplicate-key fallback to reselect.
2026-05-01T10:38:53+0200 [TOOL] Verified backend with `cargo fmt --check`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.
