#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

REPO_DIR="${HAVEN_BACKEND_REPO:-$DEFAULT_REPO_DIR}"
BRANCH="${HAVEN_BACKEND_BRANCH:-master}"
REMOTE="${HAVEN_BACKEND_REMOTE:-origin}"
COMPOSE_FILE="${HAVEN_BACKEND_COMPOSE_FILE:-docker-compose.yml}"
LOCK_FILE="${HAVEN_BACKEND_LOCK_FILE:-/tmp/haven-backend-auto-pull.lock}"

log() {
	printf '[%s] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$*"
}

cd "$REPO_DIR"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
	log "another update is already running"
	exit 0
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
	log "local changes present; refusing to pull"
	git status --short
	exit 1
fi

git fetch --prune "$REMOTE" "$BRANCH"

local_sha="$(git rev-parse "$BRANCH")"
remote_sha="$(git rev-parse "$REMOTE/$BRANCH")"

if [[ "$local_sha" == "$remote_sha" ]]; then
	log "already up to date at $local_sha"
	exit 0
fi

base_sha="$(git merge-base "$BRANCH" "$REMOTE/$BRANCH")"
if [[ "$base_sha" != "$local_sha" ]]; then
	log "local branch is not a fast-forward of $REMOTE/$BRANCH; refusing to pull"
	exit 1
fi

log "updating $BRANCH from $local_sha to $remote_sha"
git pull --ff-only "$REMOTE" "$BRANCH"

log "rebuilding and restarting docker compose service"
docker compose -f "$COMPOSE_FILE" up -d --build

log "deploy complete at $(git rev-parse "$BRANCH")"
