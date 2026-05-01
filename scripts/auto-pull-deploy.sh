#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

REPO_DIR="${HAVEN_BACKEND_REPO:-$DEFAULT_REPO_DIR}"
BRANCH="${HAVEN_BACKEND_BRANCH:-master}"
REMOTE="${HAVEN_BACKEND_REMOTE:-origin}"
COMPOSE_FILE="${HAVEN_BACKEND_COMPOSE_FILE:-docker-compose.yml}"
LOCK_FILE="${HAVEN_BACKEND_LOCK_FILE:-/tmp/haven-backend-auto-pull.lock}"
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"
DISCORD_USERNAME="${DISCORD_USERNAME:-Haven Backend Deploy}"
CURRENT_STEP="starting"

log() {
	printf '[%s] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$*"
}

json_escape() {
	local value="$1"
	value="${value//\\/\\\\}"
	value="${value//\"/\\\"}"
	value="${value//$'\n'/\\n}"
	value="${value//$'\r'/}"
	value="${value//$'\t'/\\t}"
	printf '%s' "$value"
}

send_discord() {
	local title="$1"
	local description="$2"
	local color="$3"

	if [[ -z "$DISCORD_WEBHOOK_URL" ]]; then
		return 0
	fi

	if ! command -v curl >/dev/null 2>&1; then
		log "curl not found; cannot send discord webhook"
		return 0
	fi

	local payload
	payload=$(printf '{"username":"%s","embeds":[{"title":"%s","description":"%s","color":%s}]}' \
		"$(json_escape "$DISCORD_USERNAME")" \
		"$(json_escape "$title")" \
		"$(json_escape "$description")" \
		"$color")

	curl --fail --silent --show-error \
		-H "Content-Type: application/json" \
		-d "$payload" \
		"$DISCORD_WEBHOOK_URL" >/dev/null || log "discord webhook send failed"
}

on_error() {
	local exit_code=$?
	send_discord \
		"Haven backend deploy failed" \
		"Step: ${CURRENT_STEP}\nRepo: ${REPO_DIR}\nBranch: ${BRANCH}\nExit: ${exit_code}" \
		15158332
	exit "$exit_code"
}

trap on_error ERR

fail_deploy() {
	local message="$1"
	local exit_code="${2:-1}"
	log "$message"
	send_discord \
		"Haven backend deploy failed" \
		"Step: ${CURRENT_STEP}\nRepo: ${REPO_DIR}\nBranch: ${BRANCH}\nError: ${message}" \
		15158332
	exit "$exit_code"
}

CURRENT_STEP="opening repository"
cd "$REPO_DIR"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
	log "another update is already running"
	exit 0
fi

CURRENT_STEP="checking local changes"
if ! git diff --quiet || ! git diff --cached --quiet; then
	git status --short
	fail_deploy "local changes present; refusing to pull"
fi

CURRENT_STEP="fetching remote"
git fetch --prune "$REMOTE" "$BRANCH"

local_sha="$(git rev-parse "$BRANCH")"
remote_sha="$(git rev-parse "$REMOTE/$BRANCH")"

if [[ "$local_sha" == "$remote_sha" ]]; then
	log "already up to date at $local_sha"
	exit 0
fi

CURRENT_STEP="checking fast-forward safety"
base_sha="$(git merge-base "$BRANCH" "$REMOTE/$BRANCH")"
if [[ "$base_sha" != "$local_sha" ]]; then
	fail_deploy "local branch is not a fast-forward of $REMOTE/$BRANCH; refusing to pull"
fi

log "updating $BRANCH from $local_sha to $remote_sha"
send_discord \
	"Haven backend update found" \
	"Branch: ${BRANCH}\nFrom: ${local_sha}\nTo: ${remote_sha}" \
	3447003

CURRENT_STEP="pulling latest commit"
git pull --ff-only "$REMOTE" "$BRANCH"

log "rebuilding and restarting docker compose service"
CURRENT_STEP="rebuilding docker compose service"
docker compose -f "$COMPOSE_FILE" up -d --build

deployed_sha="$(git rev-parse "$BRANCH")"
log "deploy complete at $deployed_sha"
send_discord \
	"Haven backend deploy succeeded" \
	"Branch: ${BRANCH}\nCommit: ${deployed_sha}" \
	3066993
