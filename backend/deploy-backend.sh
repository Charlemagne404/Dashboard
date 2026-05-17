#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="${SERVICE_NAME:-continental-id-auth.service}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:5000/api/health}"
REMOTE_NAME="${REMOTE_NAME:-origin}"
AUTO_STASH="${AUTO_STASH:-false}"

usage() {
  cat <<'EOF'
Usage: ./deploy-backend.sh [--stash]

Safely updates the current branch from Git, runs backend syntax checks,
restarts the user systemd service, and verifies local health.

Options:
  --stash    Stash uncommitted changes before pulling, then print stash info.
  -h, --help Show this help text.

Environment overrides:
  SERVICE_NAME   systemd user service to restart
  HEALTH_URL     health endpoint to verify after restart
  REMOTE_NAME    git remote to pull from
  AUTO_STASH     set to true to behave like --stash
EOF
}

log() {
  printf '[deploy] %s\n' "$*"
}

try_health_url() {
  local url="$1"
  log "Verifying health at $url"
  if [[ "$url" == https://* ]]; then
    curl -kfsS "$url"
  else
    curl -fsS "$url"
  fi
}

fail() {
  printf '[deploy] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stash)
      AUTO_STASH=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

require_cmd git
require_cmd npm
require_cmd curl
require_cmd systemctl

cd "$ROOT_DIR"

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "Not inside a git work tree."

branch="$(git branch --show-current)"
[[ -n "$branch" ]] || fail "Could not determine the current git branch."

status_output="$(git status --short)"
stash_name=""

if [[ -n "$status_output" && "$AUTO_STASH" != "true" ]]; then
  printf '%s\n' "$status_output"
  fail "Working tree is not clean. Commit or re-run with --stash."
fi

if [[ -n "$status_output" && "$AUTO_STASH" == "true" ]]; then
  stash_name="deploy-backup-$(date +%Y%m%dT%H%M%S)"
  log "Stashing local changes as $stash_name"
  git stash push -u -m "$stash_name" >/dev/null
fi

log "Fetching $REMOTE_NAME/$branch"
git fetch "$REMOTE_NAME"

pending_commits="$(git log --oneline --decorate "HEAD..$REMOTE_NAME/$branch" || true)"
if [[ -z "$pending_commits" ]]; then
  log "Already up to date with $REMOTE_NAME/$branch"
else
  log "Incoming commits:"
  printf '%s\n' "$pending_commits"
fi

log "Pulling with --ff-only"
git pull --ff-only "$REMOTE_NAME" "$branch"

log "Running npm run check"
npm run check

log "Restarting user service $SERVICE_NAME"
systemctl --user restart "$SERVICE_NAME"

log "Checking service status"
systemctl --user status "$SERVICE_NAME" --no-pager

if try_health_url "$HEALTH_URL"; then
  printf '\n'
elif [[ "$HEALTH_URL" == "http://127.0.0.1:5000/api/health" ]] && try_health_url "https://127.0.0.1:5000/api/health"; then
  printf '\n'
else
  fail "Health check failed."
fi

if [[ -n "$stash_name" ]]; then
  log "Local changes were stashed as $stash_name"
  log "Review with: git stash list"
fi

log "Deploy completed successfully"
