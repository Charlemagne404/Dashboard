#!/usr/bin/env bash

set -Eeuo pipefail

SOURCE_BACKEND="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SOURCE_BACKEND" rev-parse --show-toplevel)"
SERVICE_NAME="${SERVICE_NAME:-continental-id-auth.service}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:5000/api/health}"
REMOTE_NAME="${REMOTE_NAME:-origin}"
AUTO_STASH="${AUTO_STASH:-false}"
DEPLOY_DIR="${DEPLOY_DIR:-}"
BACKUP_DIR=""
DEPLOYMENT_STARTED=false

usage() {
  cat <<'EOF'
Usage: ./backend/deploy-backend.sh [--stash]

Fetches and fast-forward updates the current branch, runs backend checks,
validates the production environment, stages the backend into the systemd
WorkingDirectory while preserving its .env, installs locked production
dependencies, restarts the service, and verifies health. A source backup is
kept beside the deployment directory for rollback.

Options:
  --stash    Stash uncommitted changes, including untracked files, before pulling.
  -h, --help Show this help text.

Environment overrides:
  SERVICE_NAME   User systemd service (default: continental-id-auth.service)
  DEPLOY_DIR     Deployment directory (defaults to the unit WorkingDirectory)
  HEALTH_URL     Health URL (default: http://127.0.0.1:5000/api/health)
  REMOTE_NAME    Git remote (default: origin)
  AUTO_STASH     Set to true to behave like --stash.
EOF
}

log() { printf '[deploy] %s\n' "$*"; }
fail() { printf '[deploy] ERROR: %s\n' "$*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"; }

try_health_url() {
  local payload
  payload="$(curl -fsS --max-time 5 "$HEALTH_URL")" || return 1
  printf '%s' "$payload" | node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{try{const h=JSON.parse(s);process.exit(h.status==='ok'&&h.maintenance?.status==='ok'?0:1)}catch{process.exit(1)}})"
}

wait_for_health() {
  local attempt
  for attempt in {1..30}; do
    if try_health_url; then
      curl -fsS --max-time 5 "$HEALTH_URL"
      return 0
    fi
    sleep 1
  done
  return 1
}

rollback_deployment() {
  [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]] || return 1
  log "Rolling back source in $DEPLOY_DIR from $BACKUP_DIR"
  systemctl --user stop "$SERVICE_NAME" || true
  rsync -a --delete --exclude='.env' --exclude='node_modules' --exclude='*.log' "$BACKUP_DIR/" "$DEPLOY_DIR/"
  (cd "$DEPLOY_DIR" && npm ci --omit=dev --no-audit --no-fund)
  systemctl --user start "$SERVICE_NAME"
  wait_for_health
}

on_exit() {
  local status=$?
  if [[ "$DEPLOYMENT_STARTED" == "true" && $status -ne 0 ]]; then
    if rollback_deployment; then
      log "Previous release restored and healthy. Backup kept at $BACKUP_DIR"
    else
      log "Automatic rollback did not complete. Inspect $SERVICE_NAME and backup $BACKUP_DIR"
    fi
  fi
  exit "$status"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stash) AUTO_STASH=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown argument: $1" ;;
  esac
done

for command in git npm curl systemctl rsync realpath node; do require_cmd "$command"; done

cd "$REPO_ROOT"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "Not inside a Git work tree."
branch="$(git branch --show-current)"
[[ -n "$branch" ]] || fail "Could not determine the current branch."

status_output="$(git status --short)"
if [[ -n "$status_output" && "$AUTO_STASH" != "true" ]]; then
  printf '%s\n' "$status_output"
  fail "Working tree is not clean. Commit or re-run with --stash."
fi
if [[ -n "$status_output" && "$AUTO_STASH" == "true" ]]; then
  stash_name="deploy-backup-$(date -u +%Y%m%dT%H%M%SZ)"
  log "Stashing local changes as $stash_name"
  git stash push -u -m "$stash_name" >/dev/null
fi

log "Fetching $REMOTE_NAME/$branch"
git fetch "$REMOTE_NAME"
pending_commits="$(git log --oneline "HEAD..$REMOTE_NAME/$branch" || true)"
if [[ -n "$pending_commits" ]]; then
  log "Incoming commits:"
  printf '%s\n' "$pending_commits"
fi
git pull --ff-only "$REMOTE_NAME" "$branch"

if [[ -z "$DEPLOY_DIR" ]]; then
  DEPLOY_DIR="$(systemctl --user show "$SERVICE_NAME" --property=WorkingDirectory --value)"
fi
[[ -n "$DEPLOY_DIR" && -d "$DEPLOY_DIR" ]] || fail "Could not resolve an existing systemd deployment directory. Set DEPLOY_DIR explicitly."
DEPLOY_DIR="$(realpath "$DEPLOY_DIR")"
SOURCE_BACKEND="$(realpath "$SOURCE_BACKEND")"
[[ -f "$DEPLOY_DIR/.env" ]] || fail "The deployment directory must contain its production .env file. It will not be copied from the checkout."

log "Installing locked checkout dependencies"
cd "$SOURCE_BACKEND"
npm ci --no-audit --no-fund
npm run check
npm run lint
npm run typecheck
npm test
npm run audit

log "Validating production configuration from $DEPLOY_DIR/.env"
NODE_ENV=production DOTENV_CONFIG_PATH="$DEPLOY_DIR/.env" node - <<'NODE'
const dotenv = require('dotenv');
dotenv.config({ path: process.env.DOTENV_CONFIG_PATH, quiet: true });
process.env.NODE_ENV = 'production';
require('./utils/runtimeConfig').assertRuntimeConfig(process.env);
NODE

BACKUP_DIR="${DEPLOY_DIR}.backup-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -m 700 "$BACKUP_DIR"
rsync -a --exclude='.env' --exclude='node_modules' --exclude='*.log' "$DEPLOY_DIR/" "$BACKUP_DIR/"

trap on_exit EXIT
log "Stopping $SERVICE_NAME"
systemctl --user stop "$SERVICE_NAME"
DEPLOYMENT_STARTED=true

if [[ "$DEPLOY_DIR" != "$SOURCE_BACKEND" ]]; then
  log "Syncing tested backend into $DEPLOY_DIR (preserving .env and installed modules)"
  rsync -a --delete --exclude='.env' --exclude='node_modules' --exclude='*.log' --exclude='.git' "$SOURCE_BACKEND/" "$DEPLOY_DIR/"
fi

log "Installing locked production dependencies in $DEPLOY_DIR"
(cd "$DEPLOY_DIR" && npm ci --omit=dev --no-audit --no-fund)
log "Starting $SERVICE_NAME"
systemctl --user start "$SERVICE_NAME"
systemctl --user status "$SERVICE_NAME" --no-pager

log "Verifying health at $HEALTH_URL"
wait_for_health || fail "Health check did not report healthy service and startup maintenance."

DEPLOYMENT_STARTED=false
if [[ -n "$BACKUP_DIR" ]]; then log "Previous source backup: $BACKUP_DIR"; fi
log "Deployment completed successfully"
