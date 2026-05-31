#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="${repo_dir}/frontend/login"
web_root="/var/www/continental-id-login"
caddyfile="/etc/caddy/Caddyfile"
site_block_source="${repo_dir}/deploy/Caddyfile.login"
site_host="login.continental-hub.com"

if [[ ! -d "${source_dir}" ]]; then
  printf 'Login source directory not found: %s\n' "${source_dir}" >&2
  exit 1
fi

if [[ ! -f "${site_block_source}" ]]; then
  printf 'Caddy site block not found: %s\n' "${site_block_source}" >&2
  exit 1
fi

sudo install -d -o caddy -g caddy "${web_root}"
sudo rsync -a --delete "${source_dir}/" "${web_root}/"

if ! sudo grep -q "${site_host}" "${caddyfile}"; then
  printf '\n%s\n' "$(cat "${site_block_source}")" | sudo tee -a "${caddyfile}" >/dev/null
fi

sudo caddy validate --config "${caddyfile}"
sudo systemctl reload caddy

printf 'Published %s from %s and reloaded Caddy.\n' "${site_host}" "${source_dir}"
