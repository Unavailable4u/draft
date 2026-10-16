#!/usr/bin/env bash
# Provision MiniLocker on a fresh Ubuntu 22.04/24.04 VM (or any Linux with Docker).
#
#   git clone <repo> && cd <repo>
#   sudo ./deploy/bootstrap.sh              # installs Docker if needed, builds, starts, smoke-tests
#   ./deploy/bootstrap.sh --env-only        # just create/complete deploy/.env, touch nothing else
#   ./deploy/bootstrap.sh --skip-smoke      # do not run the post-start containment smoke test
#
# Idempotent: safe to re-run after editing deploy/.env or pulling new code.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$ROOT/deploy"
ENV_FILE="${MINILOCKER_BOOTSTRAP_ENV_FILE:-$DEPLOY/.env}"
COMPOSE=(docker compose -f "$DEPLOY/docker-compose.yml")

ENV_ONLY=0
SKIP_SMOKE=0
for arg in "$@"; do
  case "$arg" in
    --env-only) ENV_ONLY=1 ;;
    --skip-smoke) SKIP_SMOKE=1 ;;
    -h|--help) sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# env_get KEY: the value in $ENV_FILE (last one wins; Windows line endings and quotes stripped).
env_get() {
  [ -f "$ENV_FILE" ] || return 0
  { grep -E "^${1}=" "$ENV_FILE" || true; } | tail -n1 | cut -d= -f2- | tr -d '\r' \
    | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

# env_set KEY VALUE: replace the line, or append it. Only for generated values (hex): no backslashes.
env_set() {
  local tmp
  tmp="$(mktemp)"
  awk -v k="$1" -v v="$2" 'BEGIN { FS = OFS = "=" } $1 == k { $0 = k "=" v; done = 1 } { print } END { if (!done) print k "=" v }' \
    "$ENV_FILE" > "$tmp"
  cat "$tmp" > "$ENV_FILE"      # keep the file's owner and mode
  rm -f "$tmp"
}

# A hand-appended `echo KEY=value >> .env` onto a file with no trailing newline glues two settings
# together (LLM_API_KEY=sk-...HTTP_PORT=8080) and nothing complains. Name the line, never the value.
check_env_sanity() {
  local n key bad=0
  while IFS=: read -r n _; do
    [ -n "$n" ] || continue
    key="$(sed -n "${n}p" "$ENV_FILE" | cut -d= -f1)"
    printf 'error: line %s of %s (%s=...) has another setting glued onto the end of its value.\n' "$n" "$ENV_FILE" "$key" >&2
    bad=1
  done < <({ grep -nE '^[A-Za-z_][A-Za-z0-9_]*=.*(LLM_[A-Z_]+|MINILOCKER_[A-Z0-9_]+|SITE_ADDRESS|HTTPS?_PORT)=' "$ENV_FILE" || true; })
  if [ "$bad" -eq 1 ]; then
    printf '%s\n' "Put each setting on its own line and trim that value. (Append safely with: printf '\\nKEY=value\\n' >> deploy/.env)" >&2
    return 2
  fi
}

prepare_env() {
  if [ ! -f "$ENV_FILE" ]; then
    cp "$DEPLOY/env.production.example" "$ENV_FILE"
    log "created $ENV_FILE from env.production.example"
  fi
  chmod 600 "$ENV_FILE"
  check_env_sanity || return $?

  if [ -z "$(env_get MINILOCKER_API_TOKEN)" ]; then
    env_set MINILOCKER_API_TOKEN "$(openssl rand -hex 24)"
    log "generated MINILOCKER_API_TOKEN"
  fi
  local secret
  secret="$(env_get MINILOCKER_S3_SECRET_KEY)"
  if [ -z "$secret" ] || [ "$secret" = "minilocker-dev-secret-change-me" ]; then
    env_set MINILOCKER_S3_SECRET_KEY "$(openssl rand -hex 24)"
    log "generated MINILOCKER_S3_SECRET_KEY"
  fi
  if [ -z "$(env_get MINILOCKER_S3_ACCESS_KEY)" ]; then
    env_set MINILOCKER_S3_ACCESS_KEY minilocker
  fi

  local missing=() v
  for v in LLM_BASE_URL LLM_MODEL LLM_API_KEY; do
    [ -n "$(env_get "$v")" ] || missing+=("$v")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    printf '\n%s\n' "Fill in these settings in $ENV_FILE, then run this script again:" >&2
    printf '  %s\n' "${missing[@]}" >&2
    return 2
  fi
}

install_docker() {
  if command -v docker >/dev/null 2>&1; then
    log "Docker present: $(docker --version)"
  else
    [ "$(id -u)" -eq 0 ] || die "Docker is not installed; run this script with sudo to install it"
    log "installing Docker (get.docker.com)"
    curl -fsSL https://get.docker.com | sh
  fi
  docker compose version >/dev/null 2>&1 || die "the 'docker compose' plugin is missing (apt-get install docker-compose-plugin)"
  docker info >/dev/null 2>&1 || die "cannot reach the Docker daemon (is it running? are you in the docker group, or using sudo?)"
}

build_images() {
  log "building the browser sandbox image (first build takes several minutes)"
  docker build -f "$ROOT/images/browser/Dockerfile" \
    -t "$(env_get MINILOCKER_BROWSER_IMAGE | grep . || echo minilocker-browser:latest)" "$ROOT"
  log "pulling the code-sandbox base image"
  docker pull python:3.12-slim
  log "building the API and web images"
  "${COMPOSE[@]}" build
}

wait_for_api() {
  log "waiting for the API to become healthy"
  local _
  for _ in $(seq 1 60); do
    if "${COMPOSE[@]}" exec -T api python -c \
      "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  "${COMPOSE[@]}" logs --tail 40 api >&2 || true
  die "the API did not become healthy within 2 minutes (logs above)"
}

# Runs the rm -rf / attack through the real stack: Docker via the socket proxy, the packaged egress proxy,
# exec streaming, the ledger volume. No model is involved, so it works before the LLM key is proven.
smoke_test() {
  log "smoke test: rm -rf / through the real stack"
  local out verdict
  out="$("${COMPOSE[@]}" exec -T api python - < "$DEPLOY/smoke_check.py")" || out="request failed"
  verdict="$(printf '%s\n' "$out" | head -n1)"
  if [ "$verdict" != "contained" ]; then
    "${COMPOSE[@]}" logs --tail 60 api docker-proxy >&2 || true
    die "smoke test verdict was '$verdict', expected 'contained' (logs above)"
  fi
  echo "verdict:         contained"
  printf '%s\n' "$out" | tail -n +2
  if printf '%s' "$out" | grep -qE 'NOT |MISSING'; then
    printf '\nwarning: something above is not available; the stack runs, but some features will not work.\n' >&2
  fi
}

main() {
  prepare_env || exit $?
  [ "$ENV_ONLY" -eq 0 ] || { log "env ready: $ENV_FILE"; exit 0; }

  install_docker
  build_images
  log "starting the stack"
  "${COMPOSE[@]}" up -d
  wait_for_api
  [ "$SKIP_SMOKE" -eq 1 ] || smoke_test

  local site url ip port
  site="$(env_get SITE_ADDRESS)"
  site="${site:-:80}"
  port="$(env_get HTTP_PORT)"
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  case "$site" in
    :*) url="http://${ip:-localhost}$([ "${port:-80}" = 80 ] || printf ':%s' "$port")" ;;
    *)  url="https://${site}" ;;
  esac
  cat <<DONE

MiniLocker is up.
  URL:        ${url}
  API token:  $(env_get MINILOCKER_API_TOKEN)      (paste it into the UI's "API token" box)

  logs:       docker compose -f deploy/docker-compose.yml logs -f api
  stop:       docker compose -f deploy/docker-compose.yml down        (add -v to also delete the data)
DONE
}

main
