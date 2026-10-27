#!/usr/bin/env bash
# Rehearse the deployment on a clean machine, twice, and check what a second run must not change.
#
#   git clone <repo> && cd <repo>
#   sudo LLM_BASE_URL=... LLM_MODEL=... LLM_API_KEY=... ./deploy/dry_run.sh
#
# Any clean Ubuntu 22.04/24.04 box will do: a throwaway VM, a cloud instance, a fresh WSL distro. It does what the real
# deployment does (deploy/bootstrap.sh, twice) and then checks the things a deployment gets wrong quietly:
#   1. the first run finishes, including the containment smoke test;
#   2. the API is healthy and refuses a request with no token (401) and accepts one with the token;
#   3. the generated secrets are mode 600 and are the SAME after the second run (a re-run must not rotate the token
#      the operator already pasted into the UI);
#   4. the second run finishes too, and nothing is left running that should not be (no sandbox from the smoke test);
#   5. the UI is served and the Infra endpoint answers.
# It prints one line per check and exits non-zero on the first failure. It never prints a secret.
# shellcheck disable=SC2015   # `check && pass || fail`: pass never fails, so this is an if-else
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${MINILOCKER_BOOTSTRAP_ENV_FILE:-$ROOT/deploy/.env}"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml")
FAILS=0

pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*" >&2; FAILS=$((FAILS + 1)); }
step() { printf '\n== %s\n' "$*"; }
env_get() { { grep -E "^${1}=" "$ENV_FILE" || true; } | tail -n1 | cut -d= -f2- | tr -d '\r'; }
sha() { env_get "$1" | sha256sum | cut -c1-16; }

# Seed the three model settings from the environment, so the script can run unattended.
if [ ! -f "$ENV_FILE" ]; then
  : "${LLM_BASE_URL:?set LLM_BASE_URL (and LLM_MODEL, LLM_API_KEY) in the environment, or create deploy/.env first}"
  : "${LLM_MODEL:?set LLM_MODEL}"
  : "${LLM_API_KEY:?set LLM_API_KEY}"
  "$ROOT/deploy/bootstrap.sh" --env-only >/dev/null 2>&1 || true      # creates the file and generates the secrets, then stops
  for kv in LLM_BASE_URL LLM_MODEL LLM_API_KEY; do
    tmp="$(mktemp)"
    awk -v k="$kv" -v v="${!kv}" 'BEGIN { FS = OFS = "=" } $1 == k { $0 = k "=" v; done = 1 } { print } END { if (!done) print k "=" v }' \
      "$ENV_FILE" > "$tmp" && cat "$tmp" > "$ENV_FILE"; rm -f "$tmp"
  done
fi

step "run 1: bootstrap"
if "$ROOT/deploy/bootstrap.sh"; then pass "bootstrap.sh finished (build, start, smoke test)"; else fail "bootstrap.sh run 1 failed"; exit 1; fi

TOKEN="$(env_get MINILOCKER_API_TOKEN)"
S3="$(env_get MINILOCKER_S3_SECRET_KEY)"
TOKEN_ID="$(sha MINILOCKER_API_TOKEN)"; S3_ID="$(sha MINILOCKER_S3_SECRET_KEY)"
PORT="$(env_get HTTP_PORT)"; PORT="${PORT:-80}"
BASE="http://127.0.0.1:${PORT}"
[ "$(env_get SITE_ADDRESS)" = "" ] || case "$(env_get SITE_ADDRESS)" in :*) ;; *) BASE="https://$(env_get SITE_ADDRESS)" ;; esac

step "checks after run 1"
[ -n "$TOKEN" ] && [ "${#TOKEN}" -ge 32 ] && pass "an API token was generated (${#TOKEN} chars)" || fail "no API token, or a short one"
[ -n "$S3" ] && [ "$S3" != "minilocker-dev-secret-change-me" ] && pass "the storage secret was generated" || fail "the storage secret is empty or the example value"
mode="$(stat -c %a "$ENV_FILE")"
[ "$mode" = "600" ] && pass "deploy/.env is mode 600" || fail "deploy/.env is mode $mode, expected 600"
if git -C "$ROOT" check-ignore -q "$ENV_FILE" 2>/dev/null || ! git -C "$ROOT" rev-parse >/dev/null 2>&1; then pass "deploy/.env is not tracked by git"; else fail "deploy/.env would be committed"; fi

code="$(curl -ks -o /dev/null -w '%{http_code}' "$BASE/api/tasks")"
[ "$code" = "401" ] && pass "GET /api/tasks without a token is refused (401)" || fail "GET /api/tasks without a token returned $code, expected 401"
code="$(curl -ks -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/api/tasks")"
[ "$code" = "200" ] && pass "GET /api/tasks with the token works (200)" || fail "GET /api/tasks with the token returned $code"
code="$(curl -ks -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/api/infra")"
[ "$code" = "200" ] && pass "the Infra endpoint answers (200)" || fail "GET /api/infra returned $code"
curl -ks "$BASE/" | grep -qi '<div id="root"' && pass "the UI is served" || fail "the UI did not come back from $BASE/"
left="$(docker ps -a --filter label=minilocker=sandbox --format '{{.Names}}' | wc -l)"
[ "$left" = "0" ] && pass "no sandbox container left over from the smoke test" || fail "$left sandbox container(s) left over"

step "run 2: bootstrap again (must be idempotent)"
if "$ROOT/deploy/bootstrap.sh"; then pass "bootstrap.sh finished again"; else fail "bootstrap.sh run 2 failed"; fi

step "checks after run 2"
[ "$(sha MINILOCKER_API_TOKEN)" = "$TOKEN_ID" ] && pass "the API token did not change" || fail "the API token CHANGED on the second run"
[ "$(sha MINILOCKER_S3_SECRET_KEY)" = "$S3_ID" ] && pass "the storage secret did not change" || fail "the storage secret CHANGED on the second run"
code="$(curl -ks -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/api/tasks")"
[ "$code" = "200" ] && pass "the same token still works" || fail "the token no longer works ($code)"
n="$("${COMPOSE[@]}" ps --status running --format '{{.Service}}' | sort -u | wc -l)"
[ "$n" -ge 4 ] && pass "$n services running" || fail "only $n services running (expected api, web, storage and the docker proxy)"
left="$(docker ps -a --filter label=minilocker=sandbox --format '{{.Names}}' | wc -l)"
[ "$left" = "0" ] && pass "no sandbox left over" || fail "$left sandbox container(s) left over"

step "result"
if [ "$FAILS" -eq 0 ]; then echo "All checks passed. Write the date, the machine and the commit in the checklist (docs/DEPLOY_DRYRUN.md)."; else echo "$FAILS check(s) failed." >&2; exit 1; fi
