#!/usr/bin/env bash
# Local S3-compatible object store for the artifact store (development only).
#
# The MinIO community Docker images are no longer published, so this uses RustFS. The code only
# speaks the S3 API, so any S3 endpoint works instead (Garage, SeaweedFS, Vultr Object Storage...):
# change the MINILOCKER_S3_* variables, nothing else.
#
#   ./deploy/dev-storage.sh          start (or restart) and print the env vars to export
#   ./deploy/dev-storage.sh stop     stop and remove the container (data volume is kept)
set -euo pipefail

NAME=minilocker-storage
IMAGE="${MINILOCKER_STORAGE_IMAGE:-rustfs/rustfs:latest}"   # pin a tag once you have a good one
PORT="${MINILOCKER_STORAGE_PORT:-9000}"
ACCESS="${MINILOCKER_S3_ACCESS_KEY:-minilocker-dev}"
SECRET="${MINILOCKER_S3_SECRET_KEY:-minilocker-dev-secret-change-me}"

if [ "${1:-}" = "stop" ]; then docker rm -f "$NAME" >/dev/null 2>&1 && echo "stopped $NAME"; exit 0; fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
# Bound to 127.0.0.1: reachable by the control plane on this machine, not from the network.
# It is NOT on the sandboxes' network, so no sandbox can reach it.
docker run -d --name "$NAME" --restart unless-stopped \
  -p "127.0.0.1:${PORT}:9000" \
  -v minilocker-storage:/data \
  -e RUSTFS_ACCESS_KEY="$ACCESS" -e RUSTFS_SECRET_KEY="$SECRET" \
  "$IMAGE" /data >/dev/null

echo "waiting for the S3 endpoint on 127.0.0.1:${PORT} ..."
for _ in $(seq 1 30); do
  if curl -s -o /dev/null "http://127.0.0.1:${PORT}/"; then ready=1; break; fi
  sleep 1
done
[ "${ready:-}" = 1 ] || { echo "storage did not come up; see: docker logs $NAME" >&2; exit 1; }

cat <<ENV

Ready. Export these in the shell that runs the API (the bucket is created automatically):

export MINILOCKER_S3_ENDPOINT=http://127.0.0.1:${PORT}
export MINILOCKER_S3_ACCESS_KEY=${ACCESS}
export MINILOCKER_S3_SECRET_KEY=${SECRET}
ENV
