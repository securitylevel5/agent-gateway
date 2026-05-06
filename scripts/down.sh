#!/usr/bin/env bash
# Stop the dev stack started by ./scripts/up.sh.

set -euo pipefail
cd "$(dirname "$0")/.."

PIDS_DIR=".run"

for svc in gateway dashboard; do
    if [[ -f "$PIDS_DIR/$svc.pid" ]]; then
        PID=$(cat "$PIDS_DIR/$svc.pid")
        if kill -0 "$PID" 2>/dev/null; then
            echo "Stopping $svc (pid $PID)"
            kill "$PID" 2>/dev/null || true
        fi
        rm -f "$PIDS_DIR/$svc.pid"
    fi
done

echo "Stopping postgres + otel-collector"
docker compose -f docker-compose.postgres.yml down

echo "Done."
