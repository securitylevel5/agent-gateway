#!/usr/bin/env bash
# Bring up the full dev stack:
#   - postgres + otel-collector (docker)
#   - gateway (cargo run)
#   - dashboard (node)
#
# Idempotent. PID files and logs land in ./.run/ so ./scripts/down.sh can
# stop the host-side processes.

set -euo pipefail
cd "$(dirname "$0")/.."

PIDS_DIR="$(pwd)/.run"
mkdir -p "$PIDS_DIR"

echo "==> docker compose: postgres + otel-collector"
docker compose -f docker-compose.postgres.yml up -d

if [[ ! -f certs/server.pem ]]; then
    echo "==> Generating server TLS certs"
    ./examples/generate-certs.sh
fi

# generate-certs.sh produces server material only. The gateway also wants a
# client_ca_path, normally populated by sidecar enrollments via connect.sh.
# Seed it with the server CA so the gateway can boot; it'll reject any
# client until real machine-client CAs are appended.
if [[ ! -f certs/client-ca-bundle.pem ]]; then
    cp certs/server-ca.pem certs/client-ca-bundle.pem
fi

if [[ ! -f config.toml ]]; then
    echo "==> Seeding config.toml from config.example.toml"
    cp config.example.toml config.toml
fi

echo "==> Building gateway (release)"
cargo build --release --quiet

printf "==> Waiting for postgres "
until docker compose -f docker-compose.postgres.yml ps postgres --format json \
        2>/dev/null | grep -q '"Health":"healthy"'; do
    sleep 1
    printf "."
done
echo " ready"

export AGENT_GATEWAY_DATABASE_URL="postgres://agent_gateway_admin:agent_gateway_dev@localhost:5432/agent_gateway"
echo "==> Running migrations"
cargo run --release --quiet -- --config config.toml migrate

echo "==> Starting gateway"
nohup cargo run --release --quiet -- --config config.toml \
    > "$PIDS_DIR/gateway.log" 2>&1 &
echo $! > "$PIDS_DIR/gateway.pid"

echo "==> Installing dashboard dependencies"
(cd dashboard && npm install --silent --no-audit --no-fund)

echo "==> Starting dashboard"
nohup node dashboard/server.js > "$PIDS_DIR/dashboard.log" 2>&1 &
echo $! > "$PIDS_DIR/dashboard.pid"

# Brief wait so the URLs we print actually serve.
sleep 1

cat <<EOF

All services up:
  Dashboard:   http://localhost:3000
  Gateway:     127.0.0.1:8443  (mTLS)
  OTLP gRPC:   localhost:4317  (collector intake)
  Postgres:    localhost:5432

Logs:    $PIDS_DIR/*.log
Stop:    ./scripts/down.sh
EOF
