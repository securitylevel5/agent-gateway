#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.demo.yml"
COMPOSE_PROJECT_NAME="${AGENT_GATEWAY_DEMO_COMPOSE_PROJECT:-agent_gateway_demo}"
COMPOSE_CMD=()
COMPOSE_DISPLAY=""

PRINCIPAL="${AGENT_GATEWAY_DEMO_PRINCIPAL:-org-alice}"
IDENTITY="${AGENT_GATEWAY_DEMO_IDENTITY:-agent-alpha}"
HANDLE="${AGENT_GATEWAY_DEMO_HANDLE:-$IDENTITY}"
STATE_ROOT="${AGENT_GATEWAY_DEMO_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/agent-gateway/demo-agents}"
TPM2_PKCS11_STORE="${AGENT_GATEWAY_DEMO_TPM2_PKCS11_STORE:-$STATE_ROOT/tpm2-pkcs11}"
USER_PIN="${AGENT_GATEWAY_TPM_USER_PIN:-agentgateway}"
SO_PIN="${AGENT_GATEWAY_TPM_SO_PIN:-agentgateway-so}"
DATABASE_URL="${AGENT_GATEWAY_DATABASE_URL:-postgres://agent_gateway_admin:agent_gateway_dev@127.0.0.1:5432/agent_gateway}"
GATEWAY="${AGENT_GATEWAY_DEMO_GATEWAY:-127.0.0.1:8443}"
GATEWAY_CA="${AGENT_GATEWAY_DEMO_GATEWAY_CA:-$REPO_ROOT/certs/server-ca.pem}"
MOCK_CA="${AGENT_GATEWAY_DEMO_MOCK_CA:-$REPO_ROOT/certs/mock-ca.pem}"
SIDECAR_BIN="$REPO_ROOT/target/debug/agent_gateway_sidecar"
RESET_SERVER_PORT="${AGENT_GATEWAY_DEMO_RESET_SERVER_PORT:-8765}"
PIDS_DIR="$REPO_ROOT/.run"

RESET_MODE=false
if [[ "${1:-}" == "--reset" ]]; then
  RESET_MODE=true
fi

export COMPOSE_PROJECT_NAME

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

select_compose() {
  if command -v podman >/dev/null 2>&1; then
    if podman compose version >/dev/null 2>&1; then
      COMPOSE_CMD=(podman compose)
      COMPOSE_DISPLAY="podman compose"
      return
    fi
    if command -v podman-compose >/dev/null 2>&1; then
      COMPOSE_CMD=(podman-compose)
      COMPOSE_DISPLAY="podman-compose"
      return
    fi

    echo "error: podman is installed, but neither 'podman compose' nor 'podman-compose' is available" >&2
    exit 1
  fi

  if command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      COMPOSE_CMD=(docker compose)
      COMPOSE_DISPLAY="docker compose"
      return
    fi

    echo "error: docker is installed, but 'docker compose' is not available" >&2
    exit 1
  fi

  echo "error: install podman with compose support or docker with the compose plugin" >&2
  exit 1
}

compose() {
  "${COMPOSE_CMD[@]}" -p "$COMPOSE_PROJECT_NAME" -f "$COMPOSE_FILE" "$@"
}

wait_for_postgres() {
  echo "==> Waiting for Postgres"
  for _ in $(seq 1 60); do
    if psql "$DATABASE_URL" -tAc "SELECT 1" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done

  echo "error: Postgres did not become ready" >&2
  compose logs --no-color postgres >&2 || true
  exit 1
}

apply_migrations() {
  echo "==> Applying database migrations"
  if [[ "$(psql "$DATABASE_URL" -tAc "SELECT to_regclass('public.agent_gateway_schema_version') IS NOT NULL")" == "t" ]]; then
    echo "authorization registry already migrated"
    return
  fi

  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$REPO_ROOT/migrations/0001_signed_authorization_registry.sql"
}

state_dir() {
  printf '%s/%s\n' "$STATE_ROOT" "$HANDLE"
}

clear_enrollment() {
  echo "==> Stopping sidecar"
  local sidecar_pid_file
  sidecar_pid_file="$(state_dir)/sidecar_pid"
  if [[ -f "$sidecar_pid_file" ]]; then
    local pid
    pid="$(<"$sidecar_pid_file")"
    kill "$pid" 2>/dev/null || true
  fi

  echo "==> Clearing agent state and TPM store"
  rm -rf "$STATE_ROOT" "$TPM2_PKCS11_STORE"

  echo "==> Clearing enrollment records from database"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
DELETE FROM permission_registry;
DELETE FROM principal_key_permissions;
DELETE FROM principal_signing_keys;
SQL
}

enroll() {
  demo_env=(
    "AGENT_GATEWAY_DATABASE_URL=$DATABASE_URL"
    "AGENT_GATEWAY_DEMO_GATEWAY=$GATEWAY"
    "AGENT_GATEWAY_DEMO_GATEWAY_CA=$GATEWAY_CA"
    "AGENT_GATEWAY_DEMO_MOCK_CA=$MOCK_CA"
    "AGENT_GATEWAY_DEMO_SIDECAR_BIN=$SIDECAR_BIN"
    "AGENT_GATEWAY_DEMO_STATE_DIR=$STATE_ROOT"
    "AGENT_GATEWAY_TPM_USER_PIN=$USER_PIN"
    "AGENT_GATEWAY_TPM_SO_PIN=$SO_PIN"
    "AGENT_GATEWAY_RESET_TPM_STORE=false"
    "CLAUDE_CODE_PROXY_RESOLVES_HOSTS=1"
    "CURL_CA_BUNDLE=$MOCK_CA"
    "NODE_EXTRA_CA_CERTS=$MOCK_CA"
    "SSL_CERT_FILE=$MOCK_CA"
    "TPM2_PKCS11_STORE=$TPM2_PKCS11_STORE"
    "AGENT_GATEWAY_DEMO_DASHBOARD_URL=http://localhost:3000"
  )

  echo "==> Registering demo principal $PRINCIPAL"
  env "${demo_env[@]}" "$REPO_ROOT/registry-cli/register-principal-key.sh" "$PRINCIPAL"

  echo "==> Granting demo scopes"
  env "${demo_env[@]}" "$REPO_ROOT/registry-cli/grant-principal-scope.sh" "$PRINCIPAL" docstore messaging api.anthropic.com

  echo "==> Creating demo agent $HANDLE"
  env "${demo_env[@]}" "$SCRIPT_DIR/demo-agent.sh" create \
    --identity "$IDENTITY" \
    --handle "$HANDLE" \
    --grant docstore \
    --grant api.anthropic.com >/dev/null
}

start_reset_server() {
  mkdir -p "$PIDS_DIR"

  # Kill any existing reset server
  if [[ -f "$PIDS_DIR/reset-server.pid" ]]; then
    kill "$(<"$PIDS_DIR/reset-server.pid")" 2>/dev/null || true
    rm -f "$PIDS_DIR/reset-server.pid"
  fi

  local setup_script="$SCRIPT_DIR/setup.sh"
  nohup node -e "
    const http = require('http');
    const { spawn } = require('child_process');
    http.createServer((req, res) => {
      if (req.method !== 'POST' || new URL(req.url, 'http://x').pathname !== '/reset') {
        res.writeHead(404); res.end(); return;
      }
      const proc = spawn('bash', ['$setup_script', '--reset'], { stdio: 'inherit' });
      proc.on('exit', code => {
        res.writeHead(code === 0 ? 200 : 500, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({ ok: code === 0 }));
      });
    }).listen($RESET_SERVER_PORT, '0.0.0.0', () => {
      process.stdout.write('Reset server listening on $RESET_SERVER_PORT\n');
    });
  " > "$PIDS_DIR/reset-server.log" 2>&1 &
  echo $! > "$PIDS_DIR/reset-server.pid"
  echo "==> Reset server started on port $RESET_SERVER_PORT"
}

# ── Main ──────────────────────────────────────────────────────────────────────

select_compose
require_cmd cargo
require_cmd openssl
require_cmd psql
require_cmd node

cd "$REPO_ROOT"

if [[ "$RESET_MODE" == "true" ]]; then
  clear_enrollment
  enroll
  echo "Reset complete."
  exit 0
fi

echo "==> Generating demo TLS certificates"
"$SCRIPT_DIR/generate-server-certs.sh"

if [[ ! -f "$REPO_ROOT/config.toml" ]]; then
  echo "==> Creating config.toml from config.example.toml"
  cp "$REPO_ROOT/config.example.toml" "$REPO_ROOT/config.toml"
fi
# Ensure the gateway (running in Docker) sends OTLP to the collector service name,
# not localhost (which would be the gateway container itself).
sed -i 's|otlp_endpoint = "http://localhost:4317"|otlp_endpoint = "http://otel-collector:4317"|' "$REPO_ROOT/config.toml"

echo "==> Building local sidecar"
cargo build -p agent_gateway_sidecar

echo "==> Building gateway image"
compose build gateway

echo "==> Starting Postgres and mock HTTPS services"
compose up -d --force-recreate postgres mock-services
wait_for_postgres
apply_migrations

echo "==> Starting gateway, otel-collector, and dashboard"
compose up -d --force-recreate gateway otel-collector dashboard

enroll
start_reset_server

cat <<EOF

Demo is ready.

Dashboard: http://localhost:3000

Mock service URLs available through the gateway:
  https://docstore/health
  https://docstore/documents
  https://messaging/health
  https://messaging/messages

Prompt the demo agent with:
  ./demo/demo-agent.sh prompt "$HANDLE" --prompt "Use the Bash tool to run exactly these commands: curl -sS https://docstore/documents and curl -sS https://messaging/messages. Then summarize what you found."

Useful logs:
  $COMPOSE_DISPLAY -p "$COMPOSE_PROJECT_NAME" -f docker-compose.demo.yml logs -f gateway
  $(state_dir)/sidecar.log
EOF
