#!/bin/sh
set -eu

DATA_DIR="${CPA_DATA_DIR:-/data}"
CONFIG_PATH="${CPA_CONFIG_PATH:-$DATA_DIR/config.yaml}"
AUTH_DIR="${CPA_AUTH_DIR:-$DATA_DIR/auths}"
LOG_DIR="${CPA_LOG_DIR:-$DATA_DIR/logs}"
PORT_VALUE="${PORT:-8317}"
MANAGEMENT_SECRET="${MANAGEMENT_PASSWORD:-${CPA_MANAGEMENT_PASSWORD:-}}"
API_KEYS_VALUE="${CPA_API_KEYS:-${API_KEY:-}}"

mkdir -p "$DATA_DIR" "$AUTH_DIR" "$LOG_DIR"

if [ ! -s "$CONFIG_PATH" ]; then
  tmp_keys="$(mktemp)"
  if [ -n "$API_KEYS_VALUE" ]; then
    old_ifs="$IFS"
    IFS=","
    for key in $API_KEYS_VALUE; do
      trimmed="$(printf '%s' "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      if [ -n "$trimmed" ]; then
        printf '  - "%s"\n' "$trimmed" >> "$tmp_keys"
      fi
    done
    IFS="$old_ifs"
  fi
  if [ ! -s "$tmp_keys" ]; then
    printf '  - "change-me"\n' > "$tmp_keys"
  fi

  {
    cat <<EOF
host: "0.0.0.0"
port: $PORT_VALUE

tls:
  enable: false
  cert: ""
  key: ""

remote-management:
  allow-remote: true
  secret-key: "$MANAGEMENT_SECRET"
  disable-control-panel: false
  disable-auto-update-panel: false
  panel-github-repository: "https://github.com/router-for-me/Cli-Proxy-API-Management-Center"

auth-dir: "$AUTH_DIR"

api-keys:
EOF
    cat "$tmp_keys"
    cat <<EOF

debug: false
pprof:
  enable: false
  addr: "127.0.0.1:8316"

commercial-mode: false
logging-to-file: true
logs-max-total-size-mb: 512
error-logs-max-files: 20
usage-statistics-enabled: true
redis-usage-queue-retention-seconds: 300
proxy-url: ""
force-model-prefix: false
passthrough-headers: false
request-retry: 3
max-retry-credentials: 0
max-retry-interval: 30
disable-cooling: false
disable-image-generation: false

quota-exceeded:
  switch-project: true
  switch-preview-model: true
  antigravity-credits: true

routing:
  strategy: "round-robin"
  session-affinity: false
  session-affinity-ttl: "1h"

ws-auth: true
enable-gemini-cli-endpoint: false
nonstream-keepalive-interval: 0
EOF
  } > "$CONFIG_PATH"
  rm -f "$tmp_keys"
fi

exec /CLIProxyAPI/CLIProxyAPI -config "$CONFIG_PATH"
