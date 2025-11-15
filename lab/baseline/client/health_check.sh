#!/bin/bash
set -euo pipefail

DEFAULT_GATEWAY="${CLIENT_GATEWAY:-172.30.0.254}"
TARGET_HOST_IP="${HAPROXY_IP:-172.31.0.10}"
TARGET_HOSTNAME="${TARGET_HOSTNAME:-haproxy.example.internal}"
TARGET_PORT="${HAPROXY_PORT:-443}"
TARGET_SCHEME="${SCHEME:-https}"

echo "[client] configuring default route via ${DEFAULT_GATEWAY}"
ip route replace default via "$DEFAULT_GATEWAY"

TARGET_URL="${TARGET_SCHEME}://${TARGET_HOSTNAME}:${TARGET_PORT}/healthz"
RESOLVE_ARG="--resolve ${TARGET_HOSTNAME}:${TARGET_PORT}:${TARGET_HOST_IP}"
echo "[client] sending request to ${TARGET_URL} via ${TARGET_HOST_IP} (SNI=${TARGET_HOSTNAME})"
curl -v --insecure --fail $RESOLVE_ARG "$TARGET_URL"
echo "[client] request completed"
