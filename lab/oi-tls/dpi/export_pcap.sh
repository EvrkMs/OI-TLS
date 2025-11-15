#!/bin/bash
set -euo pipefail
CAP_DIR=$(cd "$(dirname "$0")/captures" && pwd)
CAP_NAME=${1:-oi-tls.pcap}
TEXT_NAME=${2:-${CAP_NAME}.txt}
SUMMARY_NAME=${3:-${CAP_NAME}.sni.txt}
PCAP_PATH="$CAP_DIR/$CAP_NAME"
if [ ! -f "$PCAP_PATH" ]; then
  echo "[export] capture not found: $PCAP_PATH" >&2
  exit 1
fi
IMAGE=${PCAP_TEXT_IMAGE:-nicolaka/netshoot}
CMD="if ! command -v tshark >/dev/null 2>&1; then echo 'tshark missing' >&2; exit 1; fi; \
  tshark -r /pcaps/$CAP_NAME -O tls > /pcaps/$TEXT_NAME; \
  tshark -r /pcaps/$CAP_NAME -Y 'tls.handshake.extensions_server_name' -T fields -e frame.number -e ip.src -e ip.dst -e tls.handshake.extensions_server_name > /pcaps/$SUMMARY_NAME"
docker run --rm -v "$CAP_DIR":/pcaps "$IMAGE" /bin/sh -c "$CMD"
echo "[export] Raw capture: $PCAP_PATH"
echo "[export] TLS-decoded text: $CAP_DIR/$TEXT_NAME"
echo "[export] SNI summary: $CAP_DIR/$SUMMARY_NAME"
