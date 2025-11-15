#!/bin/sh
set -euo pipefail

CLIENT_SELF_IP=${CLIENT_SELF_IP:-172.30.0.254}
SERVER_SELF_IP=${SERVER_SELF_IP:-172.31.0.254}

detect_iface() {
  ip_addr="$1"
  ip -o -4 addr show | awk -v needle="$ip_addr" '$4 ~ ("^" needle "/") {print $2; exit}'
}

CLIENT_IFACE=${CLIENT_IFACE:-$(detect_iface "$CLIENT_SELF_IP")}
SERVER_IFACE=${SERVER_IFACE:-$(detect_iface "$SERVER_SELF_IP")}

if [ -z "$CLIENT_IFACE" ] || [ -z "$SERVER_IFACE" ]; then
  echo "[DPI] Unable to detect interfaces (client=$CLIENT_IFACE server=$SERVER_IFACE)" >&2
  exit 1
fi

CAPTURE_IFACE=${CAPTURE_IFACE:-$CLIENT_IFACE}
CLIENT_IP=${CLIENT_IP:-172.30.0.10}
ENTRY_IP=${ENTRY_IP:-172.31.0.10}
TCPDUMP_FILTER=${TCPDUMP_FILTER:-"host $CLIENT_IP and host $ENTRY_IP"}
PCAP_FILE=${PCAP_FILE:-/captures/dpi-baseline.pcap}

mkdir -p /captures
touch "$PCAP_FILE"

if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
  echo "[DPI] Warning: unable to set net.ipv4.ip_forward=1 (may be already set or blocked)"
fi

# Ensure FORWARD chain allows traffic between client and server networks
iptables -P FORWARD ACCEPT

# Configure NAT so that backend replies reach the client network
iptables -t nat -C POSTROUTING -o "$SERVER_IFACE" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -o "$SERVER_IFACE" -j MASQUERADE

echo "[DPI] Capturing $TCPDUMP_FILTER on iface $CAPTURE_IFACE -> $PCAP_FILE"
tcpdump -i "$CAPTURE_IFACE" -w "$PCAP_FILE" -U $TCPDUMP_FILTER &
TCPDUMP_PID=$!

cleanup() {
  echo "[DPI] Shutting down, stopping tcpdump"
  kill "$TCPDUMP_PID" 2>/dev/null || true
}
trap cleanup TERM INT

tail -f /dev/null &
wait $!
