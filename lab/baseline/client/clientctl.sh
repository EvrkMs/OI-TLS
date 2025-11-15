#!/bin/sh
set -e
CMD=${1:-help}
case "$CMD" in
  request)
    exec /scripts/health_check.sh
    ;;
  *)
    echo "Usage: clientctl request" >&2
    exit 1
    ;;
esac
