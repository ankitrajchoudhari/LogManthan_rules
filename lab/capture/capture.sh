#!/bin/sh
# Record OT traffic on the lab bridge to /out/<name>.pcap for <seconds> seconds.
set -eu

NAME="${1:-capture}"
DURATION="${2:-30}"
case "$NAME" in *[!A-Za-z0-9_-]*|'') echo "capture: NAME may only contain A-Z a-z 0-9 _ -" >&2; exit 2 ;; esac
case "$DURATION" in *[!0-9]*|'') echo "capture: DURATION must be whole seconds" >&2; exit 2 ;; esac

IFACE="${LAB_IFACE:-otlab0}"
echo "capture: ${IFACE} -> /out/${NAME}.pcap for ${DURATION}s"
timeout "$DURATION" tcpdump -i "$IFACE" -U -Z root -w "/out/${NAME}.pcap" \
  'tcp port 502 or tcp port 20000 or tcp port 44818 or udp port 44818' || true
echo "capture: done"
