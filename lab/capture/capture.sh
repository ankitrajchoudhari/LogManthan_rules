#!/bin/sh
# Record OT traffic on the lab bridge to /out/<name>.pcap for <seconds> seconds.
#   capture.sh <name> <seconds> [host]    (host: only traffic to/from this lab IP)
#
# tcpdump runs without promiscuous mode (-p) and drops root to the "tcpdump" user (-Z).
# A Linux bridge only passes switched unicast frames up to a capture socket while the bridge
# is promiscuous, which the Suricata sensor sets. So the sensor must be running.
set -eu

NAME="${1:-capture}"
DURATION="${2:-30}"
HOST="${3:-}"
IFACE="${LAB_IFACE:-otlab0}"

case "$NAME" in *[!A-Za-z0-9_-]*|'') echo "capture: NAME may only contain A-Z a-z 0-9 _ -" >&2; exit 2 ;; esac
case "$DURATION" in *[!0-9]*|'') echo "capture: DURATION must be whole seconds" >&2; exit 2 ;; esac
case "$HOST" in 10.10.1.*|'') ;; *) echo "capture: HOST must be a 10.10.1.x lab address" >&2; exit 2 ;; esac
case "$HOST" in *[!0-9.]*) echo "capture: HOST must be an IPv4 address" >&2; exit 2 ;; esac

flags=$(cat "/sys/class/net/${IFACE}/flags" 2>/dev/null || echo 0)
if [ $(( flags & 0x100 )) -eq 0 ]; then
  echo "capture: ${IFACE} is not promiscuous; start the sensor first (make lab-up)" >&2
  exit 1
fi

FILTER='(tcp port 502 or tcp port 20000 or tcp port 44818 or udp port 44818)'
[ -n "$HOST" ] && FILTER="${FILTER} and host ${HOST}"

echo "capture: ${IFACE} -> /out/${NAME}.pcap for ${DURATION}s, filter: ${FILTER}"
timeout "$DURATION" tcpdump -i "$IFACE" -p -U -Z tcpdump -w "/tmp/${NAME}.pcap" "$FILTER" || true
cp "/tmp/${NAME}.pcap" "/out/${NAME}.pcap"
echo "capture: done ($(wc -c < "/out/${NAME}.pcap") bytes)"
