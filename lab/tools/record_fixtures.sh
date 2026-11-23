#!/bin/sh
# Re-record the lab test captures into tests/suricata/lab/ (run from the repo root, lab up).
#   sh lab/tools/record_fixtures.sh            # all
#   sh lab/tools/record_fixtures.sh write scan # some
# Each attack capture is filtered to the attacker (10.10.1.66), so it holds one scenario only.
# The HMI capture is filtered to the HMI (10.10.1.20) and restarts the HMI so the TCP handshake
# is included. Afterwards, update sha256 in tests/suricata/fixtures.json with the printed values.
set -eu
export MSYS_NO_PATHCONV=1

COMPOSE="docker compose -f lab/docker-compose.yml"
DEST=tests/suricata/lab
ATTACKER=10.10.1.66
HMI=10.10.1.20
mkdir -p "$DEST"

wait_capture_started() {
  i=0
  until docker ps --filter name=otlab-capture-run -q | grep -q .; do
    i=$((i + 1)); [ "$i" -gt 60 ] && { echo "record: capture did not start" >&2; exit 1; }
    sleep 1
  done
  sleep 2   # let tcpdump open the interface
}

save() {  # save <capture name>
  cp "lab/out/$1.pcap" "$DEST/lab_$1.pcap"
  sum=$(sha256sum "$DEST/lab_$1.pcap" | cut -d' ' -f1)
  echo "record: lab_$1 $(wc -c < "$DEST/lab_$1.pcap") bytes sha256 $sum"
}

record_attack() {  # record_attack <scenario> <seconds>
  name=$(echo "$1" | tr '-' '_')
  $COMPOSE run --rm capture "$name" "$2" "$ATTACKER" > /dev/null 2>&1 &
  pid=$!
  wait_capture_started
  $COMPOSE run --rm attacker "$1" 2>&1 | grep '^attacker:' || true
  wait "$pid"
  save "$name"
}

record_hmi() {  # record_hmi <seconds>
  $COMPOSE run --rm capture hmi_normal "$1" "$HMI" > /dev/null 2>&1 &
  pid=$!
  wait_capture_started
  $COMPOSE restart hmi > /dev/null 2>&1
  echo "record: hmi restarted, capturing $1 s of normal polling"
  wait "$pid"
  save hmi_normal
}

[ $# -eq 0 ] && set -- scan write listen-only restart-comms flood hmi
for s in "$@"; do
  case "$s" in
    scan)  record_attack scan 25 ;;
    flood) record_attack flood 20 ;;
    write|listen-only|restart-comms) record_attack "$s" 12 ;;
    hmi)   record_hmi 130 ;;
    *) echo "record: unknown scenario $s" >&2; exit 2 ;;
  esac
done
