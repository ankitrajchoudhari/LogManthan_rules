#!/bin/sh
# Re-record the lab test captures into tests/suricata/lab/ (run from the repo root, lab up).
#   sh lab/tools/record_fixtures.sh            # all
#   sh lab/tools/record_fixtures.sh write scan # some
# Each attack capture is filtered to the attacker (10.10.1.66), so it holds one scenario only.
# The HMI capture is filtered to the HMI (10.10.1.20) and restarts the HMI so the TCP handshake
# is included; the DNP3 master baseline likewise (10.10.1.40, 10 minutes of normal polling). Afterwards, update sha256 in tests/suricata/fixtures.json with the printed values.
set -eu
export MSYS_NO_PATHCONV=1

COMPOSE="docker compose -f lab/docker-compose.yml"
DEST=tests/suricata/lab
ATTACKER=10.10.1.66
HMI=10.10.1.20
MASTER=10.10.1.40
mkdir -p "$DEST"

wait_capture_started() {
  i=0
  until docker ps --filter name=otlab-capture-run -q | grep -q .; do
    i=$((i + 1)); [ "$i" -gt 60 ] && { echo "record: capture did not start" >&2; exit 1; }
    sleep 1
  done
  sleep 2   # let tcpdump open the interface
}

save() {  # save <capture name>; long sessions (several MB) are stored gzipped
  out="$DEST/lab_$1.pcap"
  case "$1" in
    *_long_session) gzip -9 -n -c "lab/out/$1.pcap" > "$out.gz"; out="$out.gz" ;;
    *) cp "lab/out/$1.pcap" "$out" ;;
  esac
  sum=$(sha256sum "$out" | cut -d' ' -f1)
  echo "record: $(basename "$out") $(wc -c < "$out") bytes sha256 $sum"
}

record_attack() {  # record_attack <scenario> <seconds> [capture name] [extra attacker args...]
  scenario=$1; secs=$2; shift 2
  name=$(echo "$scenario" | tr '-' '_')
  if [ $# -gt 0 ]; then name=$1; shift; fi
  $COMPOSE run --rm capture "$name" "$secs" "$ATTACKER" > /dev/null 2>&1 &
  pid=$!
  wait_capture_started
  $COMPOSE run --rm attacker "$scenario" "$@" 2>&1 | grep '^attacker:' || true
  wait "$pid"
  save "$name"
}

record_remote() {  # record_remote <scenario> <service> <source ip>: IT-side host, filtered to that host
  name=$(echo "$1" | tr '-' '_')
  $COMPOSE run --rm capture "$name" 20 "$3" > /dev/null 2>&1 &
  pid=$!
  wait_capture_started
  # No --build here: the image was built above, and a rebuild could eat the capture window.
  $COMPOSE run --rm "$2" "$1" 2>&1 | grep '^attacker:' || true
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

record_dnp3_master() {  # record_dnp3_master <seconds>
  $COMPOSE run --rm capture dnp3_master_normal "$1" "$MASTER" > /dev/null 2>&1 &
  pid=$!
  wait_capture_started
  # Restart the outstation too: it comes back with DEVICE_RESTART set, so the capture includes
  # the master's allowed WRITE that clears it (9100013 must stay silent for a DNP3_MASTERS host).
  $COMPOSE restart dnp3-outstation dnp3-master > /dev/null 2>&1
  echo "record: dnp3-outstation and dnp3-master restarted, capturing $1 s of normal polling"
  wait "$pid"
  save dnp3_master_normal
}

# Build the attacker image first (the IT hosts use the same image), so a rebuild never eats into a
# capture window.
$COMPOSE --profile attack build attacker > /dev/null
$COMPOSE --profile capture build capture > /dev/null

[ $# -eq 0 ] && set -- scan write listen-only restart-comms flood flood-heavy hmi   dnp3-cold-restart dnp3-warm-restart dnp3-direct-operate dnp3-write dnp3-disable-unsolicited dnp3-master it-remote jump-remote modbus-long-session dnp3-long-session
for s in "$@"; do
  case "$s" in
    scan)  record_attack scan 25 ;;
    flood) record_attack flood 20 ;;
    flood-heavy) record_attack flood 20 flood_heavy --count 3000 ;;
    write|listen-only|restart-comms) record_attack "$s" 12 ;;
    hmi)   record_hmi 130 ;;
    dnp3-cold-restart|dnp3-warm-restart|dnp3-direct-operate|dnp3-write|dnp3-disable-unsolicited)
           record_attack "$s" 12 ;;
    dnp3-master) record_dnp3_master 600 ;;
    it-remote)   record_remote it-remote it-host 10.10.1.130 ;;
    jump-remote) record_remote jump-remote jump-host 10.10.1.131 ;;
    # One connection with more than 1 MiB of polling, then a command (stream reassembly depth test).
    modbus-long-session) record_attack "$s" 330 ;;
    dnp3-long-session) record_attack "$s" 150 ;;
    *) echo "record: unknown scenario $s" >&2; exit 2 ;;
  esac
done
