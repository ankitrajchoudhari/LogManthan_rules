#!/bin/sh
# Lab sensor: Suricata 8 sniffing the otlab bridge with all repo rules (mounted read-only).
# Settings live in /etc/suricata/lab/suricata.yaml (lab/suricata/suricata.yaml in the repo).
set -eu

IFACE="${LAB_IFACE:-otlab0}"
find /etc/suricata/lm-rules -name '*.rules' -exec cat {} + > /tmp/all.rules
echo "lab sensor: $(grep -c '^alert' /tmp/all.rules) rules, interface ${IFACE}"

exec suricata -c /etc/suricata/lab/suricata.yaml --af-packet="${IFACE}" -k none \
  -S /tmp/all.rules -l /var/log/suricata
