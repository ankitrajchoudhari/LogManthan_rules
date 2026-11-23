#!/bin/sh
# Lab sensor: Suricata 8 sniffing the otlab bridge with all repo rules (mounted read-only).
set -eu

IFACE="${LAB_IFACE:-otlab0}"
find /etc/suricata/lm-rules -name '*.rules' -exec cat {} + > /tmp/all.rules
echo "lab sensor: $(grep -c '^alert' /tmp/all.rules) rules, interface ${IFACE}"

exec suricata -i "${IFACE}" -k none -S /tmp/all.rules -l /var/log/suricata \
  --set unix-command.enabled=no \
  --set app-layer.protocols.modbus.enabled=yes \
  --set app-layer.protocols.dnp3.enabled=yes \
  --set app-layer.protocols.enip.enabled=yes \
  --set stream.midstream=true \
  --set stream.reassembly.depth=0 \
  --set security.lua.allow-rules=false \
  --set "vars.address-groups.OT_NET=[10.10.1.10]" \
  --set "vars.address-groups.OT_WRITERS=[10.10.1.20]" \
  --set "vars.address-groups.ENG_WS=[10.10.1.30]" \
  --set "vars.address-groups.DNP3_MASTERS=[10.10.1.40]" \
  --set "vars.address-groups.IT_NET=[10.10.1.128/25]"
