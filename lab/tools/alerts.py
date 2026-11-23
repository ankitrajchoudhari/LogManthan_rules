#!/usr/bin/env python3
"""Print LogManthan OT alerts (SIDs 9100000-9199999) from a Suricata eve.json, and optionally check them.

  alerts.py lab/out/eve.json                          # table + per-SID summary
  alerts.py eve.json --since 2026-01-01T10:00:00      # only alerts at/after this UTC time
  alerts.py eve.json --src 10.10.1.66 --expect 9100001
  alerts.py eve.json --forbid-priority 1              # exit 1 if any priority:1 alert

Exit code 1 if an --expect SID is missing or a --forbid-priority alert is present.
Standard library only (runs on Python 3.9+).
"""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone

LM_MIN, LM_MAX = 9100000, 9199999


def parse_ts(ts):
    # eve: 2026-01-01T10:00:00.123456+0000
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(timezone.utc).replace(tzinfo=None)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("eve")
    p.add_argument("--since", help="UTC time YYYY-MM-DDTHH:MM:SS")
    p.add_argument("--src", help="only alerts from this source IP")
    p.add_argument("--expect", type=int, action="append", default=[], help="SID that must be present")
    p.add_argument("--forbid-priority", type=int, action="append", default=[])
    p.add_argument("--quiet", action="store_true", help="summary only")
    a = p.parse_args()

    since = datetime.strptime(a.since, "%Y-%m-%dT%H:%M:%S") if a.since else None
    alerts = []
    try:
        fh = open(a.eve, encoding="utf-8")
    except FileNotFoundError:
        sys.exit(f"no eve.json at {a.eve} (is the lab up?)")
    with fh:
        for line in fh:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("event_type") != "alert":
                continue
            al = ev["alert"]
            if not LM_MIN <= al["signature_id"] <= LM_MAX:
                continue
            if since and parse_ts(ev["timestamp"]) < since:
                continue
            if a.src and ev.get("src_ip") != a.src:
                continue
            alerts.append(ev)

    if not a.quiet:
        for ev in alerts:
            al = ev["alert"]
            print(f"{ev['timestamp'][:19]}  sid={al['signature_id']}  p{al['severity']}  "
                  f"{ev.get('src_ip')}:{ev.get('src_port')} -> {ev.get('dest_ip')}:{ev.get('dest_port')}  "
                  f"{al['signature']}")

    counts = Counter((ev["alert"]["signature_id"], ev["alert"]["severity"], ev["alert"]["signature"]) for ev in alerts)
    print(f"--- {len(alerts)} LM-OT alerts")
    for (sid, prio, msg), n in sorted(counts.items()):
        print(f"  {sid}  priority:{prio}  x{n}  {msg}")

    ok = True
    seen = {ev["alert"]["signature_id"] for ev in alerts}
    for sid in a.expect:
        good = sid in seen
        ok &= good
        print(f"{'PASS' if good else 'FAIL'} expect sid {sid}")
    for prio in a.forbid_priority:
        n = sum(1 for ev in alerts if ev["alert"]["severity"] == prio)
        ok &= n == 0
        print(f"{'PASS' if n == 0 else 'FAIL'} no priority:{prio} alerts (found {n})")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
