#!/usr/bin/env python3
"""Build the Sigma test events from our lab captures.

Replays every lab capture (tests/suricata/lab/*.pcap) through Suricata the way production sees
it: the LM-OT rules plus Suricata's bundled Modbus/DNP3 event rules, rate-limited by
tuning/threshold.config, with the lab address groups. Each alert in eve.json is reduced to the
fields LogManthan's Sigma engine sees and written to tests/sigma/events/<capture>.jsonl.

    python3 scripts/build_sigma_events.py           # (re)write the event files
    python3 scripts/build_sigma_events.py --check   # fail if the committed files are stale

Runs where Suricata runs (the pinned container: `make sigma-events`). Standard library only.
The field names written here are the logical names used by the Sigma rules; LogManthan's real
names are mapped in one place, sigma/pipelines/logmanthan-fields.yml (TODO(rajeev)).
"""

import ipaddress
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_suricata as ts  # noqa: E402

OUT = ts.ROOT / "tests" / "sigma" / "events"
LAB_NET = ipaddress.ip_network("10.10.1.0/24")


def to_event(ev):
    """eve.json alert -> the fields LogManthan's Sigma engine sees (logical names)."""
    return {
        "timestamp": ev["timestamp"],
        "signature_id": ev["alert"]["signature_id"],
        "msg": ev["alert"]["signature"],
        "src_ip": ev["src_ip"],
        "src_port": ev.get("src_port"),
        "dest_ip": ev["dest_ip"],
        "dest_port": ev.get("dest_port"),
    }


def lab_captures(fixtures):
    """One entry per lab capture file (a capture replayed under several var sets appears once)."""
    seen, out = set(), []
    for fx in fixtures["fixtures"]:
        path = fx.get("path", "")
        if path.startswith("tests/suricata/lab/") and path not in seen:
            seen.add(path)
            out.append((Path(path).stem, fx))
    return out


def build(tmpdir):
    fixtures = json.loads(ts.FIXTURES.read_text(encoding="utf-8"))
    tuning = json.loads(ts.TUNING.read_text(encoding="utf-8"))
    version, rules_dir = ts.suricata_build()
    if version != tuning["suricata_version"]:
        raise SystemExit(f"Suricata {version} under test, events are built on {tuning['suricata_version']}")
    rules = Path(tmpdir) / "events.rules"
    bundled = "".join((rules_dir / f).read_text(encoding="utf-8") for f in tuning["bundled_rule_files"])
    rules.write_text(ts.combined_rules(tmpdir).read_text(encoding="utf-8") + "\n" + bundled, encoding="utf-8")
    threshold = ts.ROOT / tuning["threshold_file"]
    lab_vars = fixtures["var_sets"]["lab"]

    files = {}
    for name, fx in lab_captures(fixtures):
        alerts = ts.replay_alerts(ts.fetch(fx), rules, lab_vars, [f"threshold-file={threshold}"])
        events = sorted((to_event(a) for a in alerts), key=lambda e: (e["timestamp"], e["signature_id"]))
        for e in events:  # lab captures must only ever hold lab addresses
            for k in ("src_ip", "dest_ip"):
                if ipaddress.ip_address(e[k]) not in LAB_NET:
                    raise SystemExit(f"{name}: {k} {e[k]} is outside {LAB_NET}; refusing to write")
        files[name] = "".join(json.dumps(e, sort_keys=True) + "\n" for e in events)
    return files


def main():
    check = "--check" in sys.argv[1:]
    with tempfile.TemporaryDirectory() as tmpdir:
        files = build(tmpdir)
    stale = []
    for name, text in files.items():
        dest = OUT / f"{name}.jsonl"
        n = text.count("\n")
        if check:
            current = dest.read_text(encoding="utf-8") if dest.exists() else None
            ok = current == text
            print(f"  {'PASS' if ok else 'FAIL'} {dest.relative_to(ts.ROOT).as_posix()} ({n} alerts)")
            if not ok:
                stale.append(name)
        else:
            OUT.mkdir(parents=True, exist_ok=True)
            with open(dest, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            print(f"  wrote {dest.relative_to(ts.ROOT).as_posix()} ({n} alerts)")
    if stale:
        print(f"  FAIL: {len(stale)} event files differ from a fresh replay; run `make sigma-events`")
        sys.exit(1)


if __name__ == "__main__":
    main()
