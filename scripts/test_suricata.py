#!/usr/bin/env python3
"""Test runner for LogManthan OT Suricata rules.

1. Lint      every rule in suricata/**/*.rules against repo conventions.
2. Static    `suricata -T` with all rule files concatenated.
3. Dynamic   replay each fixture capture and check which LM SIDs fire.
4. Tuning    replay with Suricata's bundled Modbus/DNP3 event rules, without and with
             tuning/threshold.config, and check event-alert volume stays within agreed limits.

Standard library only. Suricata binary comes from env var SURICATA (default "suricata"); the
bundled event rules are taken from that binary's own install (`suricata --build-info`).
External captures are downloaded to .cache/ and never committed; our own lab captures live in
tests/suricata/lab/. Every capture is verified by SHA-256 before use.
"""

import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "suricata"
FIXTURES = ROOT / "tests" / "suricata" / "fixtures.json"
SIDS_MD = ROOT / "SIDS.md"
LAB_CLASSIFICATION = ROOT / "lab" / "suricata" / "classification.config"
TUNING = ROOT / "tests" / "suricata" / "tuning.json"
CACHE = ROOT / ".cache" / "pcaps"
SURICATA = os.environ.get("SURICATA", "suricata")

SID_MIN, SID_MAX = 9100001, 9199999
LM_SID_MIN, LM_SID_MAX = 9100000, 9199999  # range collected from eve.json

BASE_SETS = [
    "app-layer.protocols.modbus.enabled=yes",
    "app-layer.protocols.dnp3.enabled=yes",
    "app-layer.protocols.enip.enabled=yes",
    "stream.midstream=true",
    "security.lua.allow-rules=false",
]

# Any Suricata warning fails the tests, except the known harmless environment warnings
# below. They come from the machine Suricata runs on, not from our rules.
# Only add an entry together with a comment explaining why it is harmless.
IGNORED_WARNINGS = [
    # Suricata run as a non-root user cannot create its Hyperscan pattern cache folder.
    # This only disables the cache; rule loading and detection are unaffected.
    re.compile(r"mpm-hs: Failed to create Hyperscan cache folder"),
]

ACTIONS = ("alert", "drop", "reject", "rejectsrc", "rejectdst", "rejectboth", "pass")


# ---------------------------------------------------------------- lint
def rule_files():
    return sorted(RULES_DIR.rglob("*.rules"))


def iter_rules():
    """Yield (file, line_no, text) for every non-comment, non-blank rule line."""
    for f in rule_files():
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            s = line.strip()
            if s and not s.startswith("#"):
                yield f, n, s


def lab_classtypes():
    names = set()
    for line in LAB_CLASSIFICATION.read_text(encoding="utf-8").splitlines():
        m = re.match(r"\s*config classification:\s*([^,\s]+)\s*,", line)
        if m:
            names.add(m.group(1))
    return names


def registered_sids():
    text = SIDS_MD.read_text(encoding="utf-8")
    return {int(x) for x in re.findall(r"^\|\s*(\d{7})\s*\|", text, re.M)}


def lint():
    errors = []
    seen = {}
    count = 0
    classtypes = lab_classtypes()
    registry = registered_sids()
    for f, n, rule in iter_rules():
        where = f"{f.relative_to(ROOT).as_posix()}:{n}"
        action = rule.split(None, 1)[0].lower()
        if action not in ACTIONS:
            errors.append(f"{where}: unrecognised rule line")
            continue
        count += 1
        if action != "alert":
            errors.append(f"{where}: action '{action}' not allowed (OT rules are alert-only)")
        if 'msg:"LM-OT' not in rule:
            errors.append(f'{where}: missing msg:"LM-OT ..." prefix')
        for kw in ("priority:", "metadata:", "sid:", "rev:"):
            if not re.search(r"[(;]\s*" + kw, rule):
                errors.append(f"{where}: missing {kw}")
        ct = re.search(r"[(;]\s*classtype:\s*([^;\s]+)\s*;", rule)
        if not ct:
            errors.append(f"{where}: missing classtype:")
        elif ct.group(1) not in classtypes:
            errors.append(f"{where}: classtype {ct.group(1)} not defined in lab/suricata/classification.config")
        # LogManthan reads ATT&CK IDs from mitre_technique_id (ET style); mitre_ics is not read.
        if not re.search(r"metadata:[^;]*\bmitre_technique_id\s+T\d{4}", rule):
            errors.append(f"{where}: missing metadata:mitre_technique_id Txxxx")
        if re.search(r"metadata:[^;]*\bmitre_ics\b", rule):
            errors.append(f"{where}: metadata key mitre_ics is not read by LogManthan; use mitre_technique_id")
        if re.search(r"[(;]\s*lua(jit)?\s*:", rule, re.I):
            errors.append(f"{where}: Lua rules are banned")
        m = re.search(r"[(;]\s*sid:\s*(\d+)\s*;", rule)
        if m:
            sid = int(m.group(1))
            if not SID_MIN <= sid <= SID_MAX:
                errors.append(f"{where}: sid {sid} outside {SID_MIN}-{SID_MAX}")
            if sid not in registry:
                errors.append(f"{where}: sid {sid} not registered in SIDS.md")
            if sid in seen:
                errors.append(f"{where}: sid {sid} reused (first at {seen[sid]})")
            else:
                seen[sid] = where
    return count, errors


# ---------------------------------------------------------------- suricata helpers
def suricata_args(variables):
    args = []
    for s in BASE_SETS:
        args += ["--set", s]
    for name, value in variables.items():
        args += ["--set", f"vars.address-groups.{name}={value}"]
    return args


def combined_rules(tmpdir):
    path = Path(tmpdir) / "all.rules"
    with open(path, "w", encoding="utf-8") as out:
        for f in rule_files():
            out.write(f.read_text(encoding="utf-8"))
            out.write("\n")
    return path


def find_warnings(output):
    """Return (problems, ignored) from Suricata output.

    Problems are warnings and errors. Errors matter even when Suricata exits 0: for example a
    malformed threshold.config line is reported as an error and then silently skipped.
    Errors are never ignorable; only the IGNORED_WARNINGS list can excuse a warning.
    """
    warnings, ignored = [], []
    for line in output.splitlines():
        if re.search(r"^\s*E:|<Error>|\bError:", line):
            warnings.append(line)
        elif re.search(r"^\s*W:|<Warning>|\bWarning:", line):
            if any(p.search(line) for p in IGNORED_WARNINGS):
                ignored.append(line)
            else:
                warnings.append(line)
    return warnings, ignored


def static_check(variables, tmpdir):
    rules = combined_rules(tmpdir)
    cmd = [SURICATA, "-T", "-S", str(rules), "-l", str(tmpdir)] + suricata_args(variables)
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = p.stdout + p.stderr
    warnings, ignored = find_warnings(out)
    return p.returncode, out, warnings, ignored, rules


# ---------------------------------------------------------------- dynamic
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(fx):
    """Return a verified capture: a repo file ("path") or a download cached in .cache/ ("url").

    A repo capture ending in .pcap.gz (the long-session captures, too big to commit raw) is
    verified by the SHA-256 of the .gz file and unpacked into .cache/ for Suricata.
    """
    if "path" in fx:
        dest = ROOT / fx["path"]
        got = sha256(dest)
        if got != fx["sha256"]:
            raise ValueError(f"SHA-256 mismatch (expected {fx['sha256']}, got {got}); refusing capture")
        if dest.name.endswith(".pcap.gz"):
            CACHE.mkdir(parents=True, exist_ok=True)
            unpacked = CACHE / f"{fx['sha256'][:16]}.pcap"
            if not unpacked.exists():
                tmp = unpacked.with_suffix(".part")
                with gzip.open(dest, "rb") as src, open(tmp, "wb") as out:
                    shutil.copyfileobj(src, out)
                tmp.replace(unpacked)
            return unpacked
        return dest
    CACHE.mkdir(parents=True, exist_ok=True)
    dest = CACHE / f"{fx['sha256'][:16]}.pcap"  # keyed by content: fixtures sharing a capture share one download
    if not dest.exists():
        tmp = dest.with_suffix(".part")
        with urllib.request.urlopen(fx["url"], timeout=60) as r, open(tmp, "wb") as fh:
            shutil.copyfileobj(r, fh)
        tmp.replace(dest)
    got = sha256(dest)
    if got != fx["sha256"]:
        dest.unlink()
        raise ValueError(f"SHA-256 mismatch (expected {fx['sha256']}, got {got}); refusing capture")
    return dest


def replay_eve(pcap, rules, variables, extra_sets=()):
    """Replay a capture and return all its eve.json events (alert, anomaly, flow, ...), in eve order."""
    with tempfile.TemporaryDirectory() as logdir:
        # --runmode single: with several worker threads, packets reach threshold counters out of
        # timestamp order, so threshold/limit rules give different counts run to run (seen on
        # ITI ModbusTCP: 9100007 fired 5-8 times, and 9100008 sometimes fired). One thread
        # makes every replay deterministic, which exact expectations and limits require.
        cmd = [SURICATA, "--runmode", "single", "-r", str(pcap), "-k", "none", "-S", str(rules), "-l", logdir]
        cmd += suricata_args(variables)
        for s in extra_sets:
            cmd += ["--set", s]
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError(f"suricata exited {p.returncode}:\n{p.stdout}{p.stderr}")
        warnings, _ = find_warnings(p.stdout + p.stderr)
        if warnings:
            raise RuntimeError("suricata warnings/errors:\n    " + "\n    ".join(warnings))
        events = []
        eve = Path(logdir) / "eve.json"
        if eve.exists():
            for line in eve.read_text(encoding="utf-8").splitlines():
                try:
                    events.append(json.loads(line))
                except ValueError:
                    continue
        return events


def replay_alerts(pcap, rules, variables, extra_sets=()):
    """Replay a capture and return its eve.json alert events (all SIDs), in eve order."""
    return [ev for ev in replay_eve(pcap, rules, variables, extra_sets) if ev.get("event_type") == "alert"]


def lm_sids(events):
    return {ev["alert"]["signature_id"] for ev in events
            if ev.get("event_type") == "alert" and LM_SID_MIN <= ev["alert"]["signature_id"] <= LM_SID_MAX}


def decode_problems(events, app_proto):
    """Problems if the capture is not fully decoded as app_proto: every flow must be app_proto and
    there must be no anomaly events (malformed protocol data)."""
    flows = [ev for ev in events if ev.get("event_type") == "flow"]
    problems = [f"flow to port {ev.get('dest_port')} decoded as {ev.get('app_proto')}"
                for ev in flows if ev.get("app_proto") != app_proto]
    problems += [f"anomaly {ev.get('anomaly')}" for ev in events if ev.get("event_type") == "anomaly"]
    if not flows:
        problems.append("no flows")
    return problems


def replay_counts(pcap, rules, variables, extra_sets=()):
    """Replay a capture and return a Counter of alert counts per SID (all SIDs)."""
    return Counter(ev["alert"]["signature_id"] for ev in replay_alerts(pcap, rules, variables, extra_sets))


def replay(pcap, rules, variables):
    """Replay a capture and return the set of LM-OT SIDs that fired."""
    return lm_sids(replay_eve(pcap, rules, variables))


# ---------------------------------------------------------------- tuning
def suricata_build():
    """(version, bundled rules dir) of the Suricata binary under test, from `suricata --build-info`.

    The bundled *-events.rules are installed with the binary in <datarootdir>/suricata/rules, so
    asking the binary (instead of trying fixed paths) guarantees the rule files we tune and load
    belong to the same Suricata build that runs the test.
    """
    p = subprocess.run([SURICATA, "--build-info"], capture_output=True, text=True)
    out = p.stdout + p.stderr
    ver = re.search(r"This is Suricata version (\S+)", out)
    root = re.search(r"^\s*--datarootdir\s+(\S+)", out, re.M)
    if p.returncode != 0 or not ver or not root:
        raise RuntimeError(f"cannot read version/datarootdir from `{SURICATA} --build-info`:\n{out}")
    return ver.group(1), Path(root.group(1)) / "suricata" / "rules"


THRESHOLD_LINE = re.compile(
    r"^(threshold|event_filter|rate_filter|suppress)\s+gen_id\s+1\s*,\s*sig_id\s+(\d+)\s*(,[^#]*)?$"
)


def lint_threshold_file(path, bundled_sids):
    """Check a threshold.config: valid lines only, no trailing comments, never an LM-OT SID,
    and every SID must exist in the bundled rules it is meant to tune."""
    errors, sids = [], []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        where = f"{path.relative_to(ROOT).as_posix()}:{n}"
        m = THRESHOLD_LINE.match(s)
        if not m:
            errors.append(f"{where}: not a valid gen_id 1 entry, or has a trailing comment (not allowed)")
            continue
        sid = int(m.group(2))
        sids.append(sid)
        if LM_SID_MIN <= sid <= LM_SID_MAX:
            errors.append(f"{where}: sid {sid} is an LM-OT rule; tuning must not touch our rules")
        elif sid not in bundled_sids:
            errors.append(f"{where}: sid {sid} is not in the bundled rule files")
    dup = {s for s in sids if sids.count(s) > 1}
    if dup:
        errors.append(f"{path.relative_to(ROOT).as_posix()}: duplicate entries for {sorted(dup)}")
    return errors


def tuning_check(fixtures_data, lm_rules_text, tmpdir):
    """Replay every capture with the bundled event rules, without and with tuning/threshold.config.

    Fails if: the tuning file is invalid; any capture's event-alert count after tuning exceeds its
    agreed limit; an event SID that fired before tuning is silenced completely (we rate-limit,
    we don't disable); or the LM-OT SIDs that fire change at all.
    """
    cfg = json.loads(TUNING.read_text(encoding="utf-8"))
    ev_min, ev_max = cfg["event_sid_range"]
    try:
        version, rules_dir = suricata_build()
    except RuntimeError as exc:
        print(f"  FAIL {exc}")
        return False
    if version != cfg["suricata_version"]:
        print(f"  FAIL Suricata under test is {version}, but the tuning was measured on "
              f"{cfg['suricata_version']} (tests/suricata/tuning.json): bundled rule SIDs may differ. "
              "Re-measure and update suricata_version and limits.")
        return False
    missing = [f for f in cfg["bundled_rule_files"] if not (rules_dir / f).is_file()]
    if missing:
        print(f"  FAIL bundled rule files {missing} not found in {rules_dir} "
              f"(datarootdir of {SURICATA} {version})")
        return False
    # These exact files are loaded below, so every threshold SID is checked against what Suricata
    # actually loads; Suricata's own "unknown rule" warning would also fail the replay.
    bundled = "".join((rules_dir / f).read_text(encoding="utf-8") for f in cfg["bundled_rule_files"])
    bundled_sids = {int(x) for x in re.findall(r"\bsid:\s*(\d+)\s*;", bundled)}
    threshold_file = ROOT / cfg["threshold_file"]

    problems = lint_threshold_file(threshold_file, bundled_sids)
    for p in problems:
        print("  LINT FAIL", p)
    rules = Path(tmpdir) / "with-events.rules"
    rules.write_text(lm_rules_text + "\n" + bundled, encoding="utf-8")
    empty = Path(tmpdir) / "empty-threshold.config"
    empty.write_text("", encoding="utf-8")

    var_sets = fixtures_data.get("var_sets", {})
    captures = cfg.get("extra_captures", []) + fixtures_data["fixtures"]
    limits = cfg["limits"]
    default_limit = cfg.get("default_limit", 0)
    total_before = total_after = 0
    ok_all = not problems
    print(f"  bundled rules: {', '.join(cfg['bundled_rule_files'])} from {rules_dir} (Suricata {version})")
    print(f"  {'capture':42s} {'before':>7s} {'after':>6s} {'limit':>6s}  after per SID")
    seen = set()
    for fx in captures:
        if fx["sha256"] in seen:  # same capture under another var set: event volume already measured
            continue
        seen.add(fx["sha256"])
        fx_vars = var_sets[fx["vars"]] if "vars" in fx else fixtures_data["vars"]
        limit = limits.get(fx["id"], default_limit)
        try:
            pcap = fetch(fx)
            before = replay_counts(pcap, rules, fx_vars, [f"threshold-file={empty}"])
            after = replay_counts(pcap, rules, fx_vars, [f"threshold-file={threshold_file}"])
        except Exception as exc:
            print(f"  FAIL {fx['id']} error={exc}")
            ok_all = False
            continue
        ev_b = {s: n for s, n in before.items() if ev_min <= s <= ev_max}
        ev_a = {s: n for s, n in after.items() if ev_min <= s <= ev_max}
        lm_b = {s for s in before if LM_SID_MIN <= s <= LM_SID_MAX}
        lm_a = {s for s in after if LM_SID_MIN <= s <= LM_SID_MAX}
        nb, na = sum(ev_b.values()), sum(ev_a.values())
        total_before += nb
        total_after += na
        why = []
        if na > limit:
            why.append(f"{na} event alerts > limit {limit}")
        if set(ev_b) != set(ev_a):
            why.append(f"silenced {sorted(set(ev_b) - set(ev_a))}")
        if lm_b != lm_a:
            why.append(f"LM-OT SIDs changed {sorted(lm_b)} -> {sorted(lm_a)}")
        ok_all &= not why
        per_sid = " ".join(f"{s}:{n}" for s, n in sorted(ev_a.items())) or "-"
        print(f"  {'PASS' if not why else 'FAIL'} {fx['id']:37s} {nb:7d} {na:6d} {limit:6d}  {per_sid}"
              + (f"  <- {'; '.join(why)}" if why else ""))
    print(f"  total event alerts: {total_before} before -> {total_after} after tuning")
    return ok_all


def main():
    failed = False

    print("== Lint ==")
    count, errors = lint()
    for e in errors:
        print("  LINT FAIL", e)
    print(f"  {count} rules checked, {len(errors)} problems")
    if errors:
        failed = True

    data = json.loads(FIXTURES.read_text(encoding="utf-8"))
    variables = data["vars"]
    var_sets = data.get("var_sets", {})

    print("== Static (suricata -T) ==")
    ver = subprocess.run([SURICATA, "-V"], capture_output=True, text=True)
    print("  " + (ver.stdout or ver.stderr).strip())
    with tempfile.TemporaryDirectory() as tmpdir:
        rc, out, warnings, ignored, rules = static_check(variables, tmpdir)
        for w in ignored:
            print("  IGNORED (known environment warning)", w)
        for w in warnings:
            print("  WARNING", w)
        if rc != 0:
            print(out)
            print(f"  FAIL: suricata -T exited {rc}")
            failed = True
        elif warnings:
            print(f"  FAIL: {len(warnings)} warnings/errors (none are allowed)")
            failed = True
        else:
            print(f"  PASS: rules load (0 warnings, {len(ignored)} ignored)")

        print("== Dynamic (pcap replay) ==")
        passed = 0
        fixtures = data["fixtures"]
        for fx in fixtures:
            expected = sorted(fx.get("expect_sids", []))
            fx_vars = var_sets[fx["vars"]] if "vars" in fx else variables
            try:
                pcap = fetch(fx)
                events = replay_eve(pcap, rules, fx_vars, fx.get("sets", ()))
                got = sorted(lm_sids(events))
                counts = Counter(ev["alert"]["signature_id"] for ev in events if ev.get("event_type") == "alert")
                decode = decode_problems(events, fx["app_proto"]) if "app_proto" in fx else []
            except Exception as exc:  # report and continue with the next fixture
                print(f"  FAIL {fx['id']} expected={fx['expect']}:{expected} error={exc}")
                failed = True
                continue
            if fx["expect"] == "fire" and fx.get("exact"):
                ok = set(expected) == set(got)  # no other LM SID may fire
            elif fx["expect"] == "fire":
                ok = set(expected) <= set(got)
            elif fx["expect"] == "silent":
                ok = not got
            elif fx["expect"] == "absent":  # none of expect_sids may fire (other LM SIDs may)
                ok = bool(expected) and not set(expected) & set(got)
            else:
                ok = False
            ok = ok and not decode
            # optional "expect_counts": {"sid": n} - the SID must fire exactly n times (threshold rules)
            count_ok = all(counts[int(sid)] == n for sid, n in fx.get("expect_counts", {}).items())
            ok = ok and count_ok
            mode = "exact" if fx.get("exact") else fx["expect"]
            print(f"  {'PASS' if ok else 'FAIL'} {fx['id']} expected={mode}:{expected} got={got}"
                  + (f" sets={','.join(fx['sets'])}" if fx.get("sets") else "")
                  + (" counts=" + ",".join(f"{sid}:{counts[int(sid)]}" for sid in fx["expect_counts"])
                     + ("" if count_ok else f" (expected {fx['expect_counts']})") if fx.get("expect_counts") else "")
                  + (f" decoded={fx['app_proto']}" if "app_proto" in fx and not decode else "")
                  + (f"  <- not cleanly decoded as {fx['app_proto']}: {'; '.join(decode[:3])}" if decode else ""))
            passed += ok
        print(f"{passed}/{len(fixtures)} dynamic tests passed")
        if passed != len(fixtures):
            failed = True

        print("== Tuning (bundled Modbus/DNP3 event rules + tuning/threshold.config) ==")
        if tuning_check(data, Path(rules).read_text(encoding="utf-8"), tmpdir):
            print("  PASS: event-alert volume within limits, nothing silenced, LM-OT SIDs unchanged")
        else:
            print("  FAIL: tuning check")
            failed = True

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
