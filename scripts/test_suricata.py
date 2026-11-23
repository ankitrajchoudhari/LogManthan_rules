#!/usr/bin/env python3
"""Test runner for LogManthan OT Suricata rules.

1. Lint      every rule in suricata/**/*.rules against repo conventions.
2. Static    `suricata -T` with all rule files concatenated.
3. Dynamic   replay each fixture capture and check which LM SIDs fire.

Standard library only. Suricata binary comes from env var SURICATA (default "suricata").
External captures are downloaded to .cache/ and never committed; our own lab captures live in
tests/suricata/lab/. Every capture is verified by SHA-256 before use.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "suricata"
FIXTURES = ROOT / "tests" / "suricata" / "fixtures.json"
SIDS_MD = ROOT / "SIDS.md"
LAB_CLASSIFICATION = ROOT / "lab" / "suricata" / "classification.config"
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
        if not re.search(r"metadata:[^;]*\bmitre_ics\s+T\d{4}", rule):
            errors.append(f"{where}: missing metadata:mitre_ics Txxxx")
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
    """Return (warnings, ignored) from Suricata output."""
    warnings, ignored = [], []
    for line in output.splitlines():
        if re.search(r"^\s*W:|<Warning>|\bWarning:", line):
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
    """Return a verified capture: a repo file ("path") or a download cached in .cache/ ("url")."""
    if "path" in fx:
        dest = ROOT / fx["path"]
        got = sha256(dest)
        if got != fx["sha256"]:
            raise ValueError(f"SHA-256 mismatch (expected {fx['sha256']}, got {got}); refusing capture")
        return dest
    CACHE.mkdir(parents=True, exist_ok=True)
    dest = CACHE / f"{fx['id']}.pcap"
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


def replay(pcap, rules, variables):
    with tempfile.TemporaryDirectory() as logdir:
        cmd = [SURICATA, "-r", str(pcap), "-k", "none", "-S", str(rules), "-l", logdir]
        cmd += suricata_args(variables)
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError(f"suricata exited {p.returncode}:\n{p.stdout}{p.stderr}")
        warnings, _ = find_warnings(p.stdout + p.stderr)
        if warnings:
            raise RuntimeError("suricata warnings:\n    " + "\n    ".join(warnings))
        sids = set()
        eve = Path(logdir) / "eve.json"
        if eve.exists():
            for line in eve.read_text(encoding="utf-8").splitlines():
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("event_type") == "alert":
                    sid = ev["alert"]["signature_id"]
                    if LM_SID_MIN <= sid <= LM_SID_MAX:
                        sids.add(sid)
        return sids


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
            print(f"  FAIL: {len(warnings)} warnings (warnings are not allowed)")
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
                got = sorted(replay(pcap, rules, fx_vars))
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
            else:
                ok = False
            mode = "exact" if fx.get("exact") else fx["expect"]
            print(f"  {'PASS' if ok else 'FAIL'} {fx['id']} expected={mode}:{expected} got={got}")
            passed += ok
        print(f"{passed}/{len(fixtures)} dynamic tests passed")
        if passed != len(fixtures):
            failed = True

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
