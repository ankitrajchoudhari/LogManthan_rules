#!/usr/bin/env python3
"""Test runner for the LogManthan OT Sigma rules.

1. Check     `sigma check --fail-on-error --fail-on-issues sigma/rules` (sigma-cli / pySigma).
2. Fields    the field pipeline loads in pySigma, and every field a rule uses is a LogManthan field
             listed in it (sigma/pipelines/logmanthan-fields.yml is the one place field names are
             defined).
3. Sync      every base rule requires metadata.product.name: Suricata, the base rules only name
             LM-OT SIDs that exist, and lm_ot_priority1 lists exactly the priority:1 rules in
             suricata/ot/lm-ot.rules.
4. Scenarios evaluate the correlations on alert streams built from our lab captures
             (tests/sigma/scenarios.json) and compare with the expected result. A scenario with
             "no_base_matches": true also fails if any base rule matches any of its events.

Step 4 uses a small reference evaluator of the Sigma correlation semantics, written for these
rules only (selections of field: value lists; event_count and temporal_ordered). It fails loudly
on any construct it does not support. Field names with dots are paths into the nested event, and
values are compared as text, as Sigma does. Rajeev replayed the 18 lab scenarios through
LogManthan's own Sigma engine: 36/36 checks match this evaluator.

Needs Python 3.11+ with sigma/requirements.txt installed (`make sigma-test`).
"""

import json
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import yaml
from sigma.processing.pipeline import ProcessingPipeline

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "sigma" / "rules"
PIPELINE = ROOT / "sigma" / "pipelines" / "logmanthan-fields.yml"
SURICATA_RULES = ROOT / "suricata" / "ot" / "lm-ot.rules"
SCENARIOS = ROOT / "tests" / "sigma" / "scenarios.json"
EVENTS = ROOT / "tests" / "sigma" / "events"
TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"
LM_SID_MIN, LM_SID_MAX = 9100000, 9199999
SID_FIELD = "metadata.event_code"
PRODUCT_FIELD = "metadata.product.name"
GROUP_FIELD = "src_endpoint.ip"


class Unsupported(Exception):
    pass


# ---------------------------------------------------------------- loading
def load_rules():
    """name -> rule dict, for every Sigma rule file (one rule per file)."""
    rules = {}
    for path in sorted(RULES.rglob("*.yml")):
        docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
        if len(docs) != 1:
            raise Unsupported(f"{path.name}: expected one rule per file, found {len(docs)}")
        rule = docs[0]
        rule["_file"] = path.relative_to(ROOT).as_posix()
        if rule["name"] in rules:
            raise Unsupported(f"{path.name}: duplicate rule name {rule['name']}")
        rules[rule["name"]] = rule
    return rules


def selections(rule):
    """Yield (selection name, field, values) for a base rule; only plain field: value(s) supported."""
    det = rule["detection"]
    for name, sel in det.items():
        if name == "condition":
            continue
        if not isinstance(sel, dict):
            raise Unsupported(f"{rule['_file']}: selection {name} is not a field map")
        for field, values in sel.items():
            if "|" in field:
                raise Unsupported(f"{rule['_file']}: field modifiers are not supported ({field})")
            yield name, field, values if isinstance(values, list) else [values]


def fields_used(rules):
    used = set()
    for rule in rules.values():
        if "correlation" in rule:
            used.update(rule["correlation"].get("group-by", []))
        else:
            used.update(field for _, field, _ in selections(rule))
    return used


def suricata_priorities():
    """sid -> priority for every LM-OT Suricata rule."""
    out = {}
    for line in SURICATA_RULES.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        sid = re.search(r"[(;]\s*sid:\s*(\d+)\s*;", line)
        prio = re.search(r"[(;]\s*priority:\s*(\d+)\s*;", line)
        out[int(sid.group(1))] = int(prio.group(1))
    return out


# ---------------------------------------------------------------- evaluation
def get_field(event, field):
    """Value of a dotted field name in a nested event (None if any part is missing)."""
    value = event
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def base_matches(rule, event):
    det = rule["detection"]
    cond = det["condition"]
    if not isinstance(cond, str) or not re.fullmatch(r"\w+", cond) or cond not in det:
        raise Unsupported(f"{rule['_file']}: only a single selection name is supported as condition")
    for name, field, values in selections(rule):
        if name == cond and str(get_field(event, field)) not in {str(v) for v in values}:
            return False
    return True


def parse_timespan(text):
    m = re.fullmatch(r"(\d+)([smhd])", str(text))
    if not m:
        raise Unsupported(f"timespan {text!r}")
    return timedelta(seconds=int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)])


def correlate(corr_rule, rules, events):
    """Return {group tuple: first time the correlation fires} for one correlation rule."""
    c = corr_rule["correlation"]
    kind, span, group_by = c["type"], parse_timespan(c["timespan"]), c["group-by"]
    if corr_rule.get("generate") or c.get("generate"):
        raise Unsupported(f"{corr_rule['_file']}: generate: true is not supported")
    refs = [rules[name] for name in c["rules"]]
    # per group, the (time, index of matching referenced rule) of every matching event
    hits = defaultdict(list)
    for ev in events:
        for i, ref in enumerate(refs):
            if base_matches(ref, ev):
                hits[tuple(get_field(ev, f) for f in group_by)].append((ev["_t"], i))
    fired = {}
    for group, items in hits.items():
        items.sort()
        if kind == "event_count":
            cond = c["condition"]
            if set(cond) != {"gte"}:
                raise Unsupported(f"{corr_rule['_file']}: only condition gte is supported")
            times = [t for t, _ in items]
            j = 0
            for i, t in enumerate(times):
                while t - times[j] > span:
                    j += 1
                if i - j + 1 >= cond["gte"]:
                    fired[group] = t
                    break
        elif kind == "temporal_ordered":
            # every referenced rule must match, in the listed order, within the timespan
            for start, idx in items:
                if idx != 0:
                    continue
                step, last = 1, start
                for t, i in items:
                    if step == len(refs):
                        break
                    if t >= last and i == step and t - start <= span:
                        step, last = step + 1, t
                if step == len(refs):
                    fired[group] = last
                    break
        else:
            raise Unsupported(f"{corr_rule['_file']}: correlation type {kind}")
    return fired


def load_events(name):
    path = EVENTS / f"{name}.jsonl"
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        ev = json.loads(line)
        ev["_t"] = datetime.strptime(ev["timestamp"], TS_FORMAT)
        out.append(ev)
    return out


def build_stream(scenario, base_time):
    stream = []
    for seg in scenario["segments"]:
        events = load_events(seg["capture"])  # a missing file fails; an empty one is a clean baseline
        shift = timedelta(0)
        if "at" in seg and events:
            shift = base_time + timedelta(seconds=seg["at"]) - events[0]["_t"]
        for orig in events:
            ev = json.loads(json.dumps({k: v for k, v in orig.items() if k != "_t"}))  # deep copy
            ev["_t"] = orig["_t"] + shift
            src = ev["src_endpoint"]["ip"]
            ev["src_endpoint"]["ip"] = seg.get("rewrite_src", {}).get(src, src)
            stream.append(ev)
    stream.sort(key=lambda e: e["_t"])
    return stream


# ---------------------------------------------------------------- main
def sigma_check():
    exe = shutil.which("sigma", path=str(Path(sys.executable).parent)) or shutil.which("sigma")
    if not exe:
        print("  FAIL sigma-cli not found (pip install -r sigma/requirements.txt)")
        return False
    p = subprocess.run([exe, "check", "--fail-on-error", "--fail-on-issues", str(RULES)],
                       capture_output=True, text=True)
    out = p.stdout + p.stderr
    for line in out.splitlines():
        if line.startswith(("Found ", "issue=", "error=")) or "Error" in line:
            print("  " + line)
    ok = p.returncode == 0
    print(f"  {'PASS' if ok else 'FAIL'}: sigma check exited {p.returncode}")
    return ok


def main():
    failed = False

    print("== Sigma check ==")
    ver = subprocess.run([sys.executable, "-m", "pip", "show", "sigma-cli", "pySigma"],
                         capture_output=True, text=True).stdout
    print("  " + ", ".join(f"{n} {v}" for n, v in re.findall(r"^Name: (\S+)\nVersion: (\S+)", ver, re.M)))
    failed |= not sigma_check()

    rules = load_rules()
    base = {n: r for n, r in rules.items() if "correlation" not in r}
    corrs = {n: r for n, r in rules.items() if "correlation" in r}
    print(f"  {len(base)} base rules, {len(corrs)} correlation rules")

    print("== Field names (sigma/pipelines/logmanthan-fields.yml) ==")
    pipeline_text = PIPELINE.read_text(encoding="utf-8")
    ProcessingPipeline.from_yaml(pipeline_text)  # raises if pySigma cannot load it
    mapping = {}
    for t in yaml.safe_load(pipeline_text)["transformations"]:
        if t["type"] == "field_name_mapping":
            mapping.update(t["mapping"])
    known = set(mapping.values()) | {PRODUCT_FIELD}  # product name is set by LogManthan itself
    used = fields_used(rules)
    missing = sorted(used - known)
    print(f"  pipeline:      {', '.join(f'{k} -> {v}' for k, v in mapping.items())}, plus {PRODUCT_FIELD}")
    print(f"  used by rules: {', '.join(sorted(used))}")
    if missing:
        print(f"  FAIL fields used by rules but not LogManthan fields in the pipeline: {missing}")
        failed = True
    else:
        print("  PASS: every field the rules use is a LogManthan field defined in the pipeline")

    print("== Sync with suricata/ot/lm-ot.rules ==")
    prios = suricata_priorities()
    for name, rule in sorted(base.items()):
        products = [vals for _, field, vals in selections(rule) if field == PRODUCT_FIELD]
        if products != [["Suricata"]]:
            print(f"  FAIL {name}: selection must require {PRODUCT_FIELD}: Suricata "
                  "(Wazuh rule IDs share metadata.event_code)")
            failed = True
        sids = {v for sel, field, vals in selections(rule) if field == SID_FIELD for v in vals}
        unknown = sorted(s for s in sids if s not in prios)
        bad = [s for s in sids if not LM_SID_MIN <= s <= LM_SID_MAX]
        if unknown or bad:
            print(f"  FAIL {name}: SIDs not in lm-ot.rules {unknown or bad}")
            failed = True
        else:
            print(f"  PASS {name}: {PRODUCT_FIELD} Suricata, {len(sids)} SIDs, all in lm-ot.rules")
    p1 = {s for s, p in prios.items() if p == 1}
    listed = {v for _, f, vals in selections(rules["lm_ot_priority1"]) if f == SID_FIELD for v in vals}
    if listed != p1:
        print(f"  FAIL lm_ot_priority1 differs from priority:1 rules: missing {sorted(p1 - listed)}, "
              f"extra {sorted(listed - p1)}")
        failed = True
    else:
        print(f"  PASS lm_ot_priority1 lists exactly the {len(p1)} priority:1 rules")

    print("== Correlation scenarios (tests/sigma/scenarios.json) ==")
    data = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    base_time = datetime.strptime(data["base_time"], TS_FORMAT)
    passed = 0
    for sc in data["scenarios"]:
        try:
            if set(sc["expect"]) != set(corrs):
                raise Unsupported(f"expect must list every correlation rule {sorted(corrs)}")
            stream = build_stream(sc, base_time)
            got = {n: sorted(g[0] for g in correlate(r, rules, stream)) for n, r in corrs.items()}
        except (Unsupported, KeyError, OSError) as exc:
            print(f"  FAIL {sc['id']} error={exc}")
            failed = True
            continue
        ok = all(sorted(sc["expect"][n]) == got[n] for n in corrs)
        shown = " ".join(f"{n}={got[n]}" for n in sorted(corrs))
        if sc.get("no_base_matches"):
            hit = sorted({n for n, r in base.items() for ev in stream if base_matches(r, ev)})
            ok = ok and not hit
            shown += f"  base rules matched={hit}"
        print(f"  {'PASS' if ok else 'FAIL'} {sc['id']:38s} {len(stream):3d} alerts  {shown}"
              + ("" if ok else f"  expected {sc['expect']}"))
        passed += ok
    print(f"{passed}/{len(data['scenarios'])} scenarios passed")
    if passed != len(data["scenarios"]):
        failed = True

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
