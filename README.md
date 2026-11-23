# LogManthan_rules

OT (industrial control system) detection rules for the LogManthan SOC platform, with the tests
and lab used to check them.

LogManthan ingests **Suricata alerts only**, so all OT protocol detection is done with Suricata rules
(`suricata/`). Sigma (`sigma/`) only correlates multi-step behaviour on top, by Suricata SID
([sigma/README.md](sigma/README.md)).

## Layout
| Path | What |
|---|---|
| `suricata/ot/lm-ot.rules` | OT signatures: Modbus, DNP3, EtherNet/IP, S7comm, IT→OT |
| `tests/suricata/fixtures.json` | Test captures: URL or repo path + SHA-256 + expected SIDs |
| `tests/suricata/lab/` | Our own small lab captures (one per attack scenario + normal HMI and DNP3 master traffic) |
| `scripts/test_suricata.py` | Lint + `suricata -T` + pcap replay tests |
| `sigma/rules/` | Sigma base rules and correlations over LM-OT alerts ([sigma/README.md](sigma/README.md)) |
| `sigma/pipelines/logmanthan-fields.yml` | The one place Sigma field names are defined (TODO(rajeev): confirm) |
| `tests/sigma/` | Sigma test events (alerts from the lab captures) and correlation scenarios |
| `scripts/test_sigma.py` | `sigma check` + field/SID sync + correlation scenario tests |
| `lab/` | Docker OT lab: Modbus PLC and HMI, DNP3 outstation and master, attacker, Suricata sensor ([lab/README.md](lab/README.md)) |
| `Makefile` | `make test`, `make sigma-test`, `make lab-up`, `make attack SCENARIO=...`, `make alerts`, `make capture` |
| `tuning/` | Rate limits for Suricata's bundled Modbus/DNP3 event rules, for LogManthan ([tuning/README.md](tuning/README.md)) |
| `SIDS.md` | SID registry |
| `ATTRIBUTION.md` | Credits for third-party captures |
| `SECURITY.md` | Reporting issues, what must never be committed |

## Conventions
- **SIDs:** 9100001–9199999, registered in `SIDS.md`, never reused.
- **Every rule has** `msg:"LM-OT ..."`, `classtype`, `priority`, `metadata:mitre_ics Txxxx`, `sid`, `rev`.
- **Priority** (LogManthan severity): `1` = Critical, **the only level that opens a case**
  (writes, restarts, listen-only, stop, delete, disabling alarms); `2` = Medium, alert only (recon/discovery);
  `3` = Low.
- **Address groups**, never real IPs: `OT_NET`, `OT_WRITERS`, `ENG_WS`, `DNP3_MASTERS`, `IT_NET`.
  Site values are set in each deployment's `suricata.yaml`, outside this repo.
- **Alert-only:** no `drop` / `reject` / `pass`, no auto-isolation.
- **No Lua rules** (Suricata 8 enables them by default; we turn them off).
- **Parsers:** Modbus, DNP3 and ENIP are off by default in Suricata. Enable them with
  `app-layer.protocols.<proto>.enabled: yes`. S7 has no parser, so its rule matches bytes on TCP 102.
- **Target:** Suricata 8.0.7 (production). Rules must load with no warnings.

## Running the tests
Needs Python 3 and Suricata 8 (`SURICATA` env var picks the binary, default `suricata`).

```sh
python3 scripts/test_suricata.py
```

No local Suricata? Use the Suricata 8.0.7 container (same image as CI, pinned by digest):
```sh
make test
```

The runner:
1. **Lint** fails if a rule lacks the `LM-OT` msg prefix, `classtype`, `priority`, `metadata:mitre_ics`,
   `sid` or `rev`; uses Lua; isn't an `alert`; has a SID out of range, reused, or missing from `SIDS.md`;
   or uses a classtype the lab sensor does not define (`lab/suricata/classification.config`).
2. **Static** runs `suricata -T` on all rule files. Any warning fails the test, except the known
   harmless environment warnings listed (with a reason) in `IGNORED_WARNINGS` in the script.
3. **Dynamic** verifies each capture's SHA-256 (external ones are downloaded into `.cache/` first), replays
   it (again failing on any warning), and checks that the expected SIDs fire, or that nothing fires for
   `silent` fixtures. Fixtures marked `exact` fail if any other LM SID fires too. Replays run
   single-threaded (`--runmode single`): with several threads, threshold rules gave different counts
   from run to run.

4. **Tuning** replays every capture (plus ITI `ModbusTCP.pcap`) with Suricata's bundled
   `modbus-events.rules` and `dnp3-events.rules`, without and with `tuning/threshold.config`. It fails if
   a capture's event-alert count goes above its limit in `tests/suricata/tuning.json`, if an event is
   silenced completely, or if the LM-OT SIDs change. The bundled rule files come from the Suricata
   binary under test (`--build-info` datarootdir), and the test fails clearly if its version is not the
   one the limits were measured on.

Any Suricata warning or error line fails the run, even if Suricata exits 0.

Fixture fields: `id`, `url` (external, downloaded) or `path` (in the repo), `sha256`,
`expect` (`fire` / `silent` / `absent`: none of `expect_sids` may fire), `expect_sids`, optional `exact: true`, optional `app_proto` (every flow must be decoded as that protocol, with no
anomaly events), and optional `vars` naming a set in
`var_sets` (the lab captures use the lab's address groups; the rest use the top-level `vars`).

Suricata settings are passed with `--set`; there is no custom `suricata.yaml` in the repo.
CI (`.github/workflows/test.yml`) runs gitleaks, then the same tests inside the `jasonish/suricata:8.0.7`
image pinned by digest (the production version), checks the Sigma test events against a fresh replay,
and runs the Sigma tests with the hash-pinned tools, on every push and pull request.

Sigma tests (Python 3.11+): `make sigma-setup` once, then `make sigma-test`. See [sigma/README.md](sigma/README.md).

## Secrets
```sh
pip install pre-commit && pre-commit install   # gitleaks runs on each commit
```

## Licence
Rules: [Detection Rule License 1.1](LICENSE). Third-party test captures: see [ATTRIBUTION.md](ATTRIBUTION.md).
