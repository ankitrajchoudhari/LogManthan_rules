# LogManthan_rules

OT (industrial control system) detection rules for the LogManthan SOC platform, with the tests
and lab used to check them.

LogManthan ingests **Suricata alerts only**, so all OT protocol detection is done with Suricata rules
(`suricata/`). Sigma (`sigma/`, phase 5) only correlates multi-step behaviour on top, by Suricata SID.

## Layout
| Path | What |
|---|---|
| `suricata/ot/lm-ot.rules` | OT signatures: Modbus, DNP3, EtherNet/IP, S7comm, IT→OT |
| `tests/suricata/fixtures.json` | Test captures: URL + SHA-256 + expected SIDs |
| `scripts/test_suricata.py` | Lint + `suricata -T` + pcap replay tests |
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

No local Suricata? Use the container:
```sh
docker run --rm -v "$PWD:/src" -w /src --entrypoint python3 jasonish/suricata:8.0.7 scripts/test_suricata.py
```

The runner:
1. **Lint** fails if a rule lacks the `LM-OT` msg prefix, `priority`, `metadata:mitre_ics`, `sid` or `rev`;
   uses Lua; isn't an `alert`; or has a SID out of range or reused.
2. **Static** runs `suricata -T` on all rule files.
3. **Dynamic** downloads each capture into `.cache/`, verifies its SHA-256, replays it, and checks that
   the expected SIDs fire (or that nothing fires for `silent` fixtures).

Suricata settings are passed with `--set`; there is no custom `suricata.yaml` in the repo.
CI (`.github/workflows/test.yml`) runs gitleaks and the same tests on every push and pull request.

## Secrets
```sh
pip install pre-commit && pre-commit install   # gitleaks runs on each commit
```

## Licence
Rules: [Detection Rule License 1.1](LICENSE). Third-party test captures: see [ATTRIBUTION.md](ATTRIBUTION.md).
