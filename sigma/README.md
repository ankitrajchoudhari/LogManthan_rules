# Sigma correlations for LogManthan OT

LogManthan ingests Suricata alerts only, so the Sigma rules here never look at network traffic. They
correlate LM-OT **Suricata alerts** by `signature_id` to find multi-step behaviour. LogManthan's Sigma
engine is known to see `signature_id`, `msg`, `src_ip`, `dest_ip`, the ports and `timestamp`. The alert
priority is not on that list, so the rules select priority:1 alerts by SID.

## Rules

| Rule (`name`) | Type | What it matches |
|---|---|---|
| `lm_ot_recon` | base | Recon alerts: 9100004 Modbus device ID, 9100006 Modbus scan, 9100020 ENIP List Identity |
| `lm_ot_write_control` | base | Write/control alerts: 9100001 Modbus write from unauthorised host, 9100012–9100015 DNP3 Direct Operate/Write/Select/Operate from non-master |
| `lm_ot_priority1` | base | Every priority:1 (Critical) LM-OT rule, 13 SIDs |
| `lm_ot_recon_then_write` | `temporal_ordered` | `lm_ot_recon` **then** `lm_ot_write_control` from the same `src_ip` within **10 minutes** |
| `lm_ot_priority1_burst` | `event_count` | **3 or more** `lm_ot_priority1` alerts from the same `src_ip` within **5 minutes** |

The base rules are building blocks. Suricata already raises those alerts, so the correlations keep
the Sigma default `generate: false` and do not duplicate them. Both correlations are `level: critical`.

## Field names: one place, TODO(rajeev)

The rules use logical field names (`signature_id`, `src_ip`). LogManthan's real names are **not
confirmed**. They are defined in one place only,
[pipelines/logmanthan-fields.yml](pipelines/logmanthan-fields.yml), a pySigma processing pipeline
marked `TODO(rajeev): confirm field names`. The test fails if a rule uses a field that file does not
list. The logsource (`product: suricata`, `service: alert`) also needs confirming there.

## Tests

```sh
make sigma-setup            # once: .venv with sigma/requirements.txt (PYTHON=python on Windows)
make sigma-test             # sigma check + field/SID sync + correlation scenarios
make sigma-events CHECK=1   # the test events still match a fresh Suricata replay of the lab captures
```

`scripts/test_sigma.py`:
1. runs `sigma check --fail-on-error --fail-on-issues` (sigma-cli/pySigma, hash-pinned in
   [requirements.txt](requirements.txt), only releases at least two weeks old);
2. checks that every field the rules use is in the pipeline;
3. checks that the base rules name only LM-OT SIDs that exist, and that `lm_ot_priority1` lists
   exactly the priority:1 rules in `suricata/ot/lm-ot.rules` (a new priority:1 rule must be added);
4. evaluates the correlations on the scenarios in
   [tests/sigma/scenarios.json](../tests/sigma/scenarios.json).

**Test events** (`tests/sigma/events/*.jsonl`) are real Suricata 8.0.7 alerts from our lab captures.
`scripts/build_sigma_events.py` replays each capture with the LM-OT rules, the bundled Modbus/DNP3
event rules and `tuning/threshold.config`, as LogManthan would see them. That includes the event
alerts the PLC's responses raise. The builder refuses any address outside 10.10.1.0/24.

**Scenarios** use the real lab timeline: scan, then the write 27 s later, then listen-only and
restart-comms. Captures can also be shifted in time to test the edges: inside and outside each
window, wrong order, a different source host, 2 and exactly 3 Critical alerts, alerts spread out, the
HMI baseline, and the HMI with both floods (priority 2 and event alerts must not count).

The scenario check uses a small reference evaluator of the Sigma correlation semantics. It supports
only what these rules use and fails on anything else. It is not LogManthan's engine.
**TODO(rajeev):** replay `tests/sigma/events/` through LogManthan's own engine as well.
