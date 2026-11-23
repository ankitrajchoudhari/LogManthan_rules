# Tuning for Suricata's bundled Modbus/DNP3 event rules

LogManthan's Suricata loads the bundled `modbus-events.rules` (SIDs 2250001–2250009) and
`dnp3-events.rules` (SIDs 2270000–2270007). On real Modbus traffic they are very noisy.
[threshold.config](threshold.config) cuts the volume without switching any event off.

## What to deploy

| File | What it does |
|---|---|
| `threshold.config` | Rate limits: each event alerts at most **once per source per 5 minutes**; "Data mismatch" (2250008) at most **once per source per hour**. |
| `disable.conf` | **Not needed.** No event was shown to be pure noise as a whole (see 2250008 below), so nothing is disabled. |

**TODO(rajeev):** how this reaches LogManthan's Suricata. Either:
- point `suricata.yaml` at it: `threshold-file: /path/to/tuning/threshold.config`, or
- merge its lines into LogManthan's existing `threshold.config`.

Also confirm that LogManthan has no entries of its own for these SIDs, since a second entry for the same SID conflicts.

Load it together with **both** bundled files. With only `modbus-events.rules` loaded, Suricata warns
`can't suppress sid 2270000 ... unknown rule` for the DNP3 lines.

The LM-OT rules (9100001–9199999) are not touched; the test suite fails if this file ever names one.

## Before / after

Event alerts from the bundled rules, replayed on Suricata 8.0.7 (`python3 scripts/test_suricata.py`,
Tuning section). The LM-OT alerts are identical before and after.

| Capture | Before | After | Limit |
|---|---:|---:|---:|
| ITI `ModbusTCP/ModbusTCP.pcap` (85 s) | 6331 | 19 | 19 |
| ITI `bro/modbus/modbus.pcap` (35 min) | 5017 | 3 | 3 |
| lab `lab_flood` | 1000 | 1 | 1 |
| lab `lab_hmi_normal` (normal HMI, 130 s) | 127 | 1 | 1 |
| 14 other captures | 0 | 0 | 0 |
| **Total** | **12475** | **24** | |

Per SID on ITI ModbusTCP: unsolicited response 1765 → 2, invalid length 1006 → 2, invalid value 524 → 2,
data mismatch 3036 → 13 (13 sources).

The test fails if any capture goes above its limit, if any event that fired before tuning is silenced
completely, if the LM-OT SIDs change, or if `threshold.config` is malformed. Limits live in
[tests/suricata/tuning.json](../tests/suricata/tuning.json).

## Why "Data mismatch" (2250008) is limited harder

Suricata 8.0.7 marks every FC3/FC4 (read registers) response with `error_flags: DATA_VALUE`, even when
the response is correct. Our lab PLC answers FC3 "read 10 registers" with byte count 20 and 20 data
bytes, exactly as the Modbus spec says, and every one of the 1127 lab FC3 responses still alerts.
The bro capture shows the same thing (quantity 2, 4 data bytes). So on register reads the event is pure
parser noise.

It is not disabled, because on ITI ModbusTCP it also fires on coil reads/writes and discrete inputs,
where it may be a real mismatch. One alert per source per hour keeps that signal.

**TODO(rajeev):** report the FC3/FC4 false positive upstream (OISF) and revisit after a fix.

## Notes

- Suricata 8.0.7 has no "invalid unit ID" Modbus event (there is no SID 2250004). The remaining fuzzing
  signals are invalid function code (2250005), invalid value (2250006), invalid exception code (2250007),
  invalid length (2250003) and invalid protocol version (2250001). All stay on, rate-limited.
- `threshold.config` comments must be on their own line. Suricata rejects a line with a trailing
  comment and starts anyway, silently ignoring that line. The test checks for this.
- DNP3 2270005/2270006 already carry their own `threshold` in the bundled rule and are left alone.
