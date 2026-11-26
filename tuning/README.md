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
Tuning section). The LM-OT alerts are identical before and after. The bundled rule files are taken
from the Suricata binary under test (its `--build-info` datarootdir), and the test fails if that
binary is not the version the limits were measured on (`suricata_version` in tuning.json).
Replays run single-threaded (`--runmode single`) so threshold counts are the same on every run.

| Capture | Before | After | Limit |
|---|---:|---:|---:|
| ITI `ModbusTCP/ModbusTCP.pcap` (85 s) | 6331 | 19 | 19 |
| ITI `bro/modbus/modbus.pcap` (35 min) | 5017 | 3 | 3 |
| lab `lab_flood` | 1000 | 1 | 1 |
| lab `lab_flood_heavy` | 3000 | 1 | 1 |
| lab `lab_hmi_normal` (normal HMI, 130 s) | 127 | 1 | 1 |
| lab `lab_modbus_long_session` (2250002 unsolicited response) | 15890 | 2 | 2 |
| lab `lab_dnp3_long_session` (2270000 flooded) | 875 | 2 | 2 |
| 20 other captures | 0 | 0 | 0 |
| **Total** | **32240** | **29** | |

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

This is a known bug in the sawp-modbus parser that Suricata uses:
[CybercentreCanada/sawp issue #13](https://github.com/CybercentreCanada/sawp/issues/13). Register-read
responses are checked with the coil formula, ceil(quantity / 8) bytes. It is fixed on sawp main in
commit `7f33f7e` but not yet released: sawp-modbus 0.14.0 still has the bug, and Suricata 8.0.7 ships
0.13.1.

It is not disabled, because on ITI ModbusTCP it also fires on coil reads/writes and discrete inputs,
where it may be a real mismatch. One alert per source per hour keeps that signal.

**TODO(rajeev):** remove the 1-hour limit on 2250008 (back to 300 s like the other events) once a
Suricata release ships a sawp-modbus that includes `7f33f7e`. Re-measure with the test suite then;
`suricata_version` in `tests/suricata/tuning.json` makes the test fail on a new Suricata until the
limits are re-measured.

## Stream reassembly depth

Measured on Suricata 8.0.7 with the lab long-session captures (one connection, a little over 1.1 MiB
of polling, then one command on the same connection):

| | Default (`stream.reassembly.depth` 1 MiB) | `stream.reassembly.depth=10mb` |
|---|---|---|
| Modbus FC6 write after 1,153,440 B of FC1 polling | 9100001 not raised | 9100001 raised |
| DNP3 Cold Restart after 1,154,400 B of class polls | 9100010 not raised | 9100010 raised |

- Modbus and DNP3 are both limited by the **global** `stream.reassembly.depth`. DNP3 has no
  per-protocol setting; Modbus has `app-layer.protocols.modbus.stream-depth` (0 = "track it
  completely" in the default config), but on 8.0.7 setting it to 0, 2 MB or 10 MB made no difference.
- After the limit, Modbus responses keep arriving while requests are no longer parsed, so
  `SURICATA Modbus unsolicited response` (2250002) fires on every response: 15890 times before
  tuning, 2 after. A burst of 2250002 on one long connection is a sign the limit was reached.
- The DNP3 `Request flood detected` events (2270000) in `lab_dnp3_long_session` come from the scenario
  itself: 50 polls outstanding at once, above Suricata's default DNP3 `max-tx` (32 open transactions);
  with `max-tx=64` they drop from 875 to 7. They appear with or without the depth limit.
- A site whose OT masters keep one connection open for a long time can raise the **global**
  `stream.reassembly.depth`. It applies to all TCP traffic, so it costs memory and CPU on the whole
  sensor (Rajeev's point); measure before and after. Never set it to 0 (unlimited).

Details and the per-poller numbers are in the main README, section "Stream reassembly depth".

## Notes

- Suricata 8.0.7 has no "invalid unit ID" Modbus event (there is no SID 2250004). The remaining fuzzing
  signals are invalid function code (2250005), invalid value (2250006), invalid exception code (2250007),
  invalid length (2250003) and invalid protocol version (2250001). All stay on, rate-limited.
- `threshold.config` comments must be on their own line. Suricata rejects a line with a trailing
  comment and starts anyway, silently ignoring that line. The test checks for this.
- DNP3 2270005/2270006 already carry their own `threshold` in the bundled rule and are left alone.
