# OT lab

A small, self-contained Modbus/TCP plant in Docker: a PLC, an HMI doing normal polling, an attacker,
and a Suricata 8.0.7 sensor running this repo's rules. Use it to prove each rule fires on the attack
it targets and stays quiet on normal traffic. It can also be run as a **cyber-range exercise**
(see [Exercise](#exercise)).

## Topology

One internal Docker bridge `otlab` (`10.10.1.0/24`, interface `otlab0`). It has **no internet access and
no ports published to the host**.

| Host | IP | Role | Address group |
|---|---|---|---|
| `plc-modbus` | 10.10.1.10 | pymodbus server on 502: coils 0–99, holding registers 0–99 | `OT_NET` |
| `hmi` | 10.10.1.20 | Reads HR0–9 and coils 0–15 every 1 s, writes a setpoint to HR0 every 30 s | `OT_WRITERS` |
| *(none yet)* | 10.10.1.30 | Engineering workstation slot | `ENG_WS` |
| *(phase 6)* | 10.10.1.40 | DNP3 master slot | `DNP3_MASTERS` |
| `attacker` | 10.10.1.66 | Attack traffic generator, started on demand | none |
| *(unused)* | 10.10.1.128/25 | IT network slot | `IT_NET` |
| `suricata` | host netns | Sniffs `otlab0`, writes `lab/out/eve.json` | — |

## Quick start

Needs Docker (with Compose v2) and GNU make. Run from the repo root.

```sh
make lab-up                     # build + start plc-modbus, hmi, suricata
make alerts                     # LM-OT alerts seen so far (none, if only the HMI is running)
make attack SCENARIO=write      # run one attack scenario
make alerts ARGS="--src 10.10.1.66 --expect 9100001"
make capture NAME=write DURATION=20   # record lab traffic to lab/out/write.pcap (run an attack meanwhile)
make lab-logs
make lab-down
```

`make alerts` options: `--since YYYY-MM-DDTHH:MM:SS` (UTC), `--src IP`, `--expect SID` (repeatable),
`--forbid-priority N`, `--quiet`. It exits 1 if an expectation fails.

## Scenarios

| `SCENARIO=` | What it sends | MITRE ATT&CK for ICS | Expected SID | Priority |
|---|---|---|---|---|
| `scan` | TCP connect sweep of 10.10.1.0/24 on 502, then 25 new connections to the PLC, each with FC43 Read Device Identification | T0846 | 9100006, 9100004 | 2, 2 |
| `write` | FC6 Write Single Register (HR0 = 9999) and FC16 Write Multiple Registers (HR10–14) | T0855, T0836 | 9100001 | 1 |
| `listen-only` | FC8 Diagnostics, sub-function 4 Force Listen Only Mode | T0814 | 9100002 | 1 |
| `restart-comms` | FC8 Diagnostics, sub-function 1 Restart Communications | T0816 | 9100003 | 1 |
| `flood` | 300 new connections in a burst, each sending one FC3 read | T0846 | 9100006 | 2 |

Baseline: HMI-only traffic (reads plus the allowed write from 10.10.1.20) must raise **no priority:1 alerts**.
Check with `make alerts ARGS="--forbid-priority 1"` before running any attack.

Notes:
- `flood` has no dedicated rate rule; it is caught by the connection-count rule 9100006
  (20 SYNs to `OT_NET`:502 from one non-writer host within 60 s).
- `listen-only`: a real device would stop answering until it receives Restart Communications
  (`restart-comms`) or is power-cycled. The pymodbus lab PLC keeps answering, so the HMI is not
  disrupted in the lab. Only the detection is exercised here, not the impact.

## Exercise

For trainees: an instructor runs the scenarios in any order. The trainee watches the alerts and answers:

1. **Which host** is the attacker, and how can you tell from the alerts alone?
2. **Which alerts would open a case** in LogManthan (`priority:1`), and which are context only?
3. For `scan`: why does the sweep of other addresses not count towards 9100006? *(Hint: `OT_NET`.)*
4. For `write`: the HMI writes HR0 every 30 s too. Why does only the attacker's write alert?
5. For `listen-only`: on a real PLC, what would the operator see on the HMI afterwards, and why is that dangerous?
6. Which MITRE ATT&CK for ICS technique does each alert map to?

Reset between runs with `make lab-down && make lab-up`. Alerts are appended to `lab/out/eve.json`;
use `--since` to look at one run only.

## Safety and hardening

- The attacker and HMI refuse any target outside `10.10.1.0/24` before opening a socket
  (`common/labnet.py: check_target`). Try `docker run --rm --network none otlab/attacker:local write --target 203.0.113.50`.
- `otlab` is `internal: true`: containers cannot reach the internet or your LAN.
- No host ports are published. No container is `privileged`.
- PLC, HMI and attacker run as a non-root user (uid 10001) with a read-only root filesystem,
  all capabilities dropped and `no-new-privileges`. The PLC binds 502 using the per-container
  sysctl `net.ipv4.ip_unprivileged_port_start=0` instead of a capability.
- The Suricata sensor and the capture container use the host network namespace, because that is the
  only place the `otlab0` bridge is visible. They open no ports. Capabilities: `NET_ADMIN` and
  `NET_RAW` (capture), plus `DAC_READ_SEARCH` for Suricata only, to read the image's `suricata.yaml`
  (mode 0600). That capability grants read access only, not write.
- Images are pinned by digest; pymodbus is pinned by version and hash.
- No passwords exist anywhere in the lab.

## Troubleshooting

- **No alerts at all:** check `make lab-logs` for `suricata-1 ... Engine started` and that
  `lab/out/eve.json` grows (`stats` events every few seconds).
- **Linux: Suricata can't write `lab/out/`:** the sensor runs as root without `DAC_OVERRIDE`, so it can
  only write a directory owned by root. Let Docker create `lab/out/` (delete it first if you
  created it yourself).
- **pymodbus deprecation notice in the PLC log:** harmless. The lab is pinned to pymodbus 3.16.2;
  the datastore API used here is removed only in pymodbus 4.
