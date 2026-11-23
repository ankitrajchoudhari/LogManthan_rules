# OT lab

A small, self-contained Modbus/TCP plant in Docker: a PLC, an HMI doing normal polling, an attacker,
and a Suricata 8.0.7 sensor running this repo's rules. Use it to prove each rule fires on the attack
it targets and stays quiet on normal traffic. It can also be run as a **cyber-range exercise**
(see [Exercise](#exercise)).

## Topology

One internal Docker bridge `otlab` (`10.10.1.0/24`, interface `otlab0`). It has **no internet access,
no ports published to the host, and no IP on the bridge itself**, so the Docker host is not reachable from
the lab at the gateway address 10.10.1.1.

| Host | IP | Role | Address group |
|---|---|---|---|
| `plc-modbus` | 10.10.1.10 | pymodbus server on 502: coils 0–99, holding registers 0–99 | `OT_NET` |
| `hmi` | 10.10.1.20 | Reads HR0–9 and coils 0–15 every 1 s, writes a setpoint to HR0 every 30 s | `OT_WRITERS` |
| *(none yet)* | 10.10.1.30 | Engineering workstation slot | `ENG_WS` |
| *(phase 6)* | 10.10.1.40 | DNP3 master slot | `DNP3_MASTERS` |
| `attacker` | 10.10.1.66 | Attack traffic generator, started on demand | none |
| *(unused)* | 10.10.1.128/25 | IT network slot | `IT_NET` |
| `suricata` | host netns | Sniffs `otlab0` with [suricata/suricata.yaml](suricata/suricata.yaml), writes `lab/out/eve.json` | — |

## Quick start

Needs Docker (with Compose v2) and GNU make. Run from the repo root.

```sh
make lab-up                     # build + start plc-modbus, hmi, suricata
make alerts                     # LM-OT alerts seen so far (none, if only the HMI is running)
make attack SCENARIO=write      # run one attack scenario
make alerts ARGS="--src 10.10.1.66 --expect 9100001"
make capture NAME=write DURATION=20 HOST=10.10.1.66   # record to lab/out/write.pcap (run an attack meanwhile)
make record-fixtures            # re-record all test captures into tests/suricata/lab/
make lab-logs
make lab-down
```

`make alerts` options: `--since YYYY-MM-DDTHH:MM:SS` (UTC), `--src IP`, `--expect SID` (repeatable),
`--forbid-priority N`, `--quiet`. It exits 1 if an expectation fails.

## Scenarios

| `SCENARIO=` | What it sends | MITRE ATT&CK for ICS | Expected SID | Priority |
|---|---|---|---|---|
| `scan` | TCP connect sweep of the lab hosts on 502, then 25 new connections to the PLC, each with FC43 Read Device Identification | T0846 | 9100006, 9100004 | 2, 2 |
| `write` | FC6 Write Single Register (HR0 = 9999) and FC16 Write Multiple Registers (HR10–14) | T0855, T0836 | 9100001 | 1 |
| `listen-only` | FC8 Diagnostics, sub-function 4 Force Listen Only Mode | T0814 | 9100002 | 1 |
| `restart-comms` | FC8 Diagnostics, sub-function 1 Restart Communications | T0816 | 9100003 | 1 |
| `flood` | 1000 FC3 reads in a burst over 4 connections | T0814 | 9100007 | 2 |

Baseline: HMI-only traffic (reads plus the allowed write from 10.10.1.20) must raise **no priority:1 alerts**.
Check with `make alerts ARGS="--forbid-priority 1"` before running any attack.

Notes:
- `flood` is caught by the request-rate rule 9100007 (more than 300 Modbus requests in 10 s from one
  host). The HMI sends ~21 per 10 s. It uses only 4 connections, so it does not trip the connection-count
  rule 9100006 (20 SYNs in 60 s), which belongs to `scan`.
- `listen-only`: a real device would stop answering until it receives Restart Communications
  (`restart-comms`) or is power-cycled. The pymodbus lab PLC keeps answering, so the HMI is not
  disrupted in the lab. Only the detection is exercised here, not the impact.

## Exercise

For trainees: an instructor runs the scenarios in any order. The trainee watches the alerts and answers:

1. **Which host** is the attacker, and how can you tell from the alerts alone?
2. **Which alerts would open a case** in LogManthan (`priority:1`), and which are context only?
3. For `scan`: why does the sweep of other addresses not count towards 9100006? *(Hint: `OT_NET`.)*
   And why does `flood` raise 9100007 but not 9100006?
4. For `write`: the HMI writes HR0 every 30 s too. Why does only the attacker's write alert?
5. For `listen-only`: on a real PLC, what would the operator see on the HMI afterwards, and why is that dangerous?
6. Which MITRE ATT&CK for ICS technique does each alert map to?

Reset between runs with `make lab-down && make lab-up`. Alerts are appended to `lab/out/eve.json`;
use `--since` to look at one run only.

## Safety and hardening

- The attacker and HMI refuse any target outside `10.10.1.0/24`, and also the network address
  10.10.1.0, the gateway 10.10.1.1 and the broadcast 10.10.1.255, before opening a socket
  (`common/labnet.py: check_target`). `scan` skips those three as well.
  Try `docker run --rm --network none otlab/attacker:local write --target 10.10.1.1`.
- `otlab` is `internal: true`: containers cannot reach the internet or your LAN. The bridge also has no IP
  (`com.docker.network.bridge.inhibit_ipv4`). Without that, 10.10.1.1 is the Docker host itself: on Docker
  Desktop it answered on every port tried, and port 111 (rpcbind) was open.
- No host ports are published. No container is `privileged`.
- PLC, HMI and attacker run as a non-root user (uid 10001) with a read-only root filesystem,
  all capabilities dropped and `no-new-privileges`. The PLC binds 502 using the per-container
  sysctl `net.ipv4.ip_unprivileged_port_start=0` instead of a capability.
- The Suricata sensor and the capture container use the host network namespace, because that is the
  only place the `otlab0` bridge is visible. They open no ports and have no `NET_ADMIN`.
  - **Suricata:** `NET_RAW` only. It reads a minimal config from the repo
    ([suricata/suricata.yaml](suricata/suricata.yaml), mounted read-only), not the image's
    root-unreadable one. It sets the bridge promiscuous through its packet socket (`NET_RAW` is enough
    for that). `NET_ADMIN` would only be needed to switch off NIC offloads, so the sensor logs two
    expected warnings at start: `NIC offloading ... SET` and `using AF_PACKET with offloads enabled`.
    That is harmless here: lab Modbus frames are small request/response packets, and every
    scenario is detected (see the test captures).
  - **Capture (tcpdump):** `-p` (no promiscuous mode) and `-Z tcpdump` (drops root to the `tcpdump`
    user). Capabilities `NET_RAW`, plus `SETUID`/`SETGID`/`CHOWN` for that privilege drop, plus `KILL`
    so `timeout` can stop the now non-root tcpdump (it only reaches this container's processes).
    With `-p`, a Linux bridge passes switched unicast traffic to the capture only while the bridge is
    promiscuous, which the sensor sets. So capture refuses to start unless the sensor is running.
- Images are pinned by digest; pymodbus is pinned by version and hash.
- No passwords exist anywhere in the lab.

## Test captures

`make record-fixtures` re-records one capture per scenario plus 130 s of normal HMI polling into
`tests/suricata/lab/` (attack captures are filtered to the attacker, the HMI one to the HMI). The test
runner replays them with the lab address groups and exact matching. Then update the `sha256` values in
`tests/suricata/fixtures.json` with the ones the script prints.

## Troubleshooting

- **No alerts at all:** check `make lab-logs` for `suricata-1 ... Engine started` and that
  `lab/out/eve.json` grows (`stats` events every few seconds).
- **`capture: otlab0 is not promiscuous`:** the sensor is not running; `make lab-up` first.
- **Linux: Suricata can't write `lab/out/`:** the sensor runs as root without `DAC_OVERRIDE`, so it can
  only write a directory owned by root. Let Docker create `lab/out/` (delete it first if you
  created it yourself).
- **pymodbus deprecation notice in the PLC log:** harmless. The lab is pinned to pymodbus 3.16.2;
  the datastore API used here is removed only in pymodbus 4.
