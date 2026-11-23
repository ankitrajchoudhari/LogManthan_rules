"""Shared helpers for the OT lab: lab-network safety check and minimal Modbus/TCP framing.

Every socket the lab opens goes through check_target(), which refuses anything outside
the lab network 10.10.1.0/24, and also its network address, gateway and broadcast address
(the gateway is the Docker host side of the bridge, not a lab device). Standard library only.
"""

import ipaddress
import socket
import struct
import sys

LAB_NET = ipaddress.ip_network("10.10.1.0/24")
LAB_GATEWAY = ipaddress.ip_address("10.10.1.1")
EXCLUDED = {LAB_NET.network_address, LAB_GATEWAY, LAB_NET.broadcast_address}


def is_allowed(ip):
    ip = ipaddress.ip_address(ip)
    return ip in LAB_NET and ip not in EXCLUDED


def lab_hosts():
    """Every address a lab script may target (the /24 minus network, gateway and broadcast)."""
    return [str(h) for h in LAB_NET.hosts() if is_allowed(h)]


def check_target(host):
    """Resolve host and return its IP. Exit unless every resolved address is an allowed lab address."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        sys.exit(f"REFUSED: cannot resolve {host!r}: {exc}")
    addrs = {ipaddress.ip_address(i[4][0]) for i in infos}
    if not addrs:
        sys.exit(f"REFUSED: {host!r} resolved to nothing")
    for a in addrs:
        if a not in LAB_NET:
            sys.exit(f"REFUSED: target {host!r} -> {a} is outside the lab network {LAB_NET}")
        if a in EXCLUDED:
            sys.exit(f"REFUSED: target {host!r} -> {a} is the lab network, gateway or broadcast address")
    return str(next(iter(addrs)))


def connect(host, port, timeout=3.0):
    """Open a TCP connection, but only to a lab address."""
    ip = check_target(host)
    return socket.create_connection((ip, port), timeout=timeout)


class ModbusClient:
    """Tiny Modbus/TCP client: builds MBAP frames, sends a PDU, optionally reads the reply."""

    def __init__(self, host, port=502, unit=1, timeout=3.0):
        self.sock = connect(host, port, timeout)
        self.unit = unit
        self.tid = 0

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def request(self, pdu, expect_reply=True):
        self.tid = (self.tid + 1) & 0xFFFF
        mbap = struct.pack(">HHHB", self.tid, 0, len(pdu) + 1, self.unit)
        self.sock.sendall(mbap + pdu)
        if not expect_reply:
            return None
        header = self._recv(7)
        _, _, length, _ = struct.unpack(">HHHB", header)
        return self._recv(length - 1)

    def _recv(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("connection closed by peer")
            data += chunk
        return data


# PDU builders (function code + data)
def read_coils(addr, count):
    return struct.pack(">BHH", 1, addr, count)


def read_holding(addr, count):
    return struct.pack(">BHH", 3, addr, count)


def write_single_register(addr, value):
    return struct.pack(">BHH", 6, addr, value)


def write_multiple_registers(addr, values):
    return struct.pack(">BHHB", 16, addr, len(values), 2 * len(values)) + b"".join(
        struct.pack(">H", v) for v in values
    )


def diagnostics(subfunction, data=0):
    return struct.pack(">BHH", 8, subfunction, data)


def read_device_identification(code=1, object_id=0):
    # FC43 / MEI type 0x0E (Read Device Identification)
    return struct.pack(">BBBB", 43, 0x0E, code, object_id)
