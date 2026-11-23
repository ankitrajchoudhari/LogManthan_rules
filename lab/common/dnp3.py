"""Minimal DNP3 (IEEE 1815) over TCP for the OT lab. Standard library only.

Just enough of the protocol for a lab master, outstation and attacker:
  - link layer: 0x0564 frames, header CRC and a CRC after every 16-byte data block
    (CRC-16/DNP: reflected polynomial 0xA6BC, initial value 0, result inverted, little-endian);
  - transport layer: one segment per fragment (FIR and FIN set), 6-bit sequence number;
  - application layer: request/response headers and the few object headers the lab uses.
Only single-fragment messages (at most 249 application bytes) are supported; that covers every
message the lab sends. Every connection goes through labnet.connect, so the lab guard applies.
"""

import socket
import struct

import labnet

PORT = 20000
MASTER_ADDR = 1        # link address of the master (an attacker simply reuses it)
OUTSTATION_ADDR = 10   # link address of the outstation

# application function codes
READ, WRITE, SELECT, OPERATE, DIRECT_OPERATE = 1, 2, 3, 4, 5
COLD_RESTART, WARM_RESTART = 13, 14
ENABLE_UNSOLICITED, DISABLE_UNSOLICITED = 20, 21
RESPONSE, UNSOLICITED_RESPONSE = 0x81, 0x82

# internal indications (IIN1 / IIN2 bits)
IIN1_DEVICE_RESTART = 0x80
IIN1_NEED_TIME = 0x10
IIN2_NO_FUNC_CODE_SUPPORT = 0x01

MAX_APDU = 249  # 250 link user-data bytes minus the transport header


# ---------------------------------------------------------------- CRC and link layer
def crc16(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def _with_crc(block):
    return block + struct.pack("<H", crc16(block))


def link_frame(user_data, dest, src, from_master):
    """Unconfirmed user data frame: DIR set when sent by the master, PRM set, function 4."""
    if len(user_data) > 250:
        raise ValueError("link frame user data is limited to 250 bytes")
    ctrl = (0x80 if from_master else 0x00) | 0x40 | 0x04
    header = bytes([0x05, 0x64, 5 + len(user_data), ctrl]) + struct.pack("<HH", dest, src)
    out = _with_crc(header)
    for i in range(0, len(user_data), 16):
        out += _with_crc(user_data[i:i + 16])
    return out


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed by peer")
        data += chunk
    return data


def read_link_frame(sock):
    """Read one frame; check every CRC. Returns (ctrl, dest, src, user_data)."""
    header = _recv_exact(sock, 10)
    if header[:2] != b"\x05\x64":
        raise ValueError(f"bad link start bytes {header[:2].hex()}")
    if struct.unpack("<H", header[8:10])[0] != crc16(header[:8]):
        raise ValueError("bad link header CRC")
    length, ctrl = header[2], header[3]
    dest, src = struct.unpack("<HH", header[4:8])
    remaining = length - 5
    user_data = b""
    while remaining > 0:
        size = min(16, remaining)
        block = _recv_exact(sock, size + 2)
        if struct.unpack("<H", block[size:])[0] != crc16(block[:size]):
            raise ValueError("bad link data CRC")
        user_data += block[:size]
        remaining -= size
    return ctrl, dest, src, user_data


# ---------------------------------------------------------------- object headers
def class_objects(*classes):
    """Group 60 'all objects' headers (qualifier 0x06) for class 0, 1, 2, 3."""
    return b"".join(bytes([60, 1 + c, 0x06]) for c in classes)


INTEGRITY = class_objects(1, 2, 3, 0)   # class 1-3 events, then class 0 static data
EVENTS = class_objects(1, 2, 3)


def clear_restart_iin():
    """g80v1 internal indications, qualifier 0x00 index 7..7, value 0: clear DEVICE_RESTART."""
    return bytes([80, 1, 0x00, 7, 7, 0x00])


def time_and_date(ms):
    """g50v1 absolute time (ms since 1970, 48-bit), qualifier 0x07 count 1."""
    return bytes([50, 1, 0x07, 1]) + (ms & 0xFFFFFFFFFFFF).to_bytes(6, "little")


def crob(index, code=0x41, count=1, on_ms=1000, off_ms=0, status=0):
    """g12v1 control relay output block, qualifier 0x28 (2-byte count and index). 0x41 = pulse on/close."""
    return (bytes([12, 1, 0x28]) + struct.pack("<HH", 1, index)
            + struct.pack("<BBIIB", code, count, on_ms, off_ms, status))


def binary_inputs(states):
    """g1v2 binary input with flags, qualifier 0x00 start/stop. Flag 0x01 = online, 0x80 = state."""
    flags = bytes(0x01 | (0x80 if s else 0) for s in states)
    return bytes([1, 2, 0x00, 0, len(states) - 1]) + flags


def binary_outputs(states):
    """g10v2 binary output status with flags, qualifier 0x00 start/stop."""
    flags = bytes(0x01 | (0x80 if s else 0) for s in states)
    return bytes([10, 2, 0x00, 0, len(states) - 1]) + flags


def analog_inputs(values):
    """g30v1 32-bit analog input with flag, qualifier 0x00 start/stop."""
    body = b"".join(struct.pack("<Bi", 0x01, v) for v in values)
    return bytes([30, 1, 0x00, 0, len(values) - 1]) + body


def time_delay_fine(ms):
    """g52v2 time delay fine, qualifier 0x07 count 1: the answer to a cold or warm restart."""
    return bytes([52, 2, 0x07, 1]) + struct.pack("<H", ms)


# ---------------------------------------------------------------- session
class Session:
    """One end of a DNP3 association over a TCP socket (master or outstation side)."""

    def __init__(self, sock, local, remote, is_master):
        self.sock, self.local, self.remote, self.is_master = sock, local, remote, is_master
        self.tseq = 0   # transport sequence, 0..63
        self.aseq = 0   # application sequence (master requests), 0..15

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def send_apdu(self, apdu):
        if len(apdu) > MAX_APDU:
            raise ValueError("APDU larger than one fragment")
        tpdu = bytes([0xC0 | self.tseq]) + apdu      # FIN | FIR | sequence
        self.tseq = (self.tseq + 1) & 0x3F
        self.sock.sendall(link_frame(tpdu, self.remote, self.local, self.is_master))

    def recv_apdu(self):
        """Next application fragment (single-segment messages only)."""
        while True:
            _, dest, _, user_data = read_link_frame(self.sock)
            if dest != self.local or not user_data:
                continue
            if user_data[0] & 0xC0 != 0xC0:
                raise ValueError("multi-segment transport messages are not supported")
            return user_data[1:]

    def request(self, fc, objects=b"", expect_reply=True):
        """Master: send a request, return (iin1, iin2, objects) of its response."""
        seq = self.aseq
        self.aseq = (self.aseq + 1) & 0x0F
        self.send_apdu(bytes([0xC0 | seq, fc]) + objects)   # FIR | FIN | sequence, no CON
        if not expect_reply:
            return None
        while True:
            apdu = self.recv_apdu()
            if len(apdu) >= 4 and apdu[1] == RESPONSE and apdu[0] & 0x0F == seq:
                return apdu[2], apdu[3], apdu[4:]

    def respond(self, seq, iin1, iin2, objects=b""):
        """Outstation: answer the request with application sequence seq."""
        self.send_apdu(bytes([0xC0 | (seq & 0x0F), RESPONSE, iin1, iin2]) + objects)


def connect_master(host, port=PORT, timeout=5.0):
    """Master-side session to a lab outstation (lab guard applies)."""
    sock = labnet.connect(host, port, timeout)
    return Session(sock, MASTER_ADDR, OUTSTATION_ADDR, True)
