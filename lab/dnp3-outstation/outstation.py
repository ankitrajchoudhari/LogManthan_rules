"""Lab DNP3 outstation (RTU) on TCP 20000, link address 10. Standard library only.

Holds 8 binary inputs, 4 binary outputs and 4 analog inputs that drift slowly. It answers:
  READ (class 0 static data; class 1-3 events: none), WRITE (g80v1 clear DEVICE_RESTART,
  g50v1 time), SELECT / OPERATE / DIRECT_OPERATE (g12v1 CROB: echoed back as accepted),
  COLD / WARM RESTART (g52v2 delay, DEVICE_RESTART set again) and ENABLE / DISABLE
  UNSOLICITED (accepted; this outstation never sends unsolicited responses).
Any other function code gets IIN2 NO_FUNC_CODE_SUPPORT. It accepts commands from anyone, like
many real field devices: deciding who may send them is the network's and the sensor's job.
"""

import logging
import random
import socket
import struct
import threading

import dnp3

logging.basicConfig(level=logging.INFO, format="%(asctime)s outstation %(message)s")


class Outstation:
    def __init__(self):
        self.lock = threading.Lock()
        self.restart = True     # IIN1 DEVICE_RESTART until a master clears it
        self.need_time = True   # IIN1 NEED_TIME until a master writes the time
        self.binary_in = [random.random() < 0.5 for _ in range(8)]
        self.binary_out = [False] * 4
        self.analog = [1000, 2000, 3000, 4000]

    def iin1(self):
        return (dnp3.IIN1_DEVICE_RESTART if self.restart else 0) | (dnp3.IIN1_NEED_TIME if self.need_time else 0)

    def static_data(self):
        self.analog = [v + random.randint(-5, 5) for v in self.analog]
        return (dnp3.binary_inputs(self.binary_in) + dnp3.binary_outputs(self.binary_out)
                + dnp3.analog_inputs(self.analog))

    def handle(self, fc, objects, peer):
        """Return (iin2, response objects) for one request."""
        if fc == dnp3.READ:
            # class 0 (g60v1) returns static data; class 1-3 polls find no events
            return 0, self.static_data() if b"\x3c\x01\x06" in objects else b""
        if fc == dnp3.WRITE:
            if objects.startswith(bytes([80, 1])):
                self.restart = False
            elif objects.startswith(bytes([50, 1])):
                self.need_time = False
            logging.info("WRITE from %s: %s", peer, objects[:2].hex())
            return 0, b""
        if fc in (dnp3.SELECT, dnp3.OPERATE, dnp3.DIRECT_OPERATE):
            if objects[:3] == bytes([12, 1, 0x28]) and len(objects) >= 18:
                index = struct.unpack("<H", objects[5:7])[0]
                if fc != dnp3.SELECT and index < len(self.binary_out):
                    self.binary_out[index] = not self.binary_out[index]
                logging.info("control fc=%d from %s on output %d", fc, peer, index)
            return 0, objects   # echo the CROB with status 0 (success)
        if fc in (dnp3.COLD_RESTART, dnp3.WARM_RESTART):
            logging.info("%s restart from %s", "cold" if fc == dnp3.COLD_RESTART else "warm", peer)
            self.restart = True
            return 0, dnp3.time_delay_fine(500)
        if fc in (dnp3.ENABLE_UNSOLICITED, dnp3.DISABLE_UNSOLICITED):
            logging.info("%s unsolicited from %s", "enable" if fc == dnp3.ENABLE_UNSOLICITED else "disable", peer)
            return 0, b""
        logging.info("unsupported function code %d from %s", fc, peer)
        return dnp3.IIN2_NO_FUNC_CODE_SUPPORT, b""

    def serve_client(self, conn, peer):
        session = dnp3.Session(conn, dnp3.OUTSTATION_ADDR, dnp3.MASTER_ADDR, False)
        try:
            while True:
                apdu = session.recv_apdu()
                if len(apdu) < 2:
                    continue
                seq, fc = apdu[0] & 0x0F, apdu[1]
                with self.lock:
                    iin2, objects = self.handle(fc, apdu[2:], peer)
                    session.respond(seq, self.iin1(), iin2, objects)
        except (OSError, ConnectionError, ValueError) as exc:
            logging.info("session with %s ended (%s)", peer, exc)
        finally:
            session.close()


def main():
    station = Outstation()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", dnp3.PORT))
    srv.listen(8)
    logging.info("listening on port %d, link address %d", dnp3.PORT, dnp3.OUTSTATION_ADDR)
    while True:
        conn, (peer, _) = srv.accept()
        threading.Thread(target=station.serve_client, args=(conn, peer), daemon=True).start()


if __name__ == "__main__":
    main()
