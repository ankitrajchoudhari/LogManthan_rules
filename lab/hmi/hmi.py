"""Lab HMI: normal Modbus polling.

Reads holding registers and coils every POLL_SECONDS, and writes one setpoint every
WRITE_SECONDS. The HMI is in OT_WRITERS, so none of this should raise a priority:1 alert.
"""

import logging
import os
import random
import time

import labnet

PLC = os.environ.get("PLC_HOST", "10.10.1.10")
POLL = float(os.environ.get("POLL_SECONDS", "1"))
WRITE_EVERY = float(os.environ.get("WRITE_SECONDS", "30"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s hmi %(message)s")


def run_session():
    client = labnet.ModbusClient(PLC)
    logging.info("connected to %s:502", PLC)
    last_write = time.monotonic()
    polls = 0
    try:
        while True:
            client.request(labnet.read_holding(0, 10))
            client.request(labnet.read_coils(0, 16))
            polls += 1
            if time.monotonic() - last_write >= WRITE_EVERY:
                setpoint = random.randint(90, 110)
                client.request(labnet.write_single_register(0, setpoint))
                logging.info("allowed write: HR0 = %d (after %d polls)", setpoint, polls)
                last_write = time.monotonic()
            time.sleep(POLL)
    finally:
        client.close()


def main():
    labnet.check_target(PLC)
    while True:
        try:
            run_session()
        except (OSError, ConnectionError) as exc:
            logging.warning("session ended (%s); reconnecting in 5 s", exc)
            time.sleep(5)


if __name__ == "__main__":
    main()
