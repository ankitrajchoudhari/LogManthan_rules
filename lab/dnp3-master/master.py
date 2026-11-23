"""Lab DNP3 master (SCADA front end) at 10.10.1.40, the lab's DNP3_MASTERS host.

Normal polling only: on connect an integrity poll (class 1, 2, 3 and 0), clearing the
outstation's DEVICE_RESTART indication with a WRITE when it is set (an allowed write: this host
is in DNP3_MASTERS), then class 1-3 event polls every POLL_SECONDS and an integrity poll every
INTEGRITY_SECONDS. None of this should raise any LM-OT alert or any Suricata DNP3 event.
"""

import logging
import os
import time

import dnp3
import labnet

OUTSTATION = os.environ.get("OUTSTATION_HOST", "10.10.1.11")
POLL = float(os.environ.get("POLL_SECONDS", "2"))
INTEGRITY_EVERY = float(os.environ.get("INTEGRITY_SECONDS", "60"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s master %(message)s")


def integrity(session):
    iin1, _, _ = session.request(dnp3.READ, dnp3.INTEGRITY)
    if iin1 & dnp3.IIN1_DEVICE_RESTART:
        session.request(dnp3.WRITE, dnp3.clear_restart_iin())
        logging.info("outstation reported a restart; cleared DEVICE_RESTART")


def run_session():
    session = dnp3.connect_master(OUTSTATION)
    logging.info("connected to %s:%d", OUTSTATION, dnp3.PORT)
    polls = 0
    try:
        integrity(session)
        last_integrity = time.monotonic()
        while True:
            time.sleep(POLL)
            if time.monotonic() - last_integrity >= INTEGRITY_EVERY:
                integrity(session)
                last_integrity = time.monotonic()
            else:
                iin1, _, _ = session.request(dnp3.READ, dnp3.EVENTS)
                if iin1 & dnp3.IIN1_DEVICE_RESTART:
                    integrity(session)
            polls += 1
            if polls % 100 == 0:
                logging.info("%d polls", polls)
    finally:
        session.close()


def main():
    labnet.check_target(OUTSTATION)
    while True:
        try:
            run_session()
        except (OSError, ConnectionError, ValueError) as exc:
            logging.warning("session ended (%s); reconnecting in 5 s", exc)
            time.sleep(5)


if __name__ == "__main__":
    main()
