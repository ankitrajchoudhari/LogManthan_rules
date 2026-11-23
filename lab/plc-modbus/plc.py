"""Lab Modbus/TCP PLC: pymodbus server on 502 with coils and holding registers."""

import asyncio
import logging

from pymodbus import ModbusDeviceIdentification
from pymodbus.datastore import ModbusDeviceContext, ModbusSequentialDataBlock, ModbusServerContext
from pymodbus.server import StartAsyncTcpServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s plc %(message)s")


async def main():
    # pymodbus blocks start at 1, which serves protocol address 0.
    device = ModbusDeviceContext(
        co=ModbusSequentialDataBlock(1, [False] * 100),      # coils 0-99 (pumps, valves)
        di=ModbusSequentialDataBlock(1, [False] * 100),
        ir=ModbusSequentialDataBlock(1, [0] * 100),
        hr=ModbusSequentialDataBlock(1, [100, 50] + [0] * 98),  # holding regs 0-99 (setpoints)
    )
    identity = ModbusDeviceIdentification(
        info_name={
            "VendorName": "OT Lab",
            "ProductCode": "LAB-PLC",
            "ProductName": "Lab Modbus PLC",
            "ModelName": "lab-plc-modbus",
            "MajorMinorRevision": "1.0",
        }
    )
    logging.info("listening on 0.0.0.0:502")
    await StartAsyncTcpServer(
        context=ModbusServerContext(devices=device, single=True),
        identity=identity,
        address=("0.0.0.0", 502),
    )


if __name__ == "__main__":
    asyncio.run(main())
