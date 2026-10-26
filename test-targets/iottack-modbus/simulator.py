#!/usr/bin/env python3
"""Modbus TCP test server for IoTtack.

Starts a persistent Modbus/TCP simulator on port 5020 (configurable) with
pre-populated data across all four data types so every IoTtack Modbus plugin
can be exercised locally.

Default data layout
-------------------
  Holding registers (FC03)  0-999    : mix of fixed, counter, and sensor values
  Input registers   (FC04)  0-99     : read-only analog sensor readings
  Coils             (FC01)  0-31     : alternating ON/OFF pattern
  Discrete inputs   (FC02)  0-31     : fixed sensor bits

Device identification (FC43 MEI) is enabled with realistic vendor strings.

Usage
-----
  python simulator.py                  # listen on 0.0.0.0:5020, unit 1
  python simulator.py --port 502       # standard Modbus port (needs root)
  python simulator.py --host 127.0.0.1 # loopback only
  python simulator.py --unit 3         # respond as unit ID 3
"""

import argparse
import asyncio
import logging

from pymodbus import ModbusDeviceIdentification
from pymodbus.server import StartAsyncTcpServer
from pymodbus.simulator import DataType, SimData, SimDevice

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("modbus-simulator")


def build_holding_registers() -> list[int]:
    """Return 1000 holding registers with a realistic mix of values."""
    regs = [0] * 1000
    # System status word
    regs[0] = 0x0001   # run mode
    regs[1] = 0x0064   # setpoint 100
    regs[2] = 0x01F4   # setpoint 500
    regs[3] = 0x0042   # firmware build
    # Temperature setpoints (addresses 10-19)
    for index, value in enumerate([200, 350, 400, 250, 300, 180, 220, 270, 310, 290]):
        regs[10 + index] = value
    # Process counters (addresses 100-109)
    for index in range(10):
        regs[100 + index] = index * 137 + 42
    # Config block (addresses 200-209)
    regs[200] = 0x0001  # enabled
    regs[201] = 0x09C4  # timeout 2500 ms
    regs[202] = 0x0003  # retries
    regs[203] = 0x0001  # protocol version
    # Alarm thresholds (addresses 500-509)
    for index in range(10):
        regs[500 + index] = 1000 + index * 50
    return regs


def build_input_registers() -> list[int]:
    """Return 100 input registers simulating analog sensor readings."""
    regs = [0] * 100
    # Temperature readings (0.1 °C units)
    regs[0] = 234    # 23.4 °C
    regs[1] = 251    # 25.1 °C
    regs[2] = 187    # 18.7 °C
    # Pressure (mbar)
    regs[10] = 1013
    regs[11] = 987
    # Voltage (0.01 V units)
    regs[20] = 2400  # 24.00 V
    regs[21] = 1199  # 11.99 V
    # Current (mA)
    regs[30] = 420
    regs[31] = 850
    # Uptime (seconds, low word then high word)
    regs[50] = 0xAB12
    regs[51] = 0x0002
    return regs


def build_coils() -> list[bool]:
    """Return 32 coils in an alternating ON/OFF pattern."""
    return [bool(i % 2) for i in range(32)]


def build_discrete_inputs() -> list[bool]:
    """Return 32 discrete inputs representing sensor states."""
    bits = [False] * 32
    bits[0] = True   # door open
    bits[2] = True
    bits[8] = True   # motor running
    bits[9] = True
    return bits


def build_sim_device(unit_id: int) -> SimDevice:  # noqa: ARG001
    """Build and return a simulated Modbus device with pre-populated data."""
    # id=0 is the pymodbus catch-all device: SimCore.__get_device falls back to
    # self.devices[0] when the requested unit ID is not an exact match.
    return SimDevice(
        id=0,
        simdata=(
            [SimData(address=0, values=build_coils(), datatype=DataType.BITS)],
            [SimData(address=0, values=build_discrete_inputs(), datatype=DataType.BITS)],
            [SimData(address=0, values=build_holding_registers(), datatype=DataType.REGISTERS)],
            [SimData(address=0, values=build_input_registers(), datatype=DataType.REGISTERS)],
        ),
    )


def build_identity() -> ModbusDeviceIdentification:
    """Build and return the Modbus device identity information."""
    ident = ModbusDeviceIdentification()
    ident.VendorName = "iottack Labs"
    ident.ProductCode = "SIMBUS-1000"
    ident.MajorMinorRevision = "1.0.0"
    ident.VendorUrl = "https://github.com/your-org/iottack"
    ident.ProductName = "Modbus Test Target"
    ident.ModelName = "SimBus"
    ident.UserApplicationName = "iottack modbus test"
    return ident


async def run_server(host: str, port: int, unit_id: int) -> None:
    """Run the Modbus/TCP simulator server on the specified host, port, and unit ID."""
    device = build_sim_device(unit_id)
    identity = build_identity()

    log.info("Modbus/TCP simulator starting on %s:%d  unit=%d", host, port, unit_id)
    log.info("Data layout:")
    log.info("  Holding registers (FC03)  0-999  (1000 regs)")
    log.info("  Input registers   (FC04)  0-99   (100 regs)")
    log.info("  Coils             (FC01)  0-31   (32 coils)")
    log.info("  Discrete inputs   (FC02)  0-31   (32 bits)")
    log.info("  FC43 MEI device identification: enabled")
    log.info("Press Ctrl-C to stop.")

    await StartAsyncTcpServer(
        context=device,
        identity=identity,
        address=(host, port),
    )


def main() -> None:
    """Parse command-line arguments and start the Modbus/TCP simulator."""
    parser = argparse.ArgumentParser(description="iottack Modbus/TCP test simulator")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5020, help="TCP port (default: 5020)")
    parser.add_argument("--unit", type=int, default=1, help="Modbus unit/slave ID (default: 1)")
    args = parser.parse_args()

    asyncio.run(run_server(args.host, args.port, args.unit))


if __name__ == "__main__":
    main()
