#!/usr/bin/env python3
"""BACnet/IP test server for IoTtack.

Exposes two virtual BACnet stations inside a single device so that BACnet
discovery and read/write tools can be exercised locally without real hardware.

Device layout
-------------
  Device instance  : 100  (configurable)
  Device name      : SimBAS
  Protocol         : BACnet/IP, UDP port 47808 (configurable)

  Station 1 - Boiler Room Controller
    analogInput  1   boiler-temp          75.3 °C
    analogInput  2   water-pressure        2.1 bar
    analogInput  3   flue-gas-temp       185.0 °C
    analogOutput 1   burner-power         65.0 %
    analogOutput 2   pump-speed           80.0 %
    binaryInput  1   high-temp-alarm      False
    binaryInput  2   low-pressure-alarm   False
    binaryOutput 1   pump-enable          True
    binaryOutput 2   burner-enable        True

  Station 2 - HVAC Unit
    analogInput  11  supply-air-temp      18.5 °C
    analogInput  12  return-air-temp      24.2 °C
    analogInput  13  outdoor-air-temp      9.8 °C
    analogOutput 11  cooling-setpoint     21.0 °C
    analogOutput 12  heating-setpoint     19.0 °C
    analogOutput 13  fan-speed            75.0 %
    binaryInput  11  fan-running          True
    binaryInput  12  filter-dirty         False
    binaryOutput 11  chilled-water-valve  True
    binaryOutput 12  hot-water-valve      False

Usage
-----
  python simulator.py                    # 0.0.0.0:47808, device 100
  python simulator.py --port 47809       # alternate port
  python simulator.py --host 127.0.0.1   # loopback only
  python simulator.py --device 200       # custom device instance
"""

import argparse
import asyncio
import logging

from bacpypes3.app import Application
from bacpypes3.apdu import WhoIsRequest
from bacpypes3.local.analog import AnalogInputObject, AnalogOutputObject
from bacpypes3.local.binary import BinaryInputObject, BinaryOutputObject
from bacpypes3.local.device import DeviceObject
from bacpypes3.local.networkport import NetworkPortObject

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("bacnet-simulator")


class SimBASApplication(Application):
    """Application with unicast I-Am so loopback clients receive the response.

    The standard bacpypes3 Application broadcasts I-Am to 255.255.255.255:47808.
    When client and simulator share a host the simulator holds port 47808 and
    the client's random-port socket never sees that broadcast.  Sending a
    unicast I-Am back to apdu.pduSource (the client's actual IP:port) fixes
    this for all loopback and same-host testing scenarios.
    """

    async def do_WhoIsRequest(self, apdu: WhoIsRequest) -> None:
        device_id = self.device_object.objectIdentifier[1]

        low = apdu.deviceInstanceRangeLowLimit
        high = apdu.deviceInstanceRangeHighLimit
        if low is not None and device_id < low:
            return
        if high is not None and device_id > high:
            return

        log.info("Who-Is from %s → unicast I-Am (device %d)", apdu.pduSource, device_id)
        await self.i_am(address=apdu.pduSource)


def ai(instance, name, value, units="degreesCelsius", description=""):
    """Create an AnalogInputObject."""
    return AnalogInputObject(
        objectIdentifier=("analog-input", instance),
        objectName=name,
        presentValue=float(value),
        units=units,
        description=description,
        outOfService=False,
    )


def ao(instance, name, value, units="percent", description=""):
    """Create an AnalogOutputObject."""
    return AnalogOutputObject(
        objectIdentifier=("analog-output", instance),
        objectName=name,
        presentValue=float(value),
        units=units,
        description=description,
        outOfService=False,
    )


def bi(instance, name, active, description=""):
    """Create a BinaryInputObject."""
    return BinaryInputObject(
        objectIdentifier=("binary-input", instance),
        objectName=name,
        presentValue="active" if active else "inactive",
        description=description,
        outOfService=False,
    )


def bo(instance, name, active, description=""):
    """Create a BinaryOutputObject."""
    return BinaryOutputObject(
        objectIdentifier=("binary-output", instance),
        objectName=name,
        presentValue="active" if active else "inactive",
        description=description,
        outOfService=False,
    )


async def main() -> None:
    """Main entry point for the BACnet/IP simulator."""
    parser = argparse.ArgumentParser(description="IoTtack BACnet/IP test simulator")
    parser.add_argument(
        "--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=47808, help="UDP port (default: 47808)"
    )
    parser.add_argument(
        "--device", type=int, default=100, help="BACnet device instance (default: 100)"
    )
    args = parser.parse_args()

    station_1_objects = [
        ai(1, "boiler-temp", 75.3, "degreesCelsius", "Boiler water temperature"),
        ai(2, "water-pressure", 2.1, "bars", "System water pressure"),
        ai(3, "flue-gas-temp", 185.0, "degreesCelsius", "Flue gas exit temperature"),
        ao(1, "burner-power", 65.0, "percent", "Burner modulation output"),
        ao(2, "pump-speed", 80.0, "percent", "Circulation pump speed"),
        bi(1, "high-temp-alarm", False, "Boiler over-temperature alarm"),
        bi(2, "low-pressure-alarm", False, "Low water pressure alarm"),
        bo(1, "pump-enable", True, "Circulation pump on/off"),
        bo(2, "burner-enable", True, "Main burner on/off"),
    ]

    station_2_objects = [
        ai(11, "supply-air-temp", 18.5, "degreesCelsius", "Supply air temperature"),
        ai(12, "return-air-temp", 24.2, "degreesCelsius", "Return air temperature"),
        ai(13, "outdoor-air-temp", 9.8, "degreesCelsius", "Outdoor air temperature"),
        ao(11, "cooling-setpoint", 21.0, "degreesCelsius", "Zone cooling setpoint"),
        ao(12, "heating-setpoint", 19.0, "degreesCelsius", "Zone heating setpoint"),
        ao(13, "fan-speed", 75.0, "percent", "Supply fan speed command"),
        bi(11, "fan-running", True, "Supply fan status"),
        bi(12, "filter-dirty", False, "Air filter pressure differential alarm"),
        bo(11, "chilled-water-valve", True, "Chilled water coil valve"),
        bo(12, "hot-water-valve", False, "Heating coil valve"),
    ]

    device = DeviceObject(
        objectIdentifier=("device", args.device),
        objectName="SimBAS",
        maxApduLengthAccepted=1024,
        segmentationSupported="noSegmentation",
        vendorIdentifier=15,
        vendorName="iottack Labs",
        modelName="SimBAS-1000",
        firmwareRevision="1.0",
        applicationSoftwareVersion="1.0",
        description="iottack BACnet/IP building automation simulator",
    )

    address = f"{args.host}:{args.port}"
    network_port = NetworkPortObject(
        objectIdentifier=("network-port", 1),
        objectName="NetworkPort-1",
        networkNumberQuality="unknown",
        bacnetIPUDPPort=args.port,
    )

    all_objects = [device, network_port] + station_1_objects + station_2_objects
    SimBASApplication.from_object_list(all_objects, address)

    log.info(
        "BACnet/IP simulator starting on %s  device-instance=%d", address, args.device
    )
    log.info(
        "Station 1 (Boiler Room): analogInput 1-3, analogOutput 1-2, binaryInput 1-2, binaryOutput 1-2"
    )
    log.info(
        "Station 2 (HVAC Unit):   analogInput 11-13, analogOutput 11-13, binaryInput 11-12, binaryOutput 11-12"
    )
    log.info(
        "Total objects: %d  (plus device object)",
        len(station_1_objects) + len(station_2_objects),
    )
    log.info("Press Ctrl-C to stop.")

    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
