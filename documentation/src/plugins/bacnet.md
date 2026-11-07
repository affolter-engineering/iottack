# BACnet plugins

BACnet (Building Automation and Control Networks) is an ASHRAE/ISO/ANSI
standard protocol for building automation systems. It is widely deployed in
HVAC controllers, fire alarm panels, lighting systems, energy meters and
access control equipment in commercial buildings and industrial facilities.

BACnet/IP carries the protocol over UDP port 47808 (0xBAC0) and requires no
authentication by default. Any host that can reach the UDP port can enumerate
devices, read sensor values and setpoints and write to outputs or actuators.
BACnet/SC (Secure Connect) adds TLS mutual authentication but is not yet
widely deployed.

## Device model

A BACnet network is composed of **devices**, each of which exposes a set of
**objects**. Every object has a type (e.g., Analog-Input, Binary-Output,
Device) and an instance number, identified together as an Object Identifier.
Objects carry **properties** (present value, description, units, limits, etc.)
read and written via the ReadProperty/WriteProperty confirmed services.

## Discovery

Devices announce themselves via the Who-Is/I-Am exchange. A client
broadcasts a Who-Is request. Every device in range responds with an I-Am
containing its device instance number, vendor ID and maximum APDU size.

When the iottack client and the target device share a host, the simulator
already holds port 47808 so I-Am broadcasts cannot be received. Use
`--device-id` to bypass discovery and specify the device instance directly.

## Plugins

| Plugin | Command | Purpose |
| -------| ------- | ------- |
| [find-devices](./bacnet/find-devices.md) | `iottack bacnet find-devices` | Discover all reachable BACnet/IP devices via Who-Is broadcast |
| [scan](./bacnet/scan.md) | `iottack bacnet scan` | Enumerate devices and read key Device-object properties |
| [info](./bacnet/info.md) | `iottack bacnet info` | Read identification and status properties of a single device |
| [network-info](./bacnet/network-info.md) | `iottack bacnet network-info` | Read BACnet network configuration of a device |
| [services](./bacnet/services.md) | `iottack bacnet services` | Read supported BACnet services and object types |
| [device-properties](./bacnet/device-properties.md) | `iottack bacnet device-properties` | Read all standard Device-object properties |
| [object-list](./bacnet/object-list.md) | `iottack bacnet object-list` | Enumerate all objects and read their present values |
| [object-properties](./bacnet/object-properties.md) | `iottack bacnet object-properties` | Read all standard properties of a specific object |
| [event-info](./bacnet/event-info.md) | `iottack bacnet event-info` | Read event and alarm state of a device |
| [fuzz](./bacnet/fuzz.md) | `iottack bacnet fuzz` | Send malformed BACnet PDUs and report anomalous responses |

## Severity model

| Finding | Severity |
| ------- | -------- |
| Device found; all property reads rejected | High |
| Identification/status properties readable unauthenticated | Critical |
| Process data (present values) readable unauthenticated | Critical |
| Writes accepted unauthenticated | Critical |
| No devices found or connection failed | Info |
