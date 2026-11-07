# bacnet - device-properties

Enumerate all standard properties of the BACnet Device object.

## Usage

```sh
iottack bacnet device-properties --host <HOST> [OPTIONS]
```

## Description

Reads every standard ASHRAE 135 property of the Device object on the
target via unauthenticated ReadProperty requests. Properties that the
device does not support or restricts are shown as `<not readable>`.

The Device object is the root of a BACnet device's information model.
Its properties expose configuration, capability and operational state.
Readable properties are reported as Critical findings.

### Properties attempted

Required Device object properties, optional common properties, and operational flags:

- Object Identifier, Object Name, Object Type
- System Status, Vendor Name, Vendor Identifier, Model Name
- Firmware Revision, Application Software Version
- Protocol Version, Protocol Revision
- Protocol Services Supported, Protocol Object Types Supported
- Object List, Max APDU Length Accepted, Segmentation Supported
- APDU Timeout, Number of APDU Retries, Database Revision
- Description, Location, Local Date, Local Time, UTC Offset
- Daylight Savings Status, Profile Name
- Last Restart Reason, Backup and Restore State
- Out of Service, Event State, Status Flags

### Severity mapping

| Finding | Severity |
| ------- | -------- |
| No Device properties readable | Info |
| Device properties readable unauthenticated | Critical |

## Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--host <HOST>` | `-H` | *(required)* | Target BACnet/IP device |
| `--port <PORT>` | `-p` | `47808` | BACnet/IP UDP port |
| `--timeout-ms <MS>` | - | `5000` | Per-request timeout in ms |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack bacnet device-properties --host 192.168.1.50

Plugin name:    bacnet/device-properties
Execution time: 8.74 s
Status:         pass
Date:           2025-10-06 00:00:00 UTC

24 of 31 Device properties readable unauthenticated at 192.168.1.50:47808
  Object Identifier: Device:1001
  Object Name: HVAC-Controller-01
  Object Type: 8
  System Status: 0
  Vendor Name: Siemens
  Vendor Identifier: 16
  Model Name: PXC100.D
  Firmware Revision: 2.4.1
  Application Software Version: 3.1.0
  Protocol Version: 1
  Protocol Revision: 14
  Protocol Services Supported: <binary/complex>
  Protocol Object Types Supported: <binary/complex>
  Max APDU Length Accepted: 1476
  Segmentation Supported: 3
  APDU Timeout (ms): 6000
  Number of APDU Retries: 3
  Database Revision: 42
  Description: Building 7, HVAC Zone A
  Location: Level 3, Plant Room
  Local Date: 2025-11-06
  Local Time: 09:42:15.00
  UTC Offset (min): -300
  Out of Service: false
  ...
  Profile Name: <not readable>
  Event State: <not readable>
```
