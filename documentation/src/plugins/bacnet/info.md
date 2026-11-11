# bacnet - info

Show basic identification and status properties of a BACnet/IP device.

## Usage

```sh
iottack bacnet info --host <HOST> [OPTIONS]
```

## Description

Connects to the target BACnet/IP device and reads a curated set of
Device-object properties that identify and characterize the device:

- vendor
- model
- firmware version
- application software version
- location
- protocol version
- APDU transport settings
- system status
- local clock
- backup/restore state

All reads are unauthenticated ReadProperty requests on the Device object. Any
identifying property returned without credentials is flagged Critical.

### Properties read

| Property | Description |
| -------- | ----------- |
| Object Identifier | Device object ID (type=8, instance=N) |
| Object Name | Human-readable device name |
| System Status | Operational status (operational, load-expected, etc.) |
| Vendor Name | Manufacturer string |
| Vendor Identifier | Numeric vendor ID |
| Model Name | Device model |
| Firmware Revision | Firmware version string |
| Application Software Version | Application layer software version |
| Description | Free-text description |
| Location | Physical or logical location |
| Protocol Version | BACnet protocol version |
| Protocol Revision | BACnet protocol revision |
| Max APDU Length Accepted | Maximum APDU size in bytes |
| Segmentation Supported | Segmentation capability |
| APDU Timeout | Per-request timeout in milliseconds |
| APDU Retries | Number of APDU retries |
| Database Revision | Configuration database revision counter |
| Last Restart Reason | Reason for last device restart |
| Backup and Restore State | Backup/restore operational state |
| Local Date | Device local date |
| Local Time | Device local time |
| UTC Offset | UTC offset in minutes |
| Daylight Savings | Daylight savings status |
| Profile Name | BACnet interoperability profile |

### Severity mapping

| Finding | Severity |
| ------- | -------- |
| Device responds but no properties readable | High |
| Identifying properties readable unauthenticated | Critical |

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
$ iottack bacnet info --host 192.168.1.50

Plugin name:    bacnet/info
Execution time: 2.31 s
Status:         pass
Date:           2025-11-05 00:00:00 UTC

18 device properties readable unauthenticated at 192.168.1.50:47808
  Address:    192.168.1.50:47808
  Device ID:  1001
  Vendor ID:  16 (Siemens)
  Max APDU:   1476
  Object Identifier: Device:1001
  Object Name: HVAC-Controller-01
  System Status: 0
  Vendor Name: Siemens
  Model Name: PXC100.D
  Firmware Revision: 2.4.1
  Application Software Version: 3.1.0
  Description: Building 7, HVAC Zone A
  Location: Level 3, Plant Room
  Protocol Version: 1
  Protocol Revision: 14
  Local Date: 2025-11-05
  Local Time: 09:42:15.00
  UTC Offset (min): -300
```
