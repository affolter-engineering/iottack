# bacnet - services

Read BACnet services-supported and object-types-supported unauthenticated.

## Usage

```sh
iottack bacnet services --host <HOST> [OPTIONS]
```

## Description

Implements the `get_service_supported` and `object_types_supported` recon
operations from [BACteria](https://github.com/cyber-defence-campus/BACteria).

1. **Services supported**: reads property 97 (services-supported), a BitString
   that indicates every BACnet service the device supports. Dangerous services
   such as `write-property`, `device-communication-control`, and
   `reinitialize-device` are flagged separately when enabled.
2. **Object types supported**: reads property 96 (object-types-supported), a
   BitString that reveals the device's complete object model (sensors,
   actuators, programs, trend logs, etc.).

Both properties require no authentication in standard BACnet/IP, making this
a zero-credential capability fingerprint of the target.

### Dangerous services

| Service | Risk |
| ------- | ---- |
| `write-property` | Modify device properties and control outputs |
| `write-property-multiple` | Modify multiple properties in one request |
| `device-communication-control` | Disable device communications (DoS) |
| `reinitialize-device` | Restart or factory-reset the device |
| `create-object` | Create new BACnet objects on the device |
| `delete-object` | Delete BACnet objects from the device |

### Severity mapping

| Finding | Severity |
| ------- | -------- |
| Services/types not readable | Info |
| Services-supported readable | Medium |
| One or more dangerous services enabled | High |
| Object types supported readable | Info |

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
$ iottack bacnet services --host 192.168.1.50

Plugin name:    bacnet/services
Execution time: 3.12 s
Status:         pass
Date:           2026-10-18 00:00:00 UTC

34 BACnet services readable unauthenticated at 192.168.1.50:47808
  read-property, read-property-multiple, write-property, ...

4 dangerous services enabled at 192.168.1.50:47808
  write-property          - can modify device properties and control outputs
  write-property-multiple - can modify multiple properties in a single request
  device-communication-control - can disable device communications (DoS)
  reinitialize-device     - can restart or factory-reset the device

12 BACnet object types supported at 192.168.1.50:47808
  Analog-Input, Analog-Output, Analog-Value, Binary-Input,
  Binary-Output, Binary-Value, Device, File, Schedule, ...
```
