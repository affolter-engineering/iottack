# bacnet - object-list

Enumerate all BACnet objects on a device and read their present values unauthenticated.

## Usage

```sh
iottack bacnet object-list --host <HOST> [OPTIONS]
```

## Description

Implements the `list_objects` and `list_objects_info` recon operations from
[BACteria](https://github.com/cyber-defence-campus/BACteria).

1. **Object list**: reads the object-list property (prop 76) from the Device
   object to obtain every BACnet object instantiated on the device.
2. **Object names**: reads the object-name property (prop 77) for each object.
3. **Present values**: for data-point types (Analog-Input/Output/Value,
   Binary-Input/Output/Value, Multi-State-Input/Output/Value) the present-value
   property (prop 85) is read, exposing live sensor and actuator readings.

**Note:** Very large object lists (> ~200 objects) may exceed the 1024-byte
APDU limit. Use `--max-objects` to cap enumeration and a dedicated BACnet
client for exhaustive scans.

### Severity mapping

| Finding | Severity |
| ------- | -------- |
| Object list not readable | Info |
| Object list accessible unauthenticated | High |
| Data-point present values readable | Critical |

## Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--host <HOST>` | `-H` | *(required)* | Target BACnet/IP device |
| `--port <PORT>` | `-p` | `47808` | BACnet/IP UDP port |
| `--timeout-ms <MS>` | - | `5000` | Per-request timeout in MS |
| `--max-objects <N>` | - | `64` | Maximum number of objects to enumerate |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack bacnet object-list --host 192.168.1.50

Plugin name:    bacnet/object-list
Execution time: 12.40 s
Status:         pass
Date:           2026-10-18 00:00:00 UTC

BACnet object list readable at 192.168.1.50:47808: 18 objects
  Device:0  name=HVAC-Controller
  Analog-Input:0  name=Supply-Air-Temp  present-value=22.1500
  Analog-Input:1  name=Return-Air-Temp  present-value=19.3200
  Binary-Output:0  name=Fan-Enable  present-value=1
  ...

3 process data-points readable unauthenticated at 192.168.1.50:47808
  Analog-Input:0 = 22.1500 (Supply-Air-Temp)
  Analog-Input:1 = 19.3200 (Return-Air-Temp)
  Binary-Output:0 = 1 (Fan-Enable)
```
