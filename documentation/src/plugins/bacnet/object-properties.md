# bacnet - object-properties

Show all readable properties of a specific BACnet object.

## Usage

```sh
iottack bacnet object-properties --host <HOST> --object <TYPE:INSTANCE> [OPTIONS]
```

## Description

Reads all standard properties of the named BACnet object on the target device.
The object is specified as `TYPE:INSTANCE` where TYPE is the BACnet object type
and INSTANCE is the object instance number.

Common abbreviations are accepted for object types. The plugin tries every
standard property that may apply to the object and reports what is readable
without credentials.

### Object type abbreviations

| Full name | Abbreviation |
| --------- | ------------ |
| `analogInput` | `ai` |
| `analogOutput` | `ao` |
| `analogValue` | `av` |
| `binaryInput` | `bi` |
| `binaryOutput` | `bo` |
| `binaryValue` | `bv` |
| `multiStateInput` | `msi` |
| `multiStateOutput` | `mso` |
| `multiStateValue` | `msv` |
| `device` | `dev` |
| `eventEnrollment` | `ee` |
| `notificationClass` | `nc` |
| `trendLog` | `tl` |
| `trendLogMultiple` | `tlm` |
| `eventLog` | `el` |
| `lifeSafetyPoint` | `lsp` |
| `lifeSafetyZone` | `lsz` |
| `pulseConverter` | `pc` |
| `loadControl` | `lc` |
| `structuredView` | `sv` |
| `accessDoor` | `ad` |
| `accessZone` | `az` |
| `accessUser` | `au` |
| `accessRights` | `ar` |
| `accessCredential` | `ac` |
| `accessPoint` | `ap` |
| `networkPort` | `np` |

Hyphens, underscores, and spaces in type names are ignored. Types without
an abbreviation (`calendar`, `command`, `file`, `group`, `loop`, `program`,
`schedule`, `averaging`, `accumulator`) must be spelled out.

### Properties attempted

Object Identifier, Object Name, Object Type, Description, Present Value,
Status Flags, Event State, Out of Service, Reliability, Units, Min/Max
Present Value, Resolution, COV Increment, High/Low Limit, Deadband, Limit
Enable, Event Enable, Acked Transitions, Notify Type, Number of States,
State Text, Active Text, Inactive Text, Polarity, Priority Array,
Relinquish Default, Profile Name, Property List.

### Severity mapping

| Finding | Severity |
| ------- | -------- |
| No properties readable | Info |
| Properties readable unauthenticated | High |

## Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--host <HOST>` | `-H` | *(required)* | Target BACnet/IP device |
| `--object <OBJ>` | `-O` | *(required)* | Object to inspect, e.g., `analogInput:1` or `ai:1` |
| `--port <PORT>` | `-p` | `47808` | BACnet/IP UDP port |
| `--timeout-ms <MS>` | - | `5000` | Per-request timeout in ms |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack bacnet object-properties --host 192.168.1.50 --object analogInput:1

Plugin name:    bacnet/object-properties
Execution time: 4.12 s
Status:         pass
Date:           2026-10-18 00:00:00 UTC

9 properties readable for AnalogInput:1 at 192.168.1.50:47808
  Object Identifier: AnalogInput:1
  Object Name: Supply-Air-Temp
  Description: Supply air temperature sensor, AHU-01
  Present Value: 22.1500
  Status Flags: false
  Event State: 0
  Out of Service: false
  Units: 62
  High Limit: 35.0000
  Low Limit: 0.0000
```
