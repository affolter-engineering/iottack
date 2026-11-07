# bacnet - event-info

List currently active (non-normal) event states on a BACnet device.

## Usage

```sh
iottack bacnet event-info --host <HOST> [OPTIONS]
```

## Description

Retrieves the object list from the target device and checks the `event-state`
property (property ID 36) on each object. Any object in a non-Normal state is
reported with its object identifier, name, and state.

Equivalent to BACteria `event_info()`.

Objects in Normal state or that do not support the `event-state` property are
silently skipped. The plugin reports:

1. Whether event states were readable at all (always a High finding. Live alarm
   state is exposed without credentials).
2. Any objects with non-Normal states (flagged High or Critical depending on severity).

### Event state values

| Value | Name | Description |
| ----- | ---- | ----------- |
| 0 | Normal | No active event |
| 1 | Fault | Reliability problem detected |
| 2 | Offnormal | Value outside normal range |
| 3 | High-Limit | Value above high limit |
| 4 | Low-Limit | Value below low limit |
| 5 | Life-Safety-Alarm | Life safety alarm condition |

### Severity mapping

| Finding | Severity |
| ------- | -------- |
| Event states not readable | Info |
| Event states readable unauthenticated | High |
| Active Fault or Life-Safety-Alarm events | Critical |
| Other active events (Offnormal, High/Low-Limit) | High |

## Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--host <HOST>` | `-H` | *(required)* | Target BACnet/IP device |
| `--port <PORT>` | `-p` | `47808` | BACnet/IP UDP port |
| `--timeout-ms <MS>` | - | `5000` | Per-request timeout in milliseconds |
| `--max-objects <N>` | - | `128` | Maximum objects to scan for event states |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack bacnet event-info --host 192.168.1.50

Plugin name:    bacnet/event-info
Execution time: 18.40 s
Status:         pass
Date:           2025-10-06 00:00:00 UTC

Event state readable on 12 objects at 192.168.1.50:47808 (10 normal, 2 active)

2 active events on 192.168.1.50:47808
  Analog-Input:3  state=High-Limit  (Chilled-Water-Return-Temp)
  Binary-Input:1  state=Offnormal  (Smoke-Detector-Zone-A)
```
