# can scan

Passively listens on a SocketCAN interface and enumerates every unique CAN ID
that transmits a data frame during the capture window. Each ID is reported as a
separate finding.

## Status

| Result | Meaning |
| ------ | ------- |
| `pass` | Scan completed (even if no IDs were observed) |
| `fail` | Interface could not be opened |

## Severity classification

| Severity | Condition |
| -------- | --------- |
| High | OBD-II diagnostic ID observed (0x7DF, 0x7E0-0x7EF) |
| Medium | CANopen protocol ID observed (SDO, PDO, NMT ranges) |
| Info | General ID, extended (EFF) frame or no traffic |

## Usage

```sh
iottack can scan [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--iface <IFACE>` | `-i` | `can0` | SocketCAN interface name |
| `--duration <SECS>` | `-d` | `5` | Scan duration in seconds |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Description

For each unique CAN ID observed the plugin reports:

- **ID** in HEX with the frame format (SFF or EFF)
- **Frame count** and **rate** (frames per second) over the scan window
- **DLC** (data length code, 0-8 bytes)
- **Last payload** as a HEX byte string
- A **protocol hint** when the ID falls in a known range

Extended 29-bit (EFF) frames are listed at **Info** severity without protocol
classification. J1939 PGN decoding is not performed.

IDs are reported in ascending order for consistent output across runs.

## Examples

Default 5-second scan on `can0`:

```sh
iottack can scan
```

Longer scan on a custom interface:

```sh
iottack can scan --iface vcan0 --duration 30
```

## Example output

```text
Plugin name:    can/scan
Execution time: 5.01 s
Status:         pass

[INFO] 5 unique CAN ID(s) active on can0 over 5.0s
  Discovered 5 unique CAN IDs transmitting data frames.

[INFO] CAN ID 181h
  Frames: 500   Rate: 100.0/s  DLC: 8  Last: [00 00 00 00 E8 03 00 00]

[INFO] CAN ID 280h
  Frames: 500   Rate: 100.0/s  DLC: 8  Last: [7F 00 00 00 FF 1F 00 00]

[MEDIUM] CAN ID 701h [CANopen: NMT heartbeat/node guarding]
  Frames: 50    Rate: 10.0/s   DLC: 1  Last: [05]

[HIGH] CAN ID 7DFh [OBD-II: diagnostic broadcast - exposes vehicle diagnostics (ISO 15765-4)]
  Frames: 25    Rate: 5.0/s    DLC: 3  Last: [02 01 00]

[HIGH] CAN ID 7E8h [OBD-II: diagnostic response from ECU (ISO 15765-4)]
  Frames: 24    Rate: 4.8/s    DLC: 6  Last: [06 41 00 BE 1F A8 13]
```

## Comparison with `can dump`

Both `can scan` and `can dump` are passive. The difference is in output focus:

| Plugin | Focus |
| ------ | ----- |
| `can dump` | Traffic statistics: total rate, top IDs, error frames |
| `can scan` | Per-ID enumeration: one finding per unique ID with rate and payload |

Use `can scan` when building an inventory of active nodes. Use `can dump` when
diagnosing traffic patterns or looking for anomalies.
