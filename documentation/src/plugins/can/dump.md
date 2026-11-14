# can dump

Passively captures CAN frames from a SocketCAN interface and reports traffic
statistics, the most active IDs, and any security-relevant IDs.

## Status

| Result | Meaning |
| ------ | ------- |
| `pass` | Capture completed (even if no frames were received) |
| `fail` | Interface could not be opened |

## Severity classification

| Severity | Condition |
| -------- | --------- |
| High | OBD-II diagnostic IDs present (0x7DF, 0x7E0-0x7EF) |
| Medium | CANopen SDO/NMT/PDO IDs present |
| Low | CAN error frames detected |
| Info | Traffic summary, top IDs, no traffic, or read error |

## Usage

```sh
iottack can dump [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--iface <IFACE>` | `-i` | `can0` | SocketCAN interface name |
| `--duration <SECS>` | `-d` | `10` | Capture duration in seconds |
| `--max-frames <N>` | - | `10000` | Stop early after capturing this many frames |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Description

The plugin opens the specified SocketCAN interface in read-only mode (no frames
are transmitted) and collects frames for the configured duration or until
`--max-frames` is reached.

After capture it reports:

- **Traffic summary**: total frame count, unique ID count, frame rate, error
  frame count.
- **Top 10 IDs by volume**: the most active IDs with their frame count, DLC
  and last observed payload.
- **Notable IDs**: any ID matching a known protocol range (CANopen, OBD-II) is
  reported as a separate finding at an elevated severity.

Error frames (bus-off, bit errors, CRC errors) are counted separately and
reported at **Low** severity because they may indicate a bit-rate mismatch,
wiring fault or active fault injection.

## ID classification

| ID range | Protocol | Severity |
| -------- | -------- | -------- |
| 0x000 | CANopen NMT master | Medium |
| 0x001 - 0x07F | CANopen SYNC/timestamp | Medium |
| 0x080 - 0x0FF | CANopen EMCY (emergency) | Medium |
| 0x100 - 0x4FF | CANopen PDO | Medium |
| 0x580 - 0x5FF | CANopen SDO server response | Medium |
| 0x600 - 0x67F | CANopen SDO client request | Medium |
| 0x700 - 0x77F | CANopen NMT heartbeat | Medium |
| 0x7DF | OBD-II functional broadcast | High |
| 0x7E0 - 0x7E7 | OBD-II physical request to ECU | High |
| 0x7E8 - 0x7EF | OBD-II response from ECU | High |

## Examples

Default 10-second capture on `can0`:

```sh
iottack can dump
```

Longer capture on a custom interface:

```sh
iottack can dump --iface vcan0 --duration 60
```

Save to JSON for further processing:

```sh
iottack can dump --duration 30 --format json --output can-dump.json
```

## Example output

```text
Plugin name:    can/dump
Execution time: 10.01 s
Status:         pass

[INFO] can0: 4823 frame(s), 7 unique ID(s) in 10.0s (482.1 fps)
  Data frames: 4823
  Frame rate: 482.1/s
  Unique IDs: 7
  Error frames: 0

[INFO] Top 7 CAN ID(s) by volume on can0
  181h  count=1621   dlc=8  last=[00 00 00 00 E8 03 00 00]
  280h  count=1203   dlc=8  last=[7F 00 00 00 FF 1F 00 00]
  380h  count=802    dlc=8  last=[00 00 00 00 00 00 00 00]
  701h  count=401    dlc=1  last=[05]
  702h  count=401    dlc=1  last=[05]
  7DFh  count=200    dlc=3  last=[02 01 00]
  7E8h  count=195    dlc=6  last=[06 41 00 BE 1F A8 13]

[MEDIUM] Notable CAN ID 701h: CANopen: NMT heartbeat/node guarding
  ID 701h seen 401 time(s). Last frame: dlc=1 data=[05]

[MEDIUM] Notable CAN ID 702h: CANopen: NMT heartbeat/node guarding
  ID 702h seen 401 time(s). Last frame: dlc=1 data=[05]

[HIGH] Notable CAN ID 7DFh: OBD-II: diagnostic broadcast - exposes vehicle diagnostics (ISO 15765-4)
  ID 7DFh seen 200 time(s). Last frame: dlc=3 data=[02 01 00]

[HIGH] Notable CAN ID 7E8h: OBD-II: diagnostic response from ECU (ISO 15765-4)
  ID 7E8h seen 195 time(s). Last frame: dlc=6 data=[06 41 00 BE 1F A8 13]
```

## Troubleshooting

### Cannot open interface

Verify the interface exists and is up:

```sh
ip link show type can
sudo ip link set can0 up type can bitrate 500000
```

### No frames received

- Confirm the target bus is powered and has active traffic.
- Check the bit rate matches the bus: a mismatch causes all frames to be
  discarded at the hardware level with no error returned to userspace.
- Run `ip -details link show can0` to view the current bitrate and bus state.

### Error frames

If error frames appear, the interface bit rate may not match the bus or there
is a wiring issue (missing termination resistors, ground loop). CAN buses
typically require 120 Ohm termination at each end.
