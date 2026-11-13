# can send

Constructs and transmits one or more CAN data frames via a SocketCAN interface.

## Status

| Result | Meaning |
|--------|---------|
| `pass` | At least one frame was sent successfully |
| `fail` | Interface could not be opened, or all writes failed |

## Usage

```sh
iottack can send --id <HEX> [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--id <HEX>` | - | *(required)* | CAN ID in HEX without `0x` prefix (e.g., `7DF`). IDs greater than `0x7FF` are automatically treated as 29-bit EFF |
| `--data <HEX>` | - | *(empty)* | Payload bytes in HEX, any separator accepted (e.g., `"02 01 00"`, `"020100"`, `"02:01:00"`). Maximum 8 bytes |
| `--iface <IFACE>` | `-i` | `can0` | SocketCAN interface name |
| `--extended` | `-e` | off | Force 29-bit extended frame format (EFF) even for IDs <= `0x7FF` |
| `--count <N>` | `-n` | `1` | Number of frames to send |
| `--interval-ms <MS>` | - | `0` | Delay between consecutive frames in milliseconds |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Frame format selection

The ID determines the frame format automatically:

| Condition | Format |
| --------- | ------ |
| `--id` <= `0x7FF` | SFF (11-bit), unless `--extended` is set |
| `--id` > `0x7FF` | EFF (29-bit) always |
| `--extended` flag | EFF (29-bit) regardless of ID value |

## Data encoding

The `--data` argument accepts HEX bytes in any common notation. All non-HEX
characters (spaces, colons, commas) are stripped before parsing, so the
following are equivalent:

```sh
--data "02 01 00"
--data "020100"
--data "02:01:00"
--data "02,01,00"
```

A data length of zero (no `--data`) sends a zero-length data frame (DLC=0),
which is valid on CAN and commonly used as a keep-alive or ping.

## Examples

OBD-II functional broadcast. Query supported PIDs:

```sh
iottack can send --id 7DF --data "02 01 00"
```

CANopen NMT command. Reset all nodes (use with caution):

```sh
iottack can send --id 000 --data "81 00"
```

Send a J1939 extended frame:

```sh
iottack can send --id 18DB33F1 --data "02 01 00"
```

Repeat a frame 10 times with 100 ms between sends:

```sh
iottack can send --id 123 --data "DEADBEEF" --count 10 --interval-ms 100
```

Send a zero-length frame on a virtual interface:

```sh
iottack can send --iface vcan0 --id 7FF
```

## Example output

```text
Plugin name:    can/send
Execution time: 0 ms
Status:         pass

[INFO] Sent 1/1 frame(s): 7DFh [02 01 00]
  Interface : can0
  ID        : 7DFh (SFF/11-bit)
  Payload   : [02 01 00] (3 byte(s))
  Sent      : 1  Errors: 0
  Evidence: "iface=can0 id=7DFh fmt=SFF/11-bit data=[02 01 00] sent=1 errors=0"
```

## Notes

- CAN classic frames carry a maximum of 8 bytes. CAN FD (Flexible Data-rate) is
  not currently supported.
- Sending frames to a live CAN bus can disrupt operation. Take care when testing
  on production systems.
- NMT reset commands (ID `0x000`, data `0x81 0x00`) will restart all CANopen
  nodes on the bus.
