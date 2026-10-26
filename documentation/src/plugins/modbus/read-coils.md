# modbus read-coils

Reads a block of single-bit values from a Modbus device. Supports both coils
(FC01) and discrete inputs (FC02).

Coils are read/write single-bit values typically representing digital output
states such as relay on/off, valve open/closed or motor running. Discrete
inputs are read-only single-bit values representing digital input states such as
limit switches, door sensors or push buttons.

The finding reports each bit as `ON` or `OFF` and counts how many are active.

## Status

| Result | Meaning |
|--------|---------|
| `pass` | Bits read successfully |
| `fail` | Read failed or connection error |

## Severity classification

| Severity | Condition |
|----------|-----------|
| High | Bits returned (unauthenticated read succeeded) |
| Info | Read failed or connection failed |

## Usage

```sh
iottack modbus read-coils --host <HOST> [OPTIONS]
iottack modbus read-coils --serial <DEVICE> [OPTIONS]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host <HOST>` | `-H` | *(required or --serial)* | Target hostname or IP for Modbus/TCP |
| `--tcp-port <PORT>` | - | `502` | Modbus/TCP port |
| `--serial <DEVICE>` | `-s` | *(required or --host)* | Serial device for Modbus RTU (e.g., `/dev/ttyUSB0`) |
| `--baud <BAUD>` | - | `9600` | Baud rate for RTU serial |
| `--unit <ID>` | `-u` | `1` | Modbus unit/slave ID (1-247) |
| `--timeout-ms <MS>` | `-t` | `3000` | Timeout in milliseconds |
| `--address <ADDR>` | `-a` | `0` | Starting coil address (0-65535) |
| `--count <N>` | `-c` | `16` | Number of bits to read (max. 2000) |
| `--coil-type <TYPE>` | `-T` | `coil` | `coil` (FC01) or `discrete` (FC02) |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

`--count` is capped at 2000, the Modbus protocol maximum per request.

## Examples

Read the first 16 coils:

```sh
iottack modbus read-coils --host 192.168.1.100
```

Read 32 discrete inputs starting at address 0:

```sh
iottack modbus read-coils --host 192.168.1.100 \
  --coil-type discrete --count 32
```

Read over RTU serial:

```sh
iottack modbus read-coils --serial /dev/ttyUSB0 --baud 9600 \
  --address 0 --count 8
```

## Example output

```text
Plugin name:    modbus/read-coils
Execution time: 0.07 s
Status:         pass

[HIGH] Modbus/TCP: unauthenticated read of Coils 0-15
  FC01: unit 1, 16 Coils at address 0. 5/16 bits are ON.
  Evidence:
    [    0] ON
    [    1] OFF
    [    2] ON
    [    3] OFF
    [    4] ON
    [    5] OFF
    [    6] OFF
    [    7] ON
    [    8] OFF
    [    9] OFF
    [   10] ON
    [   11] OFF
    [   12] OFF
    [   13] OFF
    [   14] OFF
    [   15] OFF
```
