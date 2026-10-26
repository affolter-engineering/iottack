# modbus read-registers

Reads a contiguous block of 16-bit registers from a Modbus device. Supports
both holding registers (FC03) and input registers (FC04).

Holding registers are general-purpose read/write 16-bit values typically used
for setpoints, configuration, and counters. Input registers are read-only 16-bit
values typically representing analog measurements and sensor readings.

The finding reports all register values in hex and decimal and counts how many
hold non-zero values.

## Status

| Result | Meaning |
|--------|---------|
| `pass` | Registers read successfully |
| `fail` | Read failed or connection error |

## Severity classification

| Severity | Condition |
|----------|-----------|
| High | Registers returned (unauthenticated read succeeded) |
| Info | Read failed or connection failed |

## Usage

```sh
iottack modbus read-registers --host <HOST> [OPTIONS]
iottack modbus read-registers --serial <DEVICE> [OPTIONS]
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
| `--address <ADDR>` | `-a` | `0` | Starting register address (0-65535) |
| `--count <N>` | `-c` | `10` | Number of registers to read (max. 125) |
| `--register-type <TYPE>` | `-T` | `holding` | `holding` (FC03) or `input` (FC04) |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

`--count` is capped at 125, the Modbus protocol maximum per request.

## Examples

Read the first 10 holding registers:

```sh
iottack modbus read-registers --host 192.168.1.100
```

Read 20 input registers starting at address 100:

```sh
iottack modbus read-registers --host 192.168.1.100 \
  --register-type input --address 100 --count 20
```

Read over RTU serial, unit ID 3:

```sh
iottack modbus read-registers --serial /dev/ttyUSB0 --baud 19200 \
  --unit 3 --address 0 --count 10
```

## Example output

```text
Plugin name:    modbus/read-registers
Execution time: 0.08 s
Status:         pass

[HIGH] Modbus/TCP: unauthenticated read of Holding registers 0-9
  FC03: unit 1, 10 Holding registers at address 0.
  7/10 registers hold non-zero values.
  Evidence:
    [    0] 0x0064 =    100
    [    1] 0x01F4 =    500
    [    2] 0x0000 =      0
    [    3] 0x03E8 =   1000
    [    4] 0x0000 =      0
    [    5] 0x000A =     10
    [    6] 0x0032 =     50
    [    7] 0x0000 =      0
    [    8] 0x00C8 =    200
    [    9] 0x0001 =      1
```
