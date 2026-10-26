# modbus enumerate

Scans a configurable address range across all four Modbus data types to discover
which addresses a device will serve without error:

| Data type | Function code | Default scan |
|-----------|--------------|-------------|
| Holding registers | FC03 | yes |
| Input registers | FC04 | yes |
| Coils | FC01 | yes |
| Discrete inputs | FC02 | yes |

Addresses are read in blocks of 125 (the Modbus maximum per request). The scan
reports each contiguous accessible range and the total number of readable
locations. This reveals the full attack surface available to an unauthenticated
attacker.

## Status

| Result | Meaning |
|--------|---------|
| `pass` | At least one accessible address found |
| `fail` | No accessible addresses, or connection failed |

## Severity classification

| Severity | Condition |
|----------|-----------|
| High | More than 100 accessible addresses of a given type |
| High | Summary finding when any data is found |
| Medium | 1-100 accessible addresses of a given type |
| Info | No accessible addresses for a data type |
| Info | No data found at all, or connection failed |

## Usage

```sh
iottack modbus enumerate --host <HOST> [OPTIONS]
iottack modbus enumerate --serial <DEVICE> [OPTIONS]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host <HOST>` | `-H` | *(required or --serial)* | Target hostname or IP for Modbus/TCP |
| `--tcp-port <PORT>` | - | `502` | Modbus/TCP port |
| `--serial <DEVICE>` | `-s` | *(required or --host)* | Serial device for Modbus RTU (e.g., `/dev/ttyUSB0`) |
| `--baud <BAUD>` | - | `9600` | Baud rate for RTU serial |
| `--unit <ID>` | `-u` | `1` | Modbus unit/slave ID (1-247) |
| `--timeout-ms <MS>` | `-t` | `3000` | Per-block timeout (lower values speed up the scan) |
| `--start-addr <ADDR>` | `-S` | `0` | First address to scan |
| `--end-addr <ADDR>` | `-E` | `999` | Last address to scan (inclusive) |
| `--no-holding` | - | off | Skip holding register scan (FC03) |
| `--no-input` | - | off | Skip input register scan (FC04) |
| `--no-coils` | - | off | Skip coil scan (FC01) |
| `--no-discrete` | - | off | Skip discrete input scan (FC02) |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Performance notes

Each block read is one round-trip. For the default range (0-999) with all four
data types, the scan issues approximately 36 requests (⌈1000/125⌉ * 4 = 32-36).
Reduce `--timeout-ms` (e.g., `500`) for faster scans when the network is
reliable.

## Examples

Full default scan over TCP:

```sh
iottack modbus enumerate --host 192.168.1.100
```

Scan a wider range with a shorter timeout:

```sh
iottack modbus enumerate --host 192.168.1.100 \
  --start-addr 0 --end-addr 9999 --timeout-ms 500
```

Only scan holding registers and coils:

```sh
iottack modbus enumerate --host 192.168.1.100 \
  --no-input --no-discrete
```

RTU serial, unit 5:

```sh
iottack modbus enumerate --serial /dev/ttyUSB0 --unit 5
```

## Example output

```text
Plugin name:    modbus/enumerate
Execution time: 3.21 s
Status:         pass

[HIGH] Modbus/TCP: 875 accessible Holding Registers (FC03) in range 0-999
  Unit 1: 875 addresses in 2 contiguous block(s) are readable without
  authentication.
  Evidence:
    Accessible ranges: 0-874, 900-999
    Total accessible: 875

[MEDIUM] Modbus/TCP: 16 accessible Coils (FC01) in range 0-999
  Unit 1: 16 addresses in 1 contiguous block(s) are readable without
  authentication.
  Evidence:
    Accessible ranges: 0-15
    Total accessible: 16

[INFO] Modbus/TCP: no accessible Input Registers (FC04) in range 0-999
[INFO] Modbus/TCP: no accessible Discrete Inputs (FC02) in range 0-999

[HIGH] Modbus/TCP: 891 total accessible data points on unit 1
  Enumeration of addresses 0-999 found 891 readable locations across all
  scanned data types.
    Holding Registers (FC03): 875 accessible (2 range(s): 0-874, 900-999)
    Input Registers    (FC04): no accessible addresses
    Coils              (FC01): 16 accessible (1 range(s): 0-15)
    Discrete Inputs    (FC02): no accessible addresses
```
