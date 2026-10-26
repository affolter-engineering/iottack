# modbus write-register

Writes one or more 16-bit values to Modbus holding registers without
authentication. Two write modes are available:

| Mode | Function code | Flag |
|------|--------------|------|
| Single register | FC06 — Write Single Register | `--value` |
| Multiple registers | FC16 — Write Multiple Registers | `--values` |

Values may be specified in decimal or `0x`-prefixed hexadecimal.

**Warning:** Writing to holding registers can directly modify setpoints,
configuration parameters or device state on industrial equipment.

## Status

| Result | Meaning |
|--------|---------|
| `pass` | Write accepted by the device |
| `fail` | Write rejected, parse error or connection failed |

## Severity classification

| Severity | Condition |
|----------|-----------|
| Critical | Write succeeded (unauthenticated modification of device state) |
| Info | Write failed, invalid value or connection failed |

## Usage

```sh
iottack modbus write-register --host <HOST> --value <VALUE> [OPTIONS]
iottack modbus write-register --host <HOST> --values <V1,V2,...> [OPTIONS]
iottack modbus write-register --serial <DEVICE> --value <VALUE> [OPTIONS]
```

Either `--value` or `--values` must be supplied.

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host <HOST>` | `-H` | *(required or --serial)* | Target hostname or IP for Modbus/TCP |
| `--tcp-port <PORT>` | - | `502` | Modbus/TCP port |
| `--serial <DEVICE>` | `-s` | *(required or --host)* | Serial device for Modbus RTU (e.g., `/dev/ttyUSB0`) |
| `--baud <BAUD>` | - | `9600` | Baud rate for RTU serial |
| `--unit <ID>` | `-u` | `1` | Modbus unit/slave ID (1-247) |
| `--timeout-ms <MS>` | `-t` | `3000` | Timeout in milliseconds |
| `--address <ADDR>` | `-a` | `0` | Target register address (0-65535) |
| `--value <VALUE>` | `-v` | - | Single 16-bit value (decimal or `0xHEX`) for FC06 |
| `--values <V1,V2,...>` | `-V` | - | Comma-separated values for FC16 multi-register write |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

When both `--value` and `--values` are supplied, `--values` (FC16) takes
precedence.

## Examples

Write decimal value 100 to register 40:

```sh
iottack modbus write-register --host 192.168.1.100 \
  --address 40 --value 100
```

Write a hex value:

```sh
iottack modbus write-register --host 192.168.1.100 \
  --address 40 --value 0x0064
```

Write multiple registers starting at address 10:

```sh
iottack modbus write-register --host 192.168.1.100 \
  --address 10 --values 100,200,300,0xFF
```

Write over RTU serial, unit 2:

```sh
iottack modbus write-register --serial /dev/ttyUSB0 --unit 2 \
  --address 0 --value 1
```

## Example output

Single register write (FC06):

```text
Plugin name:    modbus/write-register
Execution time: 0.07 s
Status:         pass

[CRITICAL] Modbus/TCP: wrote register 40 = 0x0064 without authentication (FC06)
  Unit 1: register 40 written with value 100 (0x0064) without authentication.
  Evidence: "address=40 value=100 (0x0064)"
```

Multi-register write (FC16):

```text
Plugin name:    modbus/write-register
Execution time: 0.09 s
Status:         pass

[CRITICAL] Modbus/TCP: wrote 4 registers at address 10 without authentication (FC16)
  Unit 1: 4 consecutive registers written starting at 10.
  Evidence:
    [   10] 0x0064 = 100
    [   11] 0x00C8 = 200
    [   12] 0x012C = 300
    [   13] 0x00FF = 255
```
