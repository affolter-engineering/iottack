# i2c read

Read one or more bytes from a specific I2C device register via an FTDI MPSSE
adapter.

## Requirements

An FTDI MPSSE adapter (FT232H, FT2232H or FT4232H) connected to the I2C bus.
See [FTDI adapter wiring](../hardware/ftdi.md#i2c) for the exact pin connections
and the required udev rule.

## Usage

```sh
iottack i2c read --address <HEX> [OPTIONS]
```

## Description

Performs a single I2C transaction to the target address:

- **Plain read** (`--address` only): issues a raw read of `--length` bytes.
- **Write-then-read** (`--address` + `--register`): writes the register byte
  first (repeated-START), then reads back `--length` bytes. This is the standard
  way to read a sensor register.

Raw bytes are reported as hex, decimal, and printable ASCII.

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--address <HEX>` | `-a` | _(required)_ | 7-bit I2C target address in hex, e.g., `68` or `0x68` |
| `--register <HEX>` | `-r` | _(none)_ | Register/command byte to write before reading, e.g., `00` or `0x00` |
| `--length <N>` | `-n` | `1` | Number of bytes to read |
| `--channel <CHANNEL>` | `-c` | `A` | FTDI channel to use, must be A or B (MPSSE-capable) |
| `--vid <HEX>` | - | `0403` | USB vendor ID in hex |
| `--pid <HEX>` | - | `6011` | USB product ID in hex (6001=FT232R, 6010=FT2232H, 6011=FT4232H, 6014=FT232H) |
| `--clock-hz <HZ>` | - | `100000` | I2C clock frequency in Hz |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Examples

Read 1 byte from the WHO_AM_I register (0x75) of an MPU-6050 at address 0x68:

```sh
$ iottack i2c read --address 68 --register 75

Plugin name:    i2c/read
Execution time: 18 ms
Status:         pass

[INFO] 1 byte(s) from I2C 0x68 reg 0x75
  Device 0x68 reg 0x75 on channel A at 100000 Hz
  HEX:     68
  Decimal: 104
  ASCII:   h
  Evidence: addr=0x68 reg=0x75 bytes=[68]
```

Read 6 raw bytes (accelerometer X/Y/Z) from register 0x3b:

```sh
$ iottack i2c read --address 68 --register 3b --length 6

[INFO] 6 byte(s) from I2C 0x68 reg 0x3b
  Device 0x68 reg 0x3b on channel A at 100000 Hz
  HEX:     01 2c ff e4 00 08
  Decimal: 1 44 255 228 0 8
  ASCII:   ....
```

## Troubleshooting

### NACK/read failed

- Confirm the address is correct (use `iottack i2c scan` to discover devices).
- Check the register byte is valid for the target device.
- Verify pull-up resistors (4.7 kOhm) are on SCL and SDA.

### FTDI device not found

- Check `lsusb` shows the adapter (`0403:6011` or similar).
- Apply the [udev rule](../hardware/ftdi.md#linux-setup-udev) and reconnect.

### MPSSE initialization failed

- Channels C and D on the FT4232H do not support MPSSE. Use `--channel A` or
  `--channel B`.
