# uart - port-scan

Discover serial ports available on this host.

## Usage

```sh
iottack uart port-scan [OPTIONS]
```

## Description

Scans `/dev/` for character devices whose names match known UART naming patterns:

| Prefix | Interface |
|--------|-----------|
| `ttyUSB*` | USB-to-serial (FTDI, CH340, CP210x, …) |
| `ttyACM*` | USB CDC ACM (Arduino, modems) |
| `ttyAMA*` | ARM PL011 UART (Raspberry Pi, …) |
| `ttymxc*` | NXP i.MX SoC UART |
| `ttyO*` | TI OMAP UART |
| `ttyMSM*` | Qualcomm UART |
| `ttySAC*` | Samsung SoC UART |
| `ttyS*` | Native 16550 UART |

Pass `--verify` to attempt opening each discovered port at 9600 baud, confirming
whether it is accessible without elevated privileges.

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--verify` | - | off | Try to open each port to confirm accessibility |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack uart port-scan --verify

Plugin name:    uart/port-scan
Execution time: 12ms
Status:         pass

Serial port available: /dev/ttyUSB0
  /dev/ttyUSB0 is present and can be opened.
```
