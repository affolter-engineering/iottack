# uart - baud-scan

Probe common UART baud rates to identify the active configuration.

## Usage

```sh
iottack uart baud-scan --port <PATH> [OPTIONS]
```

## Description

Opens the target serial port at each standard baud rate in sequence, sends a
stimulus (`\r\n\r\nAT\r\n`), and checks whether the response contains
printable ASCII. Reports all baud rates that produce readable output.

Baud rates probed (in order):
115200, 57600, 38400, 19200, 9600, 4800, 2400, 1200, 230400, 460800, 921600, 300

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port <PATH>` | `-p` | *(required)* | Serial port device, e.g. `/dev/ttyUSB0` |
| `--timeout-ms <MS>` | - | `500` | Read timeout per baud rate in milliseconds |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack uart baud-scan --port /dev/ttyUSB0

Plugin name:    uart/baud-scan
Execution time: 6.23 s
Status:         pass

UART active at 115200 baud
  Port /dev/ttyUSB0 responded with readable ASCII at 115200 baud.
  Evidence: "OpenWrt login: "
```
