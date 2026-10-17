# uart - shell-detect

Detect an interactive shell or login prompt on a UART interface.

## Usage

```sh
iottack uart shell-detect --port <PATH> [OPTIONS]
```

## Description

Connects at the configured baud rate, sends newlines to wake the device, and
inspects the response for shell and login prompt patterns. Makes multiple
attempts to handle devices that need time to produce output.

Findings are classified as follows:

| Finding | Severity | Condition |
|---------|----------|-----------|
| Unauthenticated root shell | Critical | `# ` or `root@` present in output |
| Login prompt exposed | High | `login:`, `Password:`, etc. present |
| Interactive prompt | Medium | Other shell patterns matched |
| Boot messages | Info | Boot-time keywords detected |
| No response | - | No output after all attempts |

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port <PATH>` | `-p` | *(required)* | Serial port device, e.g. `/dev/ttyUSB0` |
| `--baud-rate <BAUD>` | `-b` | `115200` | Baud rate to connect at |
| `--attempts <N>` | - | `3` | Number of stimulus attempts |
| `--timeout-ms <MS>` | - | `500` | Read timeout per attempt in milliseconds |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack uart shell-detect --port /dev/ttyUSB0 --baud-rate 115200

Plugin name:    uart/shell-detect
Execution time: 1.52 s
Status:         pass

Login prompt exposed on UART
  A login prompt is accessible on /dev/ttyUSB0 at 115200 baud.
  Default or weak credentials should be tested.
  Evidence: "OpenWrt login: "
```
