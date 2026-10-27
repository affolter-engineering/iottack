# ghostesp device

[GhostESP](https://ghostesp.net/) is an ESP32-based wireless security
tool capable of Bluetooth and Wi-Fi scanning, deauthentication and
credential harvesting. Its presence on a network or in a facility
is itself a security finding.

## Requirements

An ESP32 that runs [GhostESP](https://ghostesp.net/). Keep an eye the
type of ESP32 that you are going to use, not all variants have support
for Bluetooth.

## Plugin description

Opens a serial connection to a GhostESP device, sends a newline to wake
the interactive shell and waits for the `ghost>` prompt. Once the prompt
is confirmed, the plugin runs two commands:

- **`chipinfo`**: retrieves ESP32 chip identity, revision, and flash size.
- **`devices`**: lists enabled hardware peripherals (GPS, RGB LED, SD card,
  etc.) and their configuration.

Findings are classified as follows:

| Finding | Severity | Condition |
|---------|----------|-----------|
| GhostESP device detected | High | `ghost>` prompt found on port |
| GhostESP chip information | Info | `chipinfo` returned output |
| Enabled peripherals | Info | `devices` returned peripheral list |
| Prompt not found / port error | Info | Device absent or wrong firmware |

## Usage

```sh
iottack ghostesp device --port <PORT> [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port <PORT>` | `-p` | *(required)* | Serial port, e.g., `/dev/ttyACM0` |
| `--baud-rate <BAUD>` | `-b` | `115200` | Serial baud rate |
| `--timeout-ms <MS>` | `-t` | `5000` | Per-command response timeout in ms |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack ghostesp device --port /dev/ttyACM1

Plugin name:    ghostesp/device
Execution time: 1.23 s
Status:         pass

[INFO] GhostESP chip information
  ESP32-D0WD-V3 rev 3, 4 MB flash, single core

[INFO] 3 enabled peripheral(s) on GhostESP device
  Enabled devices:
    GPS: default pin [idle]
    RGB: data GPIO0, 0 LEDs
    SD Card: SPI (CS GPIO4) [not mounted]
```
