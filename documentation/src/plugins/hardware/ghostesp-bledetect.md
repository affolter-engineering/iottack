# ghostesp bledetect

Detects BLE trackers, skimmers and beacons near a GhostESP device by matching
advertisement signatures against a built-in database. Each discovered device
is reported as a finding with severity scaled by type.

## Requirements

An ESP32 that runs [GhostESP](https://ghostesp.net/). Not all ESP32 variants
support Bluetooth — check your board's specifications before use.

## Plugin description

Opens a serial connection to a GhostESP device, waits for the `ghost>` prompt,
then starts `bledetect` to scan for known device signatures in the background.
After the configured duration the plugin queries:

- **`bledetect -l`**: structured list of discovered devices (type, name/MAC, RSSI)
- **`bledetect -i`**: scan state and device count

The scan is then stopped with `bledetect -s` and findings are reported.

Findings are classified as follows:

| Finding | Severity | Condition |
|---------|----------|-----------|
| Skimmer detected | High | Device type contains "skimmer" |
| Tracker / AirTag detected | Medium | Device type contains "tracker", "airtag" or "tile" |
| Beacon detected | Low | Device type contains "beacon" |
| Other BLE device | Info | Any other signature match |
| No devices detected | Info | Scan returned empty list |
| BLE detect scan state | Info | Output of `bledetect -i` |
| Prompt not found / port error | Info | Device absent or wrong firmware |

## Usage

```sh
iottack ghostesp bledetect --port <PORT> [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port <PORT>` | `-p` | *(required)* | Serial port, e.g. `/dev/ttyACM0` |
| `--duration <SECS>` | `-d` | `15` | Scan duration in seconds before querying results |
| `--baud-rate <BAUD>` | `-b` | `115200` | Serial baud rate |
| `--timeout-ms <MS>` | `-t` | `5000` | Prompt wait timeout in ms |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | - | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack ghostesp bledetect --port /dev/ttyACM1 --duration 30

Plugin name:    ghostesp/bledetect
Execution time: 30.58 s
Status:         pass

[INFO] BLE detect scan state
  Scan: running | Devices found: 3 | Tracking: none

[HIGH] Suspicious BLE device detected: [1] Skimmer AA:BB:CC:11:22:33 RSSI: -68 dBm
  [1] Skimmer AA:BB:CC:11:22:33 RSSI: -68 dBm

[MEDIUM] Suspicious BLE device detected: [2] AirTag "John's bag" DD:EE:FF:44:55:66 RSSI: -72 dBm
  [2] AirTag "John's bag" DD:EE:FF:44:55:66 RSSI: -72 dBm

[LOW] BLE device detected: [3] Beacon 11:22:33:AA:BB:CC RSSI: -80 dBm
  [3] Beacon 11:22:33:AA:BB:CC RSSI: -80 dBm
```
