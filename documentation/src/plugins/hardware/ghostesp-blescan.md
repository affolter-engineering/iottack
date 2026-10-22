# ghostesp blescan

Starts a BLE scan on a GhostESP device in one of eight modes, collects
observations for a configurable duration, stops the scan and reports
everything as structured findings.

## Requirements

An ESP32 that runs [GhostESP](https://ghostesp.net/). Not all ESP32 variants
support Bluetooth — check your board's specifications before use.

## Scan modes

| Mode | GhostESP flag | Description |
|------|---------------|-------------|
| `flipper` | `-f` | Detect Flipper Zero devices nearby |
| `spam-detector` | `-ds` | Detect active BLE advertisement spam |
| `airtag` | `-a` | Scan for Apple AirTags |
| `advertiser` | `-adv` | Parsed BLE advertiser scan (default) |
| `oui` | `-oui <prefix>` | Filter advertisers by OUI prefix |
| `vendor` | `-vendor <name>` | Filter advertisers by vendor name |
| `gatt` | `-g` | Scan connectable GATT devices |
| `raw` | `-r` | Raw BLE packet capture |

## Plugin description

Opens a serial connection to a GhostESP device, waits for the `ghost>` prompt,
then starts a BLE scan in the chosen mode. After the configured duration the
scan is stopped with `blescan -s` and all observed output is reported as
findings.

Findings are classified as follows:

| Finding | Severity | Condition |
|---------|----------|-----------|
| N BLE observations | Info | One or more devices detected |
| No BLE devices detected | Info | Scan returned no output |
| Prompt not found / port error | Info | Device absent or wrong firmware |

## Usage

```sh
iottack ghostesp blescan --port <PORT> [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port <PORT>` | `-p` | *(required)* | Serial port, e.g. `/dev/ttyACM0` |
| `--mode <MODE>` | `-m` | `advertiser` | Scan mode (see table above) |
| `--filter <VALUE>` | - | - | OUI prefix or vendor name (required for `oui`/`vendor` modes) |
| `--duration <SECS>` | `-d` | `10` | Scan duration in seconds |
| `--baud-rate <BAUD>` | `-b` | `115200` | Serial baud rate |
| `--timeout-ms <MS>` | `-t` | `5000` | Prompt wait timeout in ms |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | - | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Examples

```sh
$ iottack ghostesp blescan --port /dev/ttyACM1 --mode advertiser --duration 15

Plugin name:    ghostesp/blescan
Execution time: 15.42 s
Status:         pass

[INFO] 4 BLE observation(s) — advertiser mode
  [ADV] AA:BB:CC:11:22:33 (Apple, Inc.) RSSI: -62 dBm
  [ADV] DD:EE:FF:44:55:66 (Samsung Electronics) RSSI: -74 dBm
  [ADV] 11:22:33:AA:BB:CC (Unknown) RSSI: -81 dBm
  [ADV] 44:55:66:DD:EE:FF (Google) RSSI: -69 dBm
```

```sh
$ iottack ghostesp blescan --port /dev/ttyACM1 --mode flipper --duration 10

Plugin name:    ghostesp/blescan
Execution time: 10.38 s
Status:         pass

[INFO] 1 BLE observation(s) — flipper mode
  [FLIPPER] AA:BB:CC:DD:EE:FF "xXx_FlipperZero_xXx" RSSI: -55 dBm
```

```sh
$ iottack ghostesp blescan --port /dev/ttyACM1 --mode vendor --filter Apple --duration 20

Plugin name:    ghostesp/blescan
Execution time: 20.15 s
Status:         pass

[INFO] 2 BLE observation(s) — vendor mode
  [ADV] AA:BB:CC:11:22:33 (Apple, Inc.) RSSI: -62 dBm
  [ADV] 44:55:66:DD:EE:FF (Apple, Inc.) RSSI: -70 dBm
```
