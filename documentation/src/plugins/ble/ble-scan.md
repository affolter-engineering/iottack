# ble scan

Starts an active BLE discovery session on the selected adapter and listens for
advertising packets for the configured duration. Each newly seen device address
triggers a finding that captures:

- **Address**: Bluetooth MAC address of the device
- **Name**: advertised device name (falls back to alias if name is absent)
- **Connected**: whether the device currently has an active connection
- **Paired**: whether the device is already paired with the host
- **RSSI**: received signal strength in dBm (when reported by the adapter)
- **TX Power**: transmit power level in dBm (when included in the advertisement)
- **UUIDs**: advertised GATT service UUIDs

Findings are classified as follows:

| Finding | Severity | Condition |
|---------|----------|-----------|
| Device details | Medium | Device is connected or paired |
| Device details | Info | Unknown / unrecognised device |
| Summary count | Info | Always emitted at end of scan |
| No devices found | Info | Scan completed with zero results |
| Bluetooth not available | Info | BlueZ daemon unreachable |
| No adapters found | Info | No Bluetooth hardware detected |
| Cannot start scan | Info | Adapter powered off or busy |

## Requirements

- BlueZ daemon (`bluetoothd`) must be running.
- The D-Bus system bus must be accessible (no special privileges required).
- At least one powered Bluetooth adapter must be present on the host.

## Usage

```sh
iottack ble scan
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--timeout <SECS>` | `-t` | `10` | Scan duration in seconds |
| `--adapter <NAME>` | `-a` | first available | Adapter to use, e.g. `hci0` |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | - | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Examples

Scan with the default 10-second window:

```sh
iottack ble scan
```

Scan for 30 seconds using a specific adapter:

```sh
iottack ble scan --timeout 30 --adapter hci1
```

Save results as JSON:

```sh
iottack ble scan --timeout 20 --format json --output results.json
```

Example output:

```sh
$ iottack ble scan --timeout 5

Plugin name:    ble/scan
Execution time: 5.03 s
Status:         pass

[INFO] AA:BB:CC:11:22:33
  Address:   AA:BB:CC:11:22:33
  Name:      n/a
  Connected: no
  Paired:    no
  RSSI:      -74 dBm

[MEDIUM] My Phone (DD:EE:FF:44:55:66)
  Address:   DD:EE:FF:44:55:66
  Name:      My Phone
  Connected: yes
  Paired:    yes
  RSSI:      -52 dBm
  TX Power:  4 dBm
  UUIDs:     0000110b-0000-1000-8000-00805f9b34fb, 0000110e-0000-1000-8000-00805f9b34fb

[INFO] 2 BLE device(s) discovered
  Scan completed on adapter hci0 after 5 second(s).
```

## Remediation

Devices appearing as **Medium** are already connected or paired with the host.
Unpair devices that are no longer in use:

```sh
bluetoothctl remove <ADDRESS>
```

For devices with sensitive service UUIDs, verify the device is authorised before
allowing further interaction.
