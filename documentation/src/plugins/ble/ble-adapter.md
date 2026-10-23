# ble adapter

Connects to the BlueZ daemon via D-Bus and enumerates every Bluetooth adapter
registered with the system. For each adapter the following properties are
collected:

- **Address**: MAC address of the adapter
- **Alias**: human-readable name assigned to the adapter
- **Powered**: whether the adapter is currently powered on
- **Discoverable**: whether the adapter broadcasts its presence to nearby devices
- **Pairable**: whether the adapter accepts pairing requests
- **Class**: Bluetooth device class (when available)
- **Modalias**: USB/PCI hardware identifier in `source:vVENDORpPRODUCTdDEVICE` form (when available)

Findings are classified as follows:

| Finding | Severity | Condition |
|---------|----------|-----------|
| Adapter powered and discoverable | Medium | Adapter is on and broadcasting |
| Adapter details (powered, not discoverable) | Low | Adapter is on but not broadcasting |
| Adapter details (not powered) | Info | Adapter is off |
| No adapters found | Info | No Bluetooth hardware detected |
| Bluetooth not available | Info | BlueZ daemon unreachable |

## Requirements

- BlueZ daemon (`bluetoothd`) must be running.
- The D-Bus system bus must be accessible (no special privileges required).

## Usage

```sh
iottack ble adapter
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | - | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack ble adapter

Plugin name:    ble/adapter
Execution time: 0.12 s
Status:         pass

[INFO] 1 Bluetooth adapter(s) found
  Use 'iottack ble scan' to discover nearby BLE devices.

[MEDIUM] hci0 (AA:BB:CC:DD:EE:FF)
  Address:      AA:BB:CC:DD:EE:FF
  Alias:        My Laptop
  Powered:      yes
  Discoverable: yes
  Pairable:     yes
  Class:        0x00000000
  Modalias:     usb:v1D6Bp0246d0540

[MEDIUM] Adapter hci0 is powered and discoverable
  A discoverable Bluetooth adapter can be detected and probed by any
  nearby device. Disable discoverability when not actively pairing to
  reduce the attack surface.
```
