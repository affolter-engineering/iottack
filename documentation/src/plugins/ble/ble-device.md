# ble device

Establishes a GATT connection to the given device address and walks every service
and characteristic. For each characteristic the following are captured:

- **UUID**: 128-bit or short-form GATT UUID
- **Flags**: property flags: `read`, `write`, `write-no-rsp`, `notify`, `indicate`
- **Value**: raw bytes and printable ASCII representation (readable characteristics only)

Findings are classified as follows:

| Finding | Severity | Condition |
|---------|----------|-----------|
| Connected to device | Info | Connection established |
| Service (primary) | Low | Each primary GATT service |
| Service (secondary) | Info | Each secondary GATT service |
| Summary count | Info | Always emitted at end |
| Cannot connect | Info | Device unreachable or out of range |
| No GATT services | Info | Device reported empty profile |
| Bluetooth not available | Info | BlueZ daemon unreachable |

The plugin disconnects from the device after enumeration unless `--no-disconnect`
is given.

## Requirements

- BlueZ daemon (`bluetoothd`) must be running.
- The D-Bus system bus must be accessible (no special privileges required).
- The target device must be advertising and within range.

## Usage

```sh
iottack ble device --address AA:BB:CC:DD:EE:FF
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--address <ADDR>` | `-d` | required | Bluetooth address of the target device |
| `--adapter <NAME>` | `-a` | first available | Adapter to use, e.g. `hci0` |
| `--no-disconnect` | - | off | Leave the device connected after enumeration |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | - | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Examples

Enumerate a device found via `iottack ble scan`:

```sh
iottack ble device --address AA:BB:CC:DD:EE:FF
```

Keep the connection open after the scan:

```sh
iottack ble device --address AA:BB:CC:DD:EE:FF --no-disconnect
```

Save the full profile as JSON:

```sh
iottack ble device --address AA:BB:CC:DD:EE:FF --format json --output device.json
```

Example output:

```sh
$ iottack ble device --address DD:EE:FF:44:55:66

Plugin name:    ble/device
Execution time: 3.21 s
Status:         pass

[INFO] Connected to My Sensor
  Address: DD:EE:FF:44:55:66
  Name:    My Sensor
  Paired:  no
  RSSI:    -58 dBm

[LOW] Service 0000180a-0000-1000-8000-00805f9b34fb
  UUID:    0000180a-0000-1000-8000-00805f9b34fb
  Primary: yes
  Characteristics: 3
  00002a29-0000-1000-8000-00805f9b34fb [read] value=41 63 6d 65 (Acme)
  00002a24-0000-1000-8000-00805f9b34fb [read] value=53 65 6e 73 6f 72 (Sensor)
  00002a26-0000-1000-8000-00805f9b34fb [read] value=31 2e 30 (1.0)

[LOW] Service 0000181a-0000-1000-8000-00805f9b34fb
  UUID:    0000181a-0000-1000-8000-00805f9b34fb
  Primary: yes
  Characteristics: 2
  00002a6e-0000-1000-8000-00805f9b34fb [read, notify] value=0d 01 (...)
  00002a6f-0000-1000-8000-00805f9b34fb [read, notify] value=64 00 (d.)

[INFO] 2 GATT service(s) enumerated
  Device DD:EE:FF:44:55:66 on adapter hci0.
```
