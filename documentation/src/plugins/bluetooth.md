# Bluetooth

Bluetooth is a short-range wireless technology found in a wide range of IoT
devices like consumer electronics, medical equipment, industrial sensors, smart
home hubs and wearables. It covers two distinct protocol stacks that share
the same 2.4 GHz radio band but are otherwise independent:

| Variant | Full name | Typical range | Common IoT use |
|---------|-----------|--------------|----------------|
| **BLE** | Bluetooth Low Energy (Bluetooth 4.0+) | 10-100 m | Sensors, beacons, wearables, locks |
| **BR/EDR** | Basic Rate / Enhanced Data Rate ("Classic") | 10-100 m | Audio, serial-port emulation (SPP), HID |

Most modern IoT devices use BLE exclusively. Some use both stacks (dual-mode).

## Attack surface

Bluetooth introduces attack surface at several layers:

- **Unauthenticated pairing**: many devices use Just Works pairing, which
  provides no MITM protection and requires no user confirmation.
- **Open GATT services**: BLE devices expose services and characteristics
  over GATT. Read/write access is often unrestricted, leaking sensor data or
  accepting firmware payloads without authentication.
- **Advertising data**: devices broadcast their name, manufacturer data, and
  service UUIDs continuously. This data can reveal device type, firmware
  version, and vendor without any connection.
- **Classic Bluetooth flaws**: pre-2017 BR/EDR stacks may be vulnerable to
  the BlueBorne family of remote code execution and information disclosure
  vulnerabilities (CVE-2017-0781 through CVE-2017-1000251).
- **Vendor backdoors**: some chipsets expose undocumented HCI commands that
  can be used to read memory, disable security, or write arbitrary data
  (e.g. CVE-2025-27840 on ESP32).

## Plugins

| Plugin | Command | Summary |
|--------|---------|---------|
| [ble adapter](./ble/ble-adapter.md) | `iottack ble adapter` | List Bluetooth adapters and report their power and discoverability state |
| [ble scan](./ble/ble-scan.md) | `iottack ble scan` | Discover nearby BLE devices and report advertising data |
| [ble device](./ble/ble-device.md) | `iottack ble device` | Enumerate GATT services and characteristics of a single BLE device |
| [ble write](./ble/ble-write.md) | `iottack ble write` | Write a value to a BLE GATT characteristic or fuzz it |

## Requirements

BLE plugins require a Bluetooth adapter visible to the host OS and the
`bluetoothd` daemon running. On Linux, `bluetoothd` is part of BlueZ.
Some operations (adapter power control, raw HCI access) require root or
membership in the `bluetooth` group.

```sh
# Verify BlueZ is running
systemctl status bluetooth

# List adapters
iottack ble adapter
```

## Typical workflow

1. **Scan**: discover what devices are in range and note their addresses and
   advertised service UUIDs.

   ```sh
   iottack ble scan --timeout 15
   ```

2. **Enumerate**: connect to a device and list all GATT services and
   characteristics, including their properties (read, write, notify).

   ```sh
   iottack ble device --address AA:BB:CC:DD:EE:FF
   ```

3. **Read/write**: interact with specific characteristics. A writable
   characteristic with no authentication is a direct finding.

   ```sh
   iottack ble write --address AA:BB:CC:DD:EE:FF \
       --characteristic 0000fff1-0000-1000-8000-00805f9b34fb \
       --value 0x0100
   ```
