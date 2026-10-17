# platform

Report details about the host and platform environment.

## Usage

```sh
iottack platform [OPTIONS]
```

## Description

Collects and reports information about the host running `iottack`:

- Framework version, OS name/version/codename, kernel release, CPU architecture
- Effective user ID — flags whether the process has root privileges
- Available serial ports (`/dev/ttyUSB*`, `/dev/ttyACM*`, etc.)
- USB-serial devices enumerated via sysfs, with vendor/product details
- Known hardware identification — if a connected USB device matches the built-in
  table, its label is shown in the finding title

### Known hardware categories

| Category | Examples |
|---|---|
| Testing platforms | Expliot Bus Auditor, GreatFET One, HackRF One, YARD Stick One, Glasgow, Flipper Zero, Proxmark3, Chameleon Mini |
| Bus interface | Bus Pirate v3/v4 |
| Debug probes | ARM DAPLink, ST-Link/V2/V2-1/V3, Segger J-Link, Atmel-ICE, Picoprobe |
| Espressif | ESP32 USB JTAG/serial debug unit (S2/S3/C3/C6), ESP32-S2 native USB |
| ZigBee / BLE | nRF52840 Dongle, TI CC2531/CC2652, Sonoff Zigbee 3.0 Dongle Plus |
| USB-serial | FTDI FT232/FT2232/FT4232/FT232H/FT231X, CP210x/CP2105, CH340/CH341/CH343, Cypress |
| SDR | RTL-SDR, LimeSDR, ADALM-PLUTO |
| Wi-Fi | RTL8187, Ralink RT7601/RT5370, Atheros AR9271 |

Devices without a TTY node (e.g. HackRF One, GreatFET One) appear as a separate
`Known hardware detected` finding.

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack platform

Plugin name:    platform/platform
Execution time: 5 ms
Status:         pass
Date:           2026-10-17 14:21:17 UTC

Host environment
  iottack release: 0.2.6
  OS: NixOS 26.11 (zokor)
  Kernel: 6.18.54
  Architecture: x86_64

Running as unprivileged user (euid=1000)
  Some serial ports or USB devices may require elevated privileges.
  Run with sudo if access is denied.

Serial ports available (2)
  /dev/ttyACM0

USB-serial device: /dev/ttyACM0
  ID: 2886:0042 
  Product: Seeeduino XIAO RP2040 
  Manufacturer: Seeed 
  sysfs: /sys/devices/pci0000:00/0000:00:08.3/0000:c6:00.4/usb7/7-1/7-1.4/7-1.4.3
  Evidence: "/dev/ttyACM0"

Known hardware detected: TI CC2531 USB Dongle
  0451:16ae | CC2531 USB Dongle (Texas Instruments)
```
