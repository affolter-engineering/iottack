# ftdi device

Enumerate all FTDI USB adapters connected to this host and report their chip
type, chip ID, EEPROM strings and MPSSE capability.

## Usage

```sh
iottack ftdi device
```

## Description

Probes the five most common FTDI USB product IDs (`0x6001`, `0x6010`, `0x6011`,
`0x6014`, `0x6015`) and for each adapter found reports:

| Field | Description |
|-------|-------------|
| USB | Vendor ID and product ID |
| Chip | Chip family name |
| Chip ID | Unique 32-bit identifier burned into the chip (hex) |
| Manufacturer | EEPROM manufacturer string |
| Product | EEPROM product string |
| Serial | EEPROM serial number string |
| MPSSE | Channels with MPSSE engines and their maximum clock |

If no adapter is detected the plugin reports an info finding with udev setup
instructions.

## Options

This plugin has no plugin-specific options.

| Flag | Short | Description |
|------|-------|-------------|
| `--output <FILE>` | `-o` | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` or `json` |
| `--verbose` | `-v` | Increase log verbosity |

## Example

```sh
$ iottack ftdi device

Plugin name:    ftdi/device
Execution time: 45 ms
Status:         pass

[INFO] 1 FTDI adapter(s) detected
  Use 'iottack i2c scan' or 'iottack i2c read' for I2C operations.

[INFO] FT4232H — USB-COM485 Plus4
  USB:          0403:6011
  Chip:         FT4232H
  Chip ID:      0a1b2c3d
  Manufacturer: FTDI
  Product:      USB-COM485 Plus4
  Serial:       FT12345
  MPSSE:        A, B (30 MHz Hi-Speed); C, D UART only
```

## Linux setup (udev)

Without a UDEV rule normal users cannot open the USB device. See the
[FTDI adapter setup](./ftdi.md#linux-setup-udev) page for instructions.
