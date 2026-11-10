# mcp2221 device

Enumerate all MCP2221/MCP2221A adapters connected to this host and report their
USB identity and capabilities.

## Usage

```sh
iottack mcp2221 device
```

## Description

Scans for USB devices with Microchip VID `0x04D8` and PID `0x00DD` and for each
adapter found reports:

| Field | Description |
| ----- | ----------- |
| USB | Vendor ID and product ID |
| Manufacturer | USB manufacturer string |
| Product | USB product string |
| Serial | USB serial number string |
| Interfaces | Fixed capability summary (I2C, UART, GPIO, ADC, DAC) |

If no adapter is detected the plugin reports an info finding with udev setup
instructions.

## Options

This plugin has no plugin-specific options.

| Flag | Short | Description |
| ---- | ----- | ----------- |
| `--output <FILE>` | `-o` | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` or `json` |
| `--verbose` | `-v` | Increase log verbosity |

## Example

```sh
$ iottack mcp2221 device

Plugin name:    mcp2221/device
Execution time: 3 ms
Status:         pass

[INFO] 1 MCP2221/MCP2221A adapter(s) detected
  The MCP2221A provides a USB-to-I2C bridge (up to 400 kHz), a USB-to-UART bridge,
  4x GPIO, 3x 10-bit ADC and 1x 5-bit DAC.

[INFO] MCP2221 USB-I2C/UART Combo — 0001234567
  USB:          04d8:00dd
  Manufacturer: Microchip Technology Inc.
  Product:      MCP2221 USB-I2C/UART Combo
  Serial:       0001234567
  Interfaces:   USB-I2C (up to 400 kHz), USB-UART, 4x GPIO, 3x ADC, 1x DAC
```

## Linux setup (udev)

Without a udev rule normal users cannot access the HID device. See the
[MCP2221 adapter setup](./mcp2221.md#linux-setup-udev) page for instructions.
