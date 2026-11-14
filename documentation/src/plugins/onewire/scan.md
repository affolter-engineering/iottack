# onewire scan

Enumerate all 1-Wire devices on the bus using the standard Maxim ROM Search
algorithm and report each device's ROM code, family name and security
relevance.

## Requirements

An FTDI adapter (FT232R, FT232H, FT2232H, or FT4232H) wired to the 1-Wire DQ
line. See [1-Wire plugin intro](./intro.md#wiring) for the TX and RX loopback
circuit and the required UDEV rule.

## Usage

```sh
iottack onewire scan [OPTIONS]
```

## Description

The plugin opens the FTDI UART at **9600 baud** to issue a 1-Wire reset pulse
(sends 0xF0, reads echo. A device pulls the echo low to signal presence). It
then switches to **115200 baud** for bit-level communication:

- writing 0xFF clocks a 1 (and reads the bus level back)
- writing 0x00 clocks a 0

ROM Search runs the standard Maxim algorithm to discover all devices
simultaneously. Each iteration resolves one bit-conflict until all 64-bit ROM
codes have been read. Up to **20 devices** per bus are reported. The 8-bit
Dallas/Maxim CRC (polynomial 0x8C) is validated for every ROM code. Codes
failing CRC are discarded.

For each device the plugin reports:

- 64-bit ROM code in `XX:XX:XX:XX:XX:XX:XX:XX` format
- Family name decoded from the first byte
- Security-relevant severity if applicable

With `--temp`, any DS18B20 or DS1822 sensors are additionally queried:

- the plugin sends MATCH ROM + CONVERT T
- waits 750 ms for conversion
- reads the 9-byte scratchpad and converts the raw value to degrees Celsius

## Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--vid <HEX>` | - | `0403` | USB vendor ID in hex |
| `--pid <HEX>` | - | auto-detect | USB product ID in HEX (6001=FT232R, 6010=FT2232H, 6011=FT4232H, 6014=FT232H). Omit to probe all known PIDs |
| `--channel <CHANNEL>` | `-c` | `A` | FTDI channel to use: A, B, C or D |
| `--temp` | - | off | Also read temperature from DS18B20/DS1822 sensors |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Device family table

| Family byte | Device | Notes |
| ----------- | ------ | ----- |
| 0x01 | DS2401/DS1990A iButton | Physical-access credential. Cloneable |
| 0x10 | DS18S20 | High-precision thermometer |
| 0x14 | DS2430A | 256-bit EEPROM |
| 0x1D | DS2423 | Dual counter/EEPROM |
| 0x22 | DS1822 | Thermometer (+/-2 °C, cheaper DS18B20) |
| 0x23 | DS2433 | 4 kbit EEPROM |
| 0x28 | DS18B20 | Ubiquitous programmable thermometer |
| 0x2D | DS2431 | 1 kbit EEPROM |
| 0x36 | DS2740 | Current accumulator |
| 0x3A | DS2413 | Dual-channel GPIO |
| 0x42 | DS28EA00 | Thermometer & 2 GPIO |
| 0x43 | DS28EC20 | 20 kbit EEPROM |

## Example

```sh
$ iottack onewire scan --channel A --temp

Plugin name:    onewire/scan
Execution time: 1842 ms
Status:         pass

[INFO] 3 device(s) found on 1-Wire bus (channel A)
  ROM search complete. 3 device(s) enumerated, 0 CRC error(s).

[INFO] 1-Wire device: DS18B20 (28:FF:3A:91:7C:04:00:7E)
  Family 0x28 (DS18B20 Programmable Resolution Thermometer).
  Temperature: 23.44 °C
  Evidence: "rom=28:FF:3A:91:7C:04:00:7E family=0x28 (DS18B20) temp=23.44C"

[LOW] 1-Wire device: DS2401 iButton (01:A3:7E:12:00:00:00:4F)
  Family 0x01 (DS2401/DS1990A). Used as physical-access credential.
  The 48-bit serial number is trivially readable and cloneable.
  Evidence: "rom=01:A3:7E:12:00:00:00:4F family=0x01 (DS2401 iButton)"

[MEDIUM] 1-Wire device: DS2431 EEPROM (2D:08:C1:3F:00:00:00:12)
  Family 0x2D (DS2431 1 kbit EEPROM). May store configuration or key material.
  Evidence: "rom=2D:08:C1:3F:00:00:00:12 family=0x2D (DS2431 EEPROM)"
```

## Troubleshooting

### No devices found / no presence pulse

- Confirm the 4.7 kOhm pull-up resistor is present between DQ and VCC.
- Verify target power is on.
- Check that TX and RX are both shorted to DQ (not just TX).
- Try `--channel B` if channel A produces no result.

### CRC errors

- Check for marginal connections or long wire runs (increase pull-up strength or shorten bus).
- A single bus with more than ~20 devices may need bus-master hardware instead of UART loopback.

### FTDI device not found

- Run `lsusb` and confirm the adapter appears (`0403:6001`, `0403:6014`, etc.).
- Apply the [udev rule](./intro.md#linux-udev-rule) and reconnect.

### Wrong temperature readings from DS18B20

- The 750 ms conversion wait is mandatory at 12-bit resolution; do not reduce it.
- Confirm VCC wiring (DS18B20 in parasite-power mode may require an external strong pull-up during conversion).
